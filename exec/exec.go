/*
 * Copyright 2018 Elasticsearch Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package exec

import "C"
import (
	"bytes"
	"encoding/binary"
	"strconv"
	"time"
	"unsafe"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	bpf "github.com/iovisor/gobpf/elf"
)

// probe and map names in the eBPF program.
const (
	perfEventLocation = "/usr/lib/x86_64-linux-gnu/libpq.so.5.10:0x15b40"
	perfEventProbe    = "uprobe/pqexec"
	stackTraceMap     = "stack_traces"
)

var log = logrus.WithField("selector", "exec")

// Process Monitor

type ProcessMonitor struct {
	// eBPF
	module        *bpf.Module
	perfMap       *bpf.PerfMap
	bpfEvents     chan []byte
	lostBPFEvents chan uint64
	lostCount     uint64

	output chan interface{}
	done   <-chan struct{}
}

func NewMonitor() (*ProcessMonitor, error) {
	return &ProcessMonitor{}, nil
}

type perfEvent struct {
	Time        uint64
	Tgid        uint32
	Pid         uint32
	Command     [16]byte
	Query       [256]byte
	UserStackId uint32
}

type Event struct {
	Sent       time.Time `json:"sent"`
	Time       time.Time `json:"time"`
	Pid        int       `json:"pid"`
	Tgid       int       `json:"tgid"`
	Command    string    `json:"command"`
	Query      string    `json:"query"`
	Stacktrace []string  `json:"stacktrace"`
}

func (m *ProcessMonitor) Start(done <-chan struct{}) (<-chan interface{}, error) {
	if err := m.initBPF(); err != nil {
		return nil, err
	}
	m.output = make(chan interface{}, 1)

	go func() {
		defer close(m.output)
		defer m.perfMap.PollStop()
		defer m.module.Close()

		for {
			select {
			case data := <-m.bpfEvents:
				var event perfEvent
				err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
				if err != nil {
					log.WithError(err).Error("failed to decode received data")
					continue
				}
				command := (*C.char)(unsafe.Pointer(&event.Command))
				query := (*C.char)(unsafe.Pointer(&event.Query))
				m.output <- Event{
					Sent:       time.Now(),
					Tgid:       int(event.Tgid),
					Pid:        int(event.Pid),
					Command:    C.GoString(command),
					Query:      C.GoString(query),
					Stacktrace: []string{strconv.Itoa(int(event.UserStackId))},
				}
			case count := <-m.lostBPFEvents:
				m.lostCount += count
				log.WithField("total_dropped", m.lostCount).Infof("%v messages from kernel dropped", count)
			case <-done:
				return
			}
		}
	}()

	return m.output, nil
}

func (m *ProcessMonitor) initBPF() error {
	data, err := asset("exec.o")
	if err != nil {
		return errors.Wrap(err, "failed to load embedded ebpf code")
	}

	// Load module to kernel.
	m.module = bpf.NewModuleFromReader(bytes.NewReader(data))
	if err := m.module.Load(nil); err != nil {
		return errors.Wrap(err, "failed to load ebpf module to kernel")
	}

	// Setup our perf event readers.
	m.bpfEvents = make(chan []byte, 64)
	m.lostBPFEvents = make(chan uint64, 1)
	m.perfMap, err = bpf.InitPerfMap(m.module, "events", m.bpfEvents, m.lostBPFEvents)
	if err != nil {
		m.module.Close()
		return errors.Wrapf(err, "failed to initialize %v perf map", stackTraceMap)
	}

	// Enable the probe.
	if err := m.module.EnableUprobe(perfEventProbe, perfEventLocation); err != nil {
		m.module.Close()
		return errors.Wrapf(err, "failed to enable %v probe", perfEventProbe)
	}

	m.perfMap.PollStart()
	return nil
}
