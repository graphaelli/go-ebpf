/*
 * Copyright 2017 Elasticsearch Inc.
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
#include <linux/kconfig.h>
#include <linux/bpf.h>
#include <linux/sched.h>
#include <uapi/linux/perf_event.h>

#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps/stack_traces") stack_traces = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
	.max_entries = 1024,
};

struct pqexec_data_t {
        u64 timestamp_ns;
        u32 tgid;
        u32 pid;
        char comm[TASK_COMM_LEN];
        char query[256];
        u32 user_stack_id;
};

SEC("uprobe/pqexec")
int probe_pqexec(struct pt_regs *ctx) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 tgid = pid_tgid >> 32;
        u32 pid = pid_tgid; // implicit cast to u32 for bottom half

        struct pqexec_data_t data = {};
        data.timestamp_ns = bpf_ktime_get_ns();
        data.tgid = tgid;
        data.pid = pid;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        // 2nd arg is query
        bpf_probe_read(&data.query, sizeof(data.query), (void *)PT_REGS_PARM2(ctx));
        data.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);

        bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));
        return 0;
}

// Code is licensed under Apache 2.0 which is GPL compatible.
char _license[] SEC("license") = "GPL";

// This number will be interpreted by the elf loader to set the current
// running kernel version.
u32 _version SEC("version") = 0xFFFFFFFE;
