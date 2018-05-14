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
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/perf_event.h>

#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/stack_traces") stack_traces = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
	.max_entries = 10240,
};

struct key_t {
	char name[TASK_COMM_LEN];
	u32 pid;
	u64 kernel_ip;
    u64 kernel_ret_ip;
	u32 kernel_stack_id;
	u32 user_stack_id;
};

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    /*
    if (!(pid == 1))
        return 0;
    */
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = pid};

    // fill in command name
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_REUSE_STACKID);
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_REUSE_STACKID | BPF_F_USER_STACK);

    // from BCC profile.py (Apache 2.0 License)
    if (key.kernel_stack_id >= 0) {
        // populate extras to fix the kernel stack
        struct pt_regs regs = {};
        bpf_probe_read(&regs, sizeof(regs), (void *)&ctx->regs);
        u64 ip = PT_REGS_IP(&regs);

        // if ip isn't sane, leave key ips as zero for later checking
#ifdef CONFIG_RANDOMIZE_MEMORY
        if (ip > __PAGE_OFFSET_BASE) {
#else
        if (ip > PAGE_OFFSET) {
#endif
            key.kernel_ip = ip;
        }
    }
    return 0;
}

// Code is licensed under Apache 2.0 which is GPL compatible.
char _license[] SEC("license") = "GPL";

// This number will be interpreted by the elf loader to set the current
// running kernel version.
__u32 _version SEC("version") = 0xFFFFFFFE;
