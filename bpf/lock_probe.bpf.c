// SPDX-License-Identifier: GPL-2.0
#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_STACK_DEPTH 10

struct futex_stat {
	u64 call_count;
	u64 wait_count;
	u64 wake_count;
	u64 total_wait_ns;
	u64 max_wait_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct futex_stat);
} futex_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, u64);
} futex_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, int);
	__type(value, u64);
} contention_stacks SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_futex")
int sys_enter_futex_handler(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u64 tid = pid_tgid;
	u32 op = (u32)BPF_CORE_READ(ctx, args[1]) & 0xF;

	struct futex_stat *stat = bpf_map_lookup_elem(&futex_stats, &pid);
	if (!stat) {
		struct futex_stat new_stat = {};
		bpf_map_update_elem(&futex_stats, &pid, &new_stat, BPF_ANY);
		stat = bpf_map_lookup_elem(&futex_stats, &pid);
	}
	if (stat) {
		__sync_fetch_and_add(&stat->call_count, 1);
		if (op == 0) {
			__sync_fetch_and_add(&stat->wait_count, 1);
			u64 ts = bpf_ktime_get_ns();
			bpf_map_update_elem(&futex_start, &tid, &ts, BPF_ANY);
		} else if (op == 1) {
			__sync_fetch_and_add(&stat->wake_count, 1);
		}
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int sys_exit_futex_handler(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 tid = pid_tgid;

	u64 *start_ts = bpf_map_lookup_elem(&futex_start, &tid);
	if (!start_ts)
		return 0;

	u64 ts = bpf_ktime_get_ns();
	u64 latency_ns = ts - *start_ts;
	bpf_map_delete_elem(&futex_start, &tid);

	u32 pid = pid_tgid >> 32;
	struct futex_stat *stat = bpf_map_lookup_elem(&futex_stats, &pid);
	if (stat) {
		__sync_fetch_and_add(&stat->total_wait_ns, latency_ns);
		if (latency_ns > stat->max_wait_ns)
			stat->max_wait_ns = latency_ns;

		if (latency_ns > 1000000) {
			int stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
			if (stack_id >= 0) {
				u64 *count = bpf_map_lookup_elem(&contention_stacks, &stack_id);
				if (count) {
					__sync_fetch_and_add(count, 1);
				} else {
					u64 one = 1;
					bpf_map_update_elem(&contention_stacks, &stack_id, &one, BPF_ANY);
				}
			}
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
