// SPDX-License-Identifier: GPL-2.0
#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* sample_rate used via map for compatibility with libbpf .rodata handling */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} sample_rate_map SEC(".maps");

struct syscall_stat {
	u64 call_count;
	u64 total_time_ns;
	u64 max_time_ns;
	u64 err_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, u32);
	__type(value, struct syscall_stat);
} syscall_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, u64);
} syscall_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} total_syscalls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} sample_ctr SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_handler(struct trace_event_raw_sys_enter *ctx)
{
	u32 zero = 0;
	u32 *rate_p = bpf_map_lookup_elem(&sample_rate_map, &zero);
	u32 rate = rate_p ? *rate_p : 10;
	u64 *ctr = bpf_map_lookup_elem(&sample_ctr, &zero);
	if (ctr) {
		u64 c = *ctr;
		if (rate > 1 && (c % rate) != 0) {
			__sync_fetch_and_add(ctr, 1);
			return 0;
		}
		__sync_fetch_and_add(ctr, 1);
	}

	u64 tid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&syscall_start, &tid, &ts, BPF_ANY);

	u64 *total = bpf_map_lookup_elem(&total_syscalls, &zero);
	if (total)
		__sync_fetch_and_add(total, 1);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit_handler(struct trace_event_raw_sys_exit *ctx)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 *start_ts = bpf_map_lookup_elem(&syscall_start, &tid);
	if (!start_ts)
		return 0;

	u64 ts = bpf_ktime_get_ns();
	u64 duration_ns = ts - *start_ts;
	bpf_map_delete_elem(&syscall_start, &tid);

	u32 syscall_nr = (u32)BPF_CORE_READ(ctx, id);
	long ret = BPF_CORE_READ(ctx, ret);

	struct syscall_stat *stat = bpf_map_lookup_elem(&syscall_stats, &syscall_nr);
	if (stat) {
		__sync_fetch_and_add(&stat->call_count, 1);
		__sync_fetch_and_add(&stat->total_time_ns, duration_ns);
		if (duration_ns > stat->max_time_ns)
			stat->max_time_ns = duration_ns;
		if (ret < 0)
			__sync_fetch_and_add(&stat->err_count, 1);
	} else {
		struct syscall_stat new_stat = {};
		new_stat.call_count = 1;
		new_stat.total_time_ns = duration_ns;
		new_stat.max_time_ns = duration_ns;
		new_stat.err_count = (ret < 0) ? 1 : 0;
		bpf_map_update_elem(&syscall_stats, &syscall_nr, &new_stat, BPF_ANY);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
