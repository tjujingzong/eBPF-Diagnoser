// SPDX-License-Identifier: GPL-2.0
#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct mem_event_stats {
	u64 kswapd_wake_count;
	u64 direct_reclaim_count;
	u64 oom_kill_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mem_event_stats);
} mem_stats SEC(".maps");

SEC("tracepoint/vmscan/mm_vmscan_kswapd_wake")
int kswapd_wake_handler(struct trace_event_raw_mm_vmscan_kswapd_wake *ctx)
{
	u32 zero = 0;
	struct mem_event_stats *stat = bpf_map_lookup_elem(&mem_stats, &zero);
	if (stat) {
		__sync_fetch_and_add(&stat->kswapd_wake_count, 1);
	}
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int direct_reclaim_handler(struct trace_event_raw_mm_vmscan_direct_reclaim_begin_template *ctx)
{
	u32 zero = 0;
	struct mem_event_stats *stat = bpf_map_lookup_elem(&mem_stats, &zero);
	if (stat) {
		__sync_fetch_and_add(&stat->direct_reclaim_count, 1);
	}
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int oom_victim_handler(struct trace_event_raw_mark_victim *ctx)
{
	u32 zero = 0;
	struct mem_event_stats *stat = bpf_map_lookup_elem(&mem_stats, &zero);
	if (stat) {
		__sync_fetch_and_add(&stat->oom_kill_count, 1);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
