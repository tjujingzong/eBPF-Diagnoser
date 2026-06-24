// SPDX-License-Identifier: GPL-2.0
#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct io_dev_stat {
	u64 read_count;
	u64 write_count;
	u64 total_latency_ns;
	u64 io_count;
	u32 queue_depth;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, u64);
} io_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, struct io_dev_stat);
} dev_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, u64);
} lat_hist SEC(".maps");

SEC("tracepoint/block/block_rq_issue")
int block_rq_issue_handler(struct trace_event_raw_block_rq *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u64 sector = BPF_CORE_READ(ctx, sector);
	bpf_map_update_elem(&io_start, &sector, &ts, BPF_ANY);

	char rwbs_first;
	bpf_probe_read_kernel(&rwbs_first, 1, &ctx->rwbs[0]);
	u8 is_write = (rwbs_first == 'W');

	u32 dev_raw = BPF_CORE_READ(ctx, dev);
	u32 dev_key = dev_raw & 0xFFFF;

	struct io_dev_stat *stat = bpf_map_lookup_elem(&dev_stats, &dev_key);
	if (stat) {
		__sync_fetch_and_add(&stat->queue_depth, 1);
		if (is_write)
			__sync_fetch_and_add(&stat->write_count, 1);
		else
			__sync_fetch_and_add(&stat->read_count, 1);
	} else {
		struct io_dev_stat new_stat = {};
		new_stat.queue_depth = 1;
		new_stat.read_count = is_write ? 0 : 1;
		new_stat.write_count = is_write ? 1 : 0;
		bpf_map_update_elem(&dev_stats, &dev_key, &new_stat, BPF_ANY);
	}
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int block_rq_complete_handler(struct trace_event_raw_block_rq_completion *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u64 sector = BPF_CORE_READ(ctx, sector);

	u64 *start_ts = bpf_map_lookup_elem(&io_start, &sector);
	if (!start_ts)
		return 0;

	u64 latency_ns = ts - *start_ts;
	bpf_map_delete_elem(&io_start, &sector);

	u32 dev_raw = BPF_CORE_READ(ctx, dev);
	u32 dev_key = dev_raw & 0xFFFF;

	struct io_dev_stat *stat = bpf_map_lookup_elem(&dev_stats, &dev_key);
	if (stat) {
		__sync_fetch_and_add(&stat->io_count, 1);
		__sync_fetch_and_add(&stat->total_latency_ns, latency_ns);
		if (stat->queue_depth > 0)
			__sync_fetch_and_add(&stat->queue_depth, -1);
	}

	u32 bucket = 0;
	if (latency_ns > 0) {
		u64 val = latency_ns;
		while (val > 1) {
			val >>= 1;
			bucket += 1;
		}
	}
	if (bucket < 64) {
		u64 *count = bpf_map_lookup_elem(&lat_hist, &bucket);
		if (count) {
			__sync_fetch_and_add(count, 1);
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
