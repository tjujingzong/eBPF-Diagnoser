// SPDX-License-Identifier: GPL-2.0
#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct cpu_proc_stat {
	u32 pid;
	u64 switch_count;
	char comm[TASK_COMM_LEN];
};

struct global_stat {
	u64 total_switches;
	u64 sample_count;
};

struct sched_latency {
	u64 total_latency_ns;
	u64 max_latency_ns;
	u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct cpu_proc_stat);
} proc_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct global_stat);
} global SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} wakeup_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct sched_latency);
} sched_lat SEC(".maps");

SEC("tracepoint/sched/sched_wakeup")
int sched_wakeup_handler(struct trace_event_raw_sched_wakeup_template *ctx)
{
	u32 pid = BPF_CORE_READ(ctx, pid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int sched_switch_handler(struct trace_event_raw_sched_switch *ctx)
{
	u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
	u32 next_pid = BPF_CORE_READ(ctx, next_pid);

	u32 zero = 0;
	struct global_stat *g = bpf_map_lookup_elem(&global, &zero);
	if (g) {
		__sync_fetch_and_add(&g->total_switches, 1);
		__sync_fetch_and_add(&g->sample_count, 1);
	} else {
		struct global_stat new_g = {};
		new_g.total_switches = 1;
		new_g.sample_count = 1;
		bpf_map_update_elem(&global, &zero, &new_g, BPF_ANY);
	}

	struct cpu_proc_stat *prev_stat = bpf_map_lookup_elem(&proc_stats, &prev_pid);
	if (prev_stat) {
		__sync_fetch_and_add(&prev_stat->switch_count, 1);
	} else {
		struct cpu_proc_stat new_stat = {};
		new_stat.pid = prev_pid;
		new_stat.switch_count = 1;
		bpf_get_current_comm(&new_stat.comm, sizeof(new_stat.comm));
		bpf_map_update_elem(&proc_stats, &prev_pid, &new_stat, BPF_ANY);
	}

	u64 *wake_ts = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
	if (wake_ts) {
		u64 now_ts = bpf_ktime_get_ns();
		u64 latency_ns = now_ts - *wake_ts;
		bpf_map_delete_elem(&wakeup_ts, &next_pid);

		struct sched_latency *lat = bpf_map_lookup_elem(&sched_lat, &zero);
		if (lat) {
			__sync_fetch_and_add(&lat->total_latency_ns, latency_ns);
			if (latency_ns > lat->max_latency_ns)
				lat->max_latency_ns = latency_ns;
			__sync_fetch_and_add(&lat->count, 1);
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
