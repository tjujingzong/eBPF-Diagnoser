/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VMLINUX_TYPES_H
#define __VMLINUX_TYPES_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;
typedef u32 gfp_t;

#define TASK_COMM_LEN 16

#ifndef __uint
#define __uint(name, val) int(*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif
#ifndef __array
#define __array(name, val) typeof(val) *name[]
#endif

struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[TASK_COMM_LEN];
	int pid;
	int prio;
	int target_cpu;
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[TASK_COMM_LEN];
	int prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[TASK_COMM_LEN];
	int next_pid;
	int next_prio;
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_block_rq {
	struct trace_entry ent;
	u32 dev;
	u64 sector;
	u32 nr_sector;
	u32 bytes;
	char rwbs[8];
	char comm[TASK_COMM_LEN];
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_block_rq_completion {
	struct trace_entry ent;
	u32 dev;
	u64 sector;
	u32 nr_sector;
	int error;
	char rwbs[8];
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_mm_vmscan_kswapd_wake {
	struct trace_entry ent;
	int nid;
	int zid;
	int order;
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_mm_vmscan_direct_reclaim_begin_template {
	struct trace_entry ent;
	int order;
	gfp_t gfp_flags;
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_mark_victim {
	struct trace_entry ent;
	int pid;
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long id;
	unsigned long args[6];
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long id;
	long ret;
	char __data[0];
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_TYPES_H */

/* bpf_helper_defs.h 需要的类型别名 */
typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;
typedef s8 __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;

/* 网络字节序类型 */
typedef u16 __be16;
typedef u32 __be32;
typedef u32 __wsum;

/* BPF map 类型和标志 */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
};

#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2
