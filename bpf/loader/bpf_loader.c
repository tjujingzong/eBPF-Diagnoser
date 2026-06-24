// SPDX-License-Identifier: GPL-2.0
/*
 * bpf_loader - eBPF program loader with JSON command protocol
 *
 * Long-running process that loads pre-compiled BPF .o files,
 * attaches tracepoint programs, and serves map data to Python
 * via stdin/stdout newline-delimited JSON.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* 短名称类型定义 */
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;
/* 短名称类型定义 */typedef __u8 u8;typedef __u16 u16;typedef __u32 u32;typedef __u64 u64;typedef __s8 s8;typedef __s16 s16;typedef __s32 s32;typedef __s64 s64;
#include <bpf/btf.h>

#define MAX_OBJS     8
#define MAX_LINKS    32
#define MAX_LINE     65536
#define MAX_RESP     (1024 * 1024)
#define MAX_KSYMS    200000

struct ksym_entry {
	unsigned long addr;
	char name[128];
};

static struct ksym_entry *ksyms = NULL;
static int nr_ksyms = 0;

struct loaded_obj {
	struct bpf_object *obj;
	struct bpf_link *links[MAX_LINKS];
	int nr_links;
	int fd;
	char name[64];
};

static struct loaded_obj objects[MAX_OBJS];
static int nr_objects = 0;

/* --- JSON output buffer --- */
struct json_buf {
	char *buf;
	int pos;
	int cap;
};

static void jb_init(struct json_buf *jb, char *buf, int cap)
{
	jb->buf = buf;
	jb->pos = 0;
	jb->cap = cap;
	jb->buf[0] = '\0';
}

static void jb_append(struct json_buf *jb, const char *fmt, ...)
{
	va_list ap;
	int remaining = jb->cap - jb->pos - 1;
	if (remaining <= 0) return;
	va_start(ap, fmt);
	int n = vsnprintf(jb->buf + jb->pos, remaining, fmt, ap);
	va_end(ap);
	if (n > 0) {
		jb->pos += (n < remaining) ? n : remaining;
	}
}

/* --- /proc/kallsyms --- */
static int load_kallsyms(void)
{
	if (ksyms) return 0;

	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f) {
		fprintf(stderr, "Cannot open /proc/kallsyms: %s\n", strerror(errno));
		return -1;
	}

	ksyms = malloc(MAX_KSYMS * sizeof(struct ksym_entry));
	if (!ksyms) {
		fclose(f);
		return -1;
	}

	char line[256];
	while (fgets(line, sizeof(line), f) && nr_ksyms < MAX_KSYMS) {
		unsigned long addr;
		char type;
		if (sscanf(line, "%lx %c %127s", &addr, &type, ksyms[nr_ksyms].name) == 3) {
			if (addr > 0 && (type == 't' || type == 'T')) {
				ksyms[nr_ksyms].addr = addr;
				nr_ksyms++;
			}
		}
	}
	fclose(f);

	/* sort by address for binary search */
	for (int i = 1; i < nr_ksyms; i++) {
		struct ksym_entry tmp = ksyms[i];
		int j = i - 1;
		while (j >= 0 && ksyms[j].addr > tmp.addr) {
			ksyms[j + 1] = ksyms[j];
			j--;
		}
		ksyms[j + 1] = tmp;
	}

	return 0;
}

static const char *resolve_ksym(unsigned long addr, unsigned long *offset)
{
	if (!ksyms) {
		if (load_kallsyms() < 0)
			return "??";
	}

	int lo = 0, hi = nr_ksyms - 1, best = -1;
	while (lo <= hi) {
		int mid = (lo + hi) / 2;
		if (ksyms[mid].addr <= addr) {
			best = mid;
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}

	if (best >= 0) {
		*offset = addr - ksyms[best].addr;
		return ksyms[best].name;
	}
	return "??";
}

/* --- BTF-to-JSON serialization --- */
static int serialize_value_btf(struct json_buf *jb, const struct btf *btf,
			       const struct btf_type *type, const void *data,
			       int depth);

static int serialize_struct(struct json_buf *jb, const struct btf *btf,
			    const struct btf_type *type, const void *data,
			    int depth)
{
	if (depth > 4) return -1;

	int nr_members = btf_vlen(type);
	const struct btf_member *members = btf_members(type);

	jb_append(jb, "{");
	for (int i = 0; i < nr_members; i++) {
		const struct btf_type *mtype = btf__type_by_id(btf, members[i].type);
		const char *mname = btf__name_by_offset(btf, members[i].name_off);
		u32 bit_offset = members[i].offset;
		u32 byte_offset = bit_offset / 8;
		const void *mdata = (const char *)data + byte_offset;

		/* resolve typedefs */
		while (mtype && btf_is_typedef(mtype)) {
			mtype = btf__type_by_id(btf, mtype->type);
		}

		if (i > 0) jb_append(jb, ",");
		jb_append(jb, "\"%s\":", mname ? mname : "");

		if (!mtype) {
			jb_append(jb, "null");
			continue;
		}

		if (btf_is_int(mtype)) {
			u32 enc = btf_int_encoding(mtype);
			u32 sz = mtype->size;
			if (sz == 1) {
				if (enc & BTF_INT_SIGNED)
					jb_append(jb, "%d", *(s8 *)mdata);
				else
					jb_append(jb, "%u", *(u8 *)mdata);
			} else if (sz == 2) {
				if (enc & BTF_INT_SIGNED)
					jb_append(jb, "%d", *(s16 *)mdata);
				else
					jb_append(jb, "%u", *(u16 *)mdata);
			} else if (sz == 4) {
				if (enc & BTF_INT_SIGNED)
					jb_append(jb, "%d", *(s32 *)mdata);
				else
					jb_append(jb, "%u", *(u32 *)mdata);
			} else if (sz == 8) {
				if (enc & BTF_INT_SIGNED)
					jb_append(jb, "%lld", *(s64 *)mdata);
				else
					jb_append(jb, "%llu", *(u64 *)mdata);
			} else {
				jb_append(jb, "0");
			}
		} else if (btf_is_enum(mtype)) {
			jb_append(jb, "%d", *(int *)mdata);
		} else if (btf_is_array(mtype)) {
			struct btf_array *arr = btf_array(mtype);
			const struct btf_type *elem_type = btf__type_by_id(btf, arr->type);
			/* resolve typedefs */
			while (elem_type && btf_is_typedef(elem_type))
				elem_type = btf__type_by_id(btf, elem_type->type);

			if (elem_type && btf_is_int(elem_type) && elem_type->size == 1) {
				/* char array -> string */
				jb_append(jb, "\"");
				const char *s = (const char *)mdata;
				for (u32 k = 0; k < arr->nelems && s[k]; k++) {
					if (s[k] == '"' || s[k] == '\\')
						jb_append(jb, "\\");
					jb_append(jb, "%c", s[k]);
				}
				jb_append(jb, "\"");
			} else {
				jb_append(jb, "[");
				for (u32 k = 0; k < arr->nelems; k++) {
					if (k > 0) jb_append(jb, ",");
					u32 elem_sz = elem_type ? elem_type->size : 8;
					serialize_value_btf(jb, btf, elem_type,
							    (const char *)mdata + k * elem_sz,
							    depth + 1);
				}
				jb_append(jb, "]");
			}
		} else if (btf_is_struct(mtype)) {
			serialize_struct(jb, btf, mtype, mdata, depth + 1);
		} else {
			jb_append(jb, "null");
		}
	}
	jb_append(jb, "}");
	return 0;
}

static int serialize_value_btf(struct json_buf *jb, const struct btf *btf,
			       const struct btf_type *type, const void *data,
			       int depth)
{
	while (type && btf_is_typedef(type))
		type = btf__type_by_id(btf, type->type);

	if (!type) { jb_append(jb, "null"); return 0; }

	if (btf_is_struct(type))
		return serialize_struct(jb, btf, type, data, depth);

	if (btf_is_int(type)) {
		u32 sz = type->size;
		if (sz == 4) jb_append(jb, "%u", *(u32 *)data);
		else if (sz == 8) jb_append(jb, "%llu", *(u64 *)data);
		else if (sz == 2) jb_append(jb, "%u", *(u16 *)data);
		else if (sz == 1) jb_append(jb, "%u", *(u8 *)data);
		else jb_append(jb, "0");
		return 0;
	}

	jb_append(jb, "null");
	return 0;
}

/* --- JSON parsing helpers --- */
static const char *json_get_str(const char *json, const char *key)
{
	static char val[512];
	char pattern[128];
	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	const char *p = strstr(json, pattern);
	if (!p) return NULL;
	p += strlen(pattern);
	while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
	if (*p == '"') {
		p++;
		int i = 0;
		while (*p && *p != '"' && i < (int)sizeof(val) - 1)
			val[i++] = *p++;
		val[i] = '\0';
		return val;
	}
	return NULL;
}

static long json_get_int(const char *json, const char *key, long def)
{
	char pattern[128];
	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	const char *p = strstr(json, pattern);
	if (!p) return def;
	p += strlen(pattern);
	while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
	if (*p == '-' || isdigit(*p))
		return strtol(p, NULL, 0);
	return def;
}

/* --- Command handlers --- */
static char resp[MAX_RESP];

static void cmd_load(int id, const char *json)
{
	const char *obj_path = json_get_str(json, "obj_path");
	long sample_rate_val = json_get_int(json, "sample_rate", 1);

	if (!obj_path || !obj_path[0]) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"missing obj_path\"}\n", id);
		return;
	}

	if (nr_objects >= MAX_OBJS) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"too many objects\"}\n", id);
		return;
	}

	struct bpf_object_open_opts opts = {};
	opts.sz = sizeof(opts);

	struct bpf_object *obj = bpf_object__open_file(obj_path, &opts);
	if (libbpf_get_error(obj)) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"bpf_object__open_file failed: %s\"}\n",
			 id, strerror(errno));
		return;
	}

	/* inject sample_rate into .rodata if present */
	struct bpf_map *map;
	bpf_object__for_each_map(map, obj) {
		const char *mname = bpf_map__name(map);
		if (strstr(mname, ".rodata")) {
			const void *init_val = bpf_map__initial_value(map, NULL);
			if (init_val) {
				size_t sz = bpf_map__value_size(map);
				void *buf = malloc(sz);
				if (buf) {
					memcpy(buf, init_val, sz);
					*(u32 *)buf = (u32)sample_rate_val;
					bpf_map__set_initial_value(map, buf, sz);
					free(buf);
				}
			}
			break;
		}
	}

	int err = bpf_object__load(obj);
	if (err) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"bpf_object__load failed: %s\"}\n",
			 id, strerror(err));
		bpf_object__close(obj);
		return;
	}

	int idx = nr_objects++;
	objects[idx].obj = obj;
	objects[idx].nr_links = 0;
	objects[idx].fd = -1;

	/* extract object name from path */
	const char *base = strrchr(obj_path, '/');
	base = base ? base + 1 : obj_path;
	strncpy(objects[idx].name, base, sizeof(objects[idx].name) - 1);

	/* build response with program and map names */
	struct json_buf jb;
	jb_init(&jb, resp, sizeof(resp));
	jb_append(&jb, "{\"id\":%d,\"ok\":true,\"obj_index\":%d,\"progs\":[", id, idx);

	struct bpf_program *prog;
	int first = 1;
	bpf_object__for_each_program(prog, obj) {
		if (!first) jb_append(&jb, ",");
		jb_append(&jb, "\"%s\"", bpf_program__name(prog));
		first = 0;
	}
	jb_append(&jb, "],\"maps\":[");

	first = 1;
	bpf_object__for_each_map(map, obj) {
		const char *mname = bpf_map__name(map);
		if (strstr(mname, ".rodata") || strstr(mname, ".bss") || strstr(mname, ".data"))
			continue;
		if (!first) jb_append(&jb, ",");
		jb_append(&jb, "\"%s\"", mname);
		first = 0;
	}
	jb_append(&jb, "]}\n");
}

static void cmd_attach(int id, const char *json)
{
	long obj_index = json_get_int(json, "obj_index", -1);
	if (obj_index < 0 || obj_index >= nr_objects) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"invalid obj_index\"}\n", id);
		return;
	}

	struct loaded_obj *lo = &objects[obj_index];
	struct bpf_program *prog;
	int attached = 0;

	bpf_object__for_each_program(prog, lo->obj) {
		struct bpf_link *link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			fprintf(stderr, "Failed to attach %s: %s\n",
				bpf_program__name(prog), strerror(errno));
			continue;
		}
		if (lo->nr_links < MAX_LINKS) {
			lo->links[lo->nr_links++] = link;
			attached++;
		}
	}

	snprintf(resp, sizeof(resp),
		 "{\"id\":%d,\"ok\":true,\"attached\":%d}\n", id, attached);
}

static struct bpf_map *find_map_by_name(struct loaded_obj *lo, const char *name)
{
	struct bpf_map *map;
	bpf_object__for_each_map(map, lo->obj) {
		if (strcmp(bpf_map__name(map), name) == 0)
			return map;
	}
	return NULL;
}

static void cmd_read_map_array(int id, const char *json)
{
	long obj_index = json_get_int(json, "obj_index", -1);
	const char *map_name = json_get_str(json, "map");
	long index = json_get_int(json, "index", 0);

	if (obj_index < 0 || obj_index >= nr_objects || !map_name) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"invalid params\"}\n", id);
		return;
	}

	struct loaded_obj *lo = &objects[obj_index];
	struct bpf_map *map = find_map_by_name(lo, map_name);
	if (!map) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"map '%s' not found\"}\n", id, map_name);
		return;
	}

	int map_fd = bpf_map__fd(map);
	u32 key = (u32)index;
	u32 val_sz = bpf_map__value_size(map);
	void *val = calloc(1, val_sz);
	if (!val) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"out of memory\"}\n", id);
		return;
	}

	int err = bpf_map_lookup_elem(map_fd, &key, val);
	if (err) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":true,\"data\":{}}\n", id);
		free(val);
		return;
	}

	const struct btf *btf = bpf_object__btf(lo->obj);
	u32 val_type_id = bpf_map__btf_value_type_id(map);
	const struct btf_type *val_type = btf ? btf__type_by_id(btf, val_type_id) : NULL;

	/* resolve typedef */
	while (val_type && btf_is_typedef(val_type))
		val_type = btf__type_by_id(btf, val_type->type);

	struct json_buf jb;
	jb_init(&jb, resp, sizeof(resp));
	jb_append(&jb, "{\"id\":%d,\"ok\":true,\"data\":", id);

	if (val_type && btf_is_struct(val_type)) {
		serialize_struct(&jb, btf, val_type, val, 0);
	} else if (val_type && btf_is_int(val_type)) {
		u32 sz = val_type->size;
		if (sz == 8) jb_append(&jb, "%llu", *(u64 *)val);
		else if (sz == 4) jb_append(&jb, "%u", *(u32 *)val);
		else jb_append(&jb, "0");
	} else {
		jb_append(&jb, "{}");
	}

	jb_append(&jb, "}\n");
	free(val);
}

static void cmd_read_map_hash(int id, const char *json)
{
	long obj_index = json_get_int(json, "obj_index", -1);
	const char *map_name = json_get_str(json, "map");
	long max_entries_req = json_get_int(json, "max_entries", 256);

	if (obj_index < 0 || obj_index >= nr_objects || !map_name) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"invalid params\"}\n", id);
		return;
	}

	struct loaded_obj *lo = &objects[obj_index];
	struct bpf_map *map = find_map_by_name(lo, map_name);
	if (!map) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"map '%s' not found\"}\n", id, map_name);
		return;
	}

	int map_fd = bpf_map__fd(map);
	u32 key_sz = bpf_map__key_size(map);
	u32 val_sz = bpf_map__value_size(map);

	void *key_buf = calloc(1, key_sz);
	void *next_key_buf = calloc(1, key_sz);
	void *val_buf = calloc(1, val_sz);
	if (!key_buf || !next_key_buf || !val_buf) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"out of memory\"}\n", id);
		free(key_buf); free(next_key_buf); free(val_buf);
		return;
	}

	const struct btf *btf = bpf_object__btf(lo->obj);
	u32 key_type_id = bpf_map__btf_key_type_id(map);
	u32 val_type_id = bpf_map__btf_value_type_id(map);
	const struct btf_type *key_type = btf ? btf__type_by_id(btf, key_type_id) : NULL;
	const struct btf_type *val_type = btf ? btf__type_by_id(btf, val_type_id) : NULL;

	while (key_type && btf_is_typedef(key_type))
		key_type = btf__type_by_id(btf, key_type->type);
	while (val_type && btf_is_typedef(val_type))
		val_type = btf__type_by_id(btf, val_type->type);

	struct json_buf jb;
	jb_init(&jb, resp, sizeof(resp));
	jb_append(&jb, "{\"id\":%d,\"ok\":true,\"entries\":[", id);

	int count = 0;
	int first = 1;
	int truncated = 0;

	while (bpf_map_get_next_key(map_fd, count == 0 ? NULL : key_buf, next_key_buf) == 0) {
		if (count >= max_entries_req) {
			truncated = 1;
			break;
		}

		if (bpf_map_lookup_elem(map_fd, next_key_buf, val_buf) != 0) {
			memcpy(key_buf, next_key_buf, key_sz);
			count++;
			continue;
		}

		if (!first) jb_append(&jb, ",");
		first = 0;

		jb_append(&jb, "{\"key\":");

		/* serialize key */
		if (key_type && btf_is_int(key_type)) {
			u32 sz = key_type->size;
			if (sz == 4) jb_append(&jb, "%u", *(u32 *)next_key_buf);
			else if (sz == 8) jb_append(&jb, "%llu", *(u64 *)next_key_buf);
			else if (sz == 2) jb_append(&jb, "%u", *(u16 *)next_key_buf);
			else jb_append(&jb, "0");
		} else {
			jb_append(&jb, "0");
		}

		jb_append(&jb, ",\"value\":");

		/* serialize value */
		if (val_type && btf_is_struct(val_type)) {
			serialize_struct(&jb, btf, val_type, val_buf, 0);
		} else if (val_type && btf_is_int(val_type)) {
			u32 sz = val_type->size;
			if (sz == 8) jb_append(&jb, "%llu", *(u64 *)val_buf);
			else if (sz == 4) jb_append(&jb, "%u", *(u32 *)val_buf);
			else jb_append(&jb, "0");
		} else {
			jb_append(&jb, "{}");
		}

		jb_append(&jb, "}");

		memcpy(key_buf, next_key_buf, key_sz);
		count++;
	}

	jb_append(&jb, "],\"truncated\":%s}\n", truncated ? "true" : "false");

	free(key_buf);
	free(next_key_buf);
	free(val_buf);
}

static void cmd_read_stack(int id, const char *json)
{
	long obj_index = json_get_int(json, "obj_index", -1);
	const char *map_name = json_get_str(json, "map");
	long stack_id = json_get_int(json, "stack_id", -1);

	if (obj_index < 0 || obj_index >= nr_objects || !map_name || stack_id < 0) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"invalid params\"}\n", id);
		return;
	}

	struct loaded_obj *lo = &objects[obj_index];
	struct bpf_map *map = find_map_by_name(lo, map_name);
	if (!map) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"map '%s' not found\"}\n", id, map_name);
		return;
	}

	int map_fd = bpf_map__fd(map);
	u32 val_sz = bpf_map__value_size(map);
	void *val = calloc(1, val_sz);
	if (!val) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"out of memory\"}\n", id);
		return;
	}

	u32 key = (u32)stack_id;
	int err = bpf_map_lookup_elem(map_fd, &key, val);
	if (err) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":true,\"addrs\":[]}\n", id);
		free(val);
		return;
	}

	struct json_buf jb;
	jb_init(&jb, resp, sizeof(resp));
	jb_append(&jb, "{\"id\":%d,\"ok\":true,\"addrs\":[", id);

	u64 *ips = (u64 *)val;
	int nr_ips = val_sz / sizeof(u64);
	int first = 1;
	for (int i = 0; i < nr_ips && ips[i] != 0; i++) {
		if (!first) jb_append(&jb, ",");
		jb_append(&jb, "\"0x%llx\"", ips[i]);
		first = 0;
	}

	jb_append(&jb, "]}\n");
	free(val);
}

static void cmd_resolve_ksym(int id, const char *json)
{
	/* parse "addrs":["0xfff...","0xfff..."] */
	const char *p = strstr(json, "\"addrs\"");
	if (!p) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"missing addrs\"}\n", id);
		return;
	}

	struct json_buf jb;
	jb_init(&jb, resp, sizeof(resp));
	jb_append(&jb, "{\"id\":%d,\"ok\":true,\"symbols\":[", id);

	p = strchr(p, '[');
	int first = 1;
	while (p && *p != ']') {
		p++;
		while (*p && *p != '"' && *p != ']') p++;
		if (*p == '"') {
			p++;
			unsigned long addr = strtoul(p, NULL, 16);
			unsigned long offset = 0;
			const char *sym = resolve_ksym(addr, &offset);

			if (!first) jb_append(&jb, ",");
			if (offset > 0)
				jb_append(&jb, "\"%s+0x%lx\"", sym, offset);
			else
				jb_append(&jb, "\"%s\"", sym);
			first = 0;

			while (*p && *p != '"') p++;
		}
	}

	jb_append(&jb, "]}\n");
}

static void cmd_detach(int id, const char *json)
{
	long obj_index = json_get_int(json, "obj_index", -1);
	if (obj_index < 0 || obj_index >= nr_objects) {
		snprintf(resp, sizeof(resp),
			 "{\"id\":%d,\"ok\":false,\"error\":\"invalid obj_index\"}\n", id);
		return;
	}

	struct loaded_obj *lo = &objects[obj_index];
	for (int i = 0; i < lo->nr_links; i++) {
		bpf_link__destroy(lo->links[i]);
		lo->links[i] = NULL;
	}
	lo->nr_links = 0;

	bpf_object__close(lo->obj);
	lo->obj = NULL;

	snprintf(resp, sizeof(resp), "{\"id\":%d,\"ok\":true}\n", id);
}

/* --- Main event loop --- */
int main(void)
{
	char line[MAX_LINE];

	while (fgets(line, sizeof(line), stdin)) {
		/* strip newline */
		int len = strlen(line);
		while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
			line[--len] = '\0';

		if (len == 0) continue;

		int id = (int)json_get_int(line, "id", 0);
		const char *cmd = json_get_str(line, "cmd");

		if (!cmd) {
			snprintf(resp, sizeof(resp),
				 "{\"id\":%d,\"ok\":false,\"error\":\"missing cmd\"}\n", id);
		} else if (strcmp(cmd, "LOAD") == 0) {
			cmd_load(id, line);
		} else if (strcmp(cmd, "ATTACH") == 0) {
			cmd_attach(id, line);
		} else if (strcmp(cmd, "READ_MAP_ARRAY") == 0) {
			cmd_read_map_array(id, line);
		} else if (strcmp(cmd, "READ_MAP_HASH") == 0) {
			cmd_read_map_hash(id, line);
		} else if (strcmp(cmd, "READ_STACK") == 0) {
			cmd_read_stack(id, line);
		} else if (strcmp(cmd, "RESOLVE_KSYM") == 0) {
			cmd_resolve_ksym(id, line);
		} else if (strcmp(cmd, "DETACH") == 0) {
			cmd_detach(id, line);
		} else if (strcmp(cmd, "QUIT") == 0) {
			snprintf(resp, sizeof(resp), "{\"id\":%d,\"ok\":true}\n", id);
			fputs(resp, stdout);
			fflush(stdout);
			break;
		} else {
			snprintf(resp, sizeof(resp),
				 "{\"id\":%d,\"ok\":false,\"error\":\"unknown cmd '%s'\"}\n", id, cmd);
		}

		fputs(resp, stdout);
		fflush(stdout);
	}

	/* cleanup */
	for (int i = 0; i < nr_objects; i++) {
		if (objects[i].obj) {
			for (int j = 0; j < objects[i].nr_links; j++)
				bpf_link__destroy(objects[i].links[j]);
			bpf_object__close(objects[i].obj);
		}
	}
	free(ksyms);

	return 0;
}
