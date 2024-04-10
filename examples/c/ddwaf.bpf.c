// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ddwaf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // the thread group id
    __type(value, u64); // timestamp value
    __uint(max_entries, 256);
} start_timestamps SEC(".maps");

struct match_rule_tctx {
	u64 start_ts;
	void *rule;
	// char rule_id[22];
	// unsigned short rule_id_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // the thread group id
    __type(value, struct match_rule_tctx);
    __uint(max_entries, 256);
} rule_ctxs SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(enter_ddwaf_run, void *ddwaf_ctx)
{
	// bpf_printk("enter_ddwaf_run for context %p", ddwaf_ctx);

	u32 tid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_timestamps, &tid, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(exit_ddwaf_run, int ret)
{
	// bpf_printk("exit_ddwaf_run with ret %d", ret);

	u32 tid = bpf_get_current_pid_tgid() >> 32;
	u64 *entry_ts = bpf_map_lookup_elem(&start_timestamps, &tid);
	if (entry_ts) {
		u64 elapsed = bpf_ktime_get_ns() - *entry_ts;
		// Reserve space on the ring buffer
		struct event_ddwaf_run *evt =
			bpf_ringbuf_reserve(&rb, sizeof(struct event_ddwaf_run), 0);
		if (evt) {
			evt->event.type = EVENT_TYPE_DDWAF_RUN;
			evt->event.tid = tid;
			evt->duration = elapsed;

			bpf_ringbuf_submit(evt, 0);
		}

		bpf_map_delete_elem(&start_timestamps, &tid);
	}
	return 0;
}


struct libcpp_string {
	union {
		struct {
			unsigned char size;
			char data[23];
		} smallv;
		struct  {
			unsigned long cap;
			unsigned long size;
			char *data;
		} longv;
	};
};

static __always_inline void cpy(void *dst, const void *src, unsigned long size)
{
	for (unsigned long i = 0; i < size; i++) {
		((char *)dst)[i] = ((char *)src)[i];
	}
}

#define LIBCPP_STRING_SHORT_MASK 1
static __always_inline bool is_libcpp_string_long(struct libcpp_string *str)
{
	return (str->smallv.size & LIBCPP_STRING_SHORT_MASK) != 0;
}
static __always_inline unsigned long libcpp_string_get_short_size(struct libcpp_string *str)
{
	return str->smallv.size >> 1;
}
static __always_inline unsigned long libcpp_string_get_long_size(struct libcpp_string *str)
{
	return str->longv.size;
}

#define MAX_STR_SIZE 22
static __always_inline void libcpp_string_get_char(struct libcpp_string *str, char *out,
						    u16 *size)
{
	if (is_libcpp_string_long(str)) {
		*size = libcpp_string_get_long_size(str);
		char *data_ptr = str->longv.data;
		bpf_probe_read_user(out, 22, data_ptr);
		if (*size > MAX_STR_SIZE) {
			out[MAX_STR_SIZE] = '\0';
			*size = MAX_STR_SIZE;
		} else {
			out[*size] = '\0';
		}
	} else {
		*size = (int) libcpp_string_get_short_size(str);
		if (*size > MAX_STR_SIZE) {
			*size = MAX_STR_SIZE; // should not happen
		}
		// should already be NUL terminated
		cpy(out, str->smallv.data, MAX_STR_SIZE);
	}
}

struct rule {
	void *vptr;
	bool enabled;
	unsigned char source_type;
	struct libcpp_string id;
};

// First argument is passed actually in the second register in this case.
// See https://itanium-cxx-abi.github.io/cxx-abi/abi.html#this-parameters
SEC("uprobe")
int BPF_KPROBE(enter_match_rule, void *ret, void *rule)
{
	// bpf_printk("enter_match_rule for rule %p rip %lu", rule, ctx->ip);

	u32 tid = bpf_get_current_pid_tgid() >> 32;
	struct match_rule_tctx rule_ctx = {
		.start_ts = bpf_ktime_get_ns(),
		.rule = rule,
	};

	bpf_map_update_elem(&rule_ctxs, &tid, &rule_ctx, BPF_ANY);

	return 0;
}

SEC("uretprobe")
int BPF_KPROBE(exit_match_rule)
{
	// bpf_printk("exit_match_rule with ret %d");

	u32 tid = bpf_get_current_pid_tgid() >> 32;
	struct match_rule_tctx *entry = bpf_map_lookup_elem(&rule_ctxs, &tid);
	if (entry) {
		u64 elapsed = bpf_ktime_get_ns() - entry->start_ts;
		struct event_match_rule *evt =
			bpf_ringbuf_reserve(&rb, sizeof(struct event_match_rule), 0);
		if (evt) {
			evt->event.type = EVENT_TYPE_MATCH_RULE;
			evt->event.tid = tid;
			evt->duration = elapsed;

			struct libcpp_string cpp_str;
			void *start_read = entry->rule + offsetof(struct rule, id);
			bpf_probe_read_user(&cpp_str, sizeof(cpp_str), start_read);
			libcpp_string_get_char(&cpp_str, &evt->rule_id[0], &evt->rule_id_len);

			bpf_ringbuf_submit(evt, 0);
		}

		bpf_map_delete_elem(&rule_ctxs, &tid);
	}
	return 0;
}


