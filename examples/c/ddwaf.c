// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ddwaf.skel.h"
#include <bpf/libbpf.h>
#include "ddwaf.h"

static int handle_event(void *ctx, void *data, size_t data_sz);

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static char *find_libddwaf_so_path(int pid)
{
	char path[PATH_MAX];
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return NULL;
	}

	while (fgets(path, sizeof(path), fp)) {
		if (strstr(path, "/libddwaf.so")) {
			// find the first / character, and dup from that point
			char *p = strchr(path, '/');
			if (!p) {
				return NULL; // shouldn't happen
			}

			char *so_path = strdup(p);
			// find the line terminator and replace it with null
			p = strchr(so_path, '\n');
			if (p) {
				*p = '\0';
			} else {
				return NULL; /// shouldn't happen
			}

			fclose(fp);
			return so_path;
		}
	}

	fclose(fp);
	return NULL;
}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct ddwaf_bpf *skel;
	int err;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		return 1;
	}
	// convert argv[1] to int
	int pid = atoi(argv[1]);
	if (pid == 0) {
		fprintf(stderr, "Invalid pid: %s\n", argv[1]);
		return 1;
	}

	char *so_path = find_libddwaf_so_path(pid);
	if (!so_path) {
		fprintf(stderr, "Failed to find libddwaf.so path for pid %d\n", pid);
		return 1;
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = ddwaf_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "ddwaf_run";
	uprobe_opts.retprobe = false;
	skel->links.enter_ddwaf_run = bpf_program__attach_uprobe_opts(skel->progs.enter_ddwaf_run,
								      -1, so_path,
								      0 /* offset for function */,
								      &uprobe_opts /* opts */);
	if (!skel->links.enter_ddwaf_run) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "ddwaf_run";
	uprobe_opts.retprobe = true;
	skel->links.exit_ddwaf_run = bpf_program__attach_uprobe_opts(skel->progs.exit_ddwaf_run, -1,
								     so_path,
								     0 /* offset for function */,
								     &uprobe_opts /* opts */);
	if (!skel->links.exit_ddwaf_run) {
		err = -errno;
		fprintf(stderr, "Failed to attach uretprobe: %d\n", err);
		goto cleanup;
	}

	// at runtime: addr - shlib base + .text offset
#define RULE_MATCH_FN_OFFSET 0x15d850
	uprobe_opts.func_name = NULL;
	uprobe_opts.retprobe = false;
	skel->links.enter_match_rule = bpf_program__attach_uprobe_opts(skel->progs.enter_match_rule,
								      pid, so_path,
								      RULE_MATCH_FN_OFFSET,
								      &uprobe_opts /* opts */);
	if (!skel->links.enter_match_rule) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = NULL;
	uprobe_opts.retprobe = true;
	skel->links.exit_match_rule = bpf_program__attach_uprobe_opts(
		skel->progs.exit_match_rule, pid, so_path, RULE_MATCH_FN_OFFSET, &uprobe_opts /* opts */);
	if (!skel->links.exit_match_rule) {
		err = -errno;
		fprintf(stderr, "Failed to attach uretprobe: %d\n", err);
		goto cleanup;
	}

	err = ddwaf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ddwaf_bpf__destroy(skel);
	return -err;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *evt = data;
	if (evt->type == EVENT_TYPE_DDWAF_RUN) {
		struct event_ddwaf_run *ddwaf_run = (struct event_ddwaf_run *)evt;
		printf("DDWAF run duration: [%d] %lu ns\n", ddwaf_run->event.tid,
		       ddwaf_run->duration);
	} else if (evt->type == EVENT_TYPE_MATCH_RULE) {
		struct event_match_rule *match_rule = (struct event_match_rule *)evt;
		printf("Match rule: [%d] %.*s %lu ns\n", match_rule->event.tid,
		       (int)match_rule->rule_id_len, match_rule->rule_id, match_rule->duration);
	}
	return 0;
}
