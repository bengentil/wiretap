//+build ignore
// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Benjamin Gentil

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 32
#define DATA_LEN 256
#define MAX_ITERATIONS 1024

struct event {
	u32 pid;
	u8 comm[COMM_LEN];
	u32 len;
	u8 type;
	u8 data[DATA_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, u64);
	__type(value, u64);
} buf_addr SEC(".maps");

int min(int a, int b) {
	if (a > b) {
		return b;
	}
	return a;
}

SEC("uprobe/SSL_readwrite")
int BPF_KPROBE(SSL_readwrite_enter, void *ssl, void *buf, int num) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&buf_addr, &pid_tgid, &buf, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_readwrite")
int BPF_KRETPROBE(SSL_readwrite_ret, int rc) {
	// no data has been read
	if (rc <= 0) {
		return 0;
	}

	struct event event = {0};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	event.pid = pid_tgid >> 32;
	bpf_get_current_comm(&event.comm, COMM_LEN);
	event.type = 1;
	event.len = min(rc, DATA_LEN);

	u64 *buf = bpf_map_lookup_elem(&buf_addr, &pid_tgid);
	if (buf == 0) {
		return 0;
	}
	bpf_map_delete_elem(&buf_addr, &pid_tgid);

	// TODO: use a real loop
	// for some reason the eBPF verifier in not happy with a for loop here
	int iterations = 0;
send:
	bpf_probe_read_user(&event.data, DATA_LEN, (char *)*buf);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	rc -= DATA_LEN;
	if (rc > 0 && iterations++ < MAX_ITERATIONS) {
		event.len = min(rc, DATA_LEN);
		*buf += DATA_LEN;
		goto send;
	}
	return 0;
}
