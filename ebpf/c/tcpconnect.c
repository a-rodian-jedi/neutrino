// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

// eBPF C program that hooks kprobe/tcp_connect
// to capture every tcp connection on the system.

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Maximum filename length we capture
#define FILENAME_LEN 256
// Maximum comm (command name) length — kernel limit is 16
#define COMM_LEN 16

// Event struct sent to userspace via ring buffer.
// IMPORTANT: field order and sizes must exactly match the Go struct
// in internal/event/event.go.
struct tcpconn_event_t {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[COMM_LEN];
    __be32 daddr;
    __be32 saddr;
    __be16 dport;
    __u16 sport;
    short unsigned int family;
};

// Force this struct into BTF so bpf2go's -type flag can find it.
// Without this, the compiler may optimize the type away since it's only
// used via pointer cast in bpf_ringbuf_reserve.
const struct tcpconn_event_t *unused_tcpconn_event_t __attribute__((unused));

// Ring buffer map for sending events to userspace.
// Ring buffer is preferred over perf event arrays:
//   - no per-CPU allocation overhead
//   - atomic reservation (no lost events under moderate load)
//   - simpler userspace API
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 256); // 256 KB ring buffer
} events SEC(".maps");

// tcp_connect tracing, for kprobe using pt_regs
SEC("kprobe/tcp_connect")
int handle_tcpconnect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcpconn_event_t *evt;
    struct task_struct *task;

    // Reserve space in the ring buffer
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0; // ring buffer full — drop event
    }

    // Get PID (thread group ID) and UID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid & 0xFFFFFFFF;

    // Get the command name
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Get the parent PID via task_struct->real_parent->tgid
    // BPF_CORE_READ handles struct layout differences across kernel versions
    task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // update event data from sock_common struct
    evt->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    evt->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    evt->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    evt->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    evt->family = BPF_CORE_READ(sk, __sk_common.skc_family);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// License is required by the kernel verifier for eBPF programs
// that use certain helper functions (like bpf_probe_read_str).
char LICENSE[] SEC("license") = "Dual BSD/GPL";

