// Package ebpf contains the eBPF programs and go:generate directives
// for compiling them with bpf2go.
package ebpf

// Generate Go bindings from the eBPF C program.
// bpf2go compiles execve.c into eBPF bytecode and generates:
//   - execve_bpfel.go  — Go loader functions and struct definitions
//   - execve_bpfel.o   — compiled eBPF object (embedded in binary)
//
// Flags:
//   -target amd64  — target architecture
//   -type exec_event_t — generate a Go type for this C struct
//   -- -I headers  — include path for vmlinux.h
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type exec_event_t execve c/execve.c -- -I c/headers -I /usr/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type tcpconn_event_t tcp_connect c/tcpconnect.c -- -I c/headers -I /usr/include
