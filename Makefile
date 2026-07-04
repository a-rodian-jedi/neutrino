.PHONY: generate build run clean vmlinux

# Generate vmlinux.h from the running kernel's BTF data.
# This file contains all kernel type definitions needed for CO-RE.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/c/headers/vmlinux.h

# Compile the eBPF C program and generate Go bindings via bpf2go.
generate: vmlinux
	cd ebpf && go generate ./...

# Build the agent binary.
build: generate
	go build -o neutrino .

# Build and run as root (required for eBPF).
run: build
	sudo ./neutrino

# Remove generated artifacts.
clean:
	rm -f neutrino
	rm -f ebpf/execve_x86_bpfel.go ebpf/execve_x86_bpfel.o
	rm -f ebpf/c/headers/vmlinux.h
