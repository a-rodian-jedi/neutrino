package ebpf

import (
	ciliumebpf "github.com/cilium/ebpf"
)

// Re-export the generated types so they're accessible from main.
// bpf2go generates unexported types (lowercase) — these aliases make
// them available to packages outside of ebpf/.

// ExecEvent mirrors the eBPF C struct exec_event_t.
// Field types match the BTF-generated struct exactly.
type ExecEvent = execveExecEventT
type TCPConnectEvent = tcp_connectTcpconnEventT

// Objects holds references to all loaded eBPF programs, maps, and variables.
type Objects = execveObjects
type TCPObjects = tcp_connectObjects

// LoadObjects loads the compiled eBPF bytecode into the kernel
// and returns populated Objects handles.
func LoadObjects(obj any, opts *ciliumebpf.CollectionOptions) error {
	return loadExecveObjects(obj, opts)
}

func LoadTCPConnections(obj any, opts *ciliumebpf.CollectionOptions) error {
	return loadTcp_connectObjects(obj, opts)
}
