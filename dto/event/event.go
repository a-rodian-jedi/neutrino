package event

import "github.com/a-rodian-jedi/neutrino/ebpf"

type EventType int

const (
	Execve     EventType = 0
	TCPConnect EventType = 1
)

type Event struct {
	Type    EventType
	PID     uint32
	PPID    uint32
	UID     uint32
	Comm    [16]int8
	Exec    ebpf.ExecEvent
	TCPConn ebpf.TCPConnectEvent
}
