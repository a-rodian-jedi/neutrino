package event

type EventType int

const (
	Execve     EventType = 0
	TCPConnect EventType = 1
)

type Event struct {
	Type EventType
	PID  uint32
	PPID uint32
	UID  uint32
	Comm string
	Raw  any
}
