package execve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"log/slog"
	"sync"

	"github.com/a-rodian-jedi/neutrino/dto/event"
	"github.com/a-rodian-jedi/neutrino/ebpf"
	"github.com/a-rodian-jedi/neutrino/internal/convert"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ExecveMonitor is a monitor that wraps up all functionality for watching
// syscalls.
type ExecveMonitor struct {
	ctx    context.Context // parent context
	logger *slog.Logger
	objs   ebpf.Objects
	tp     link.Link
	wg     *sync.WaitGroup
}

func NewExecveMonitor(ctx context.Context, l *slog.Logger) *ExecveMonitor {
	var objs ebpf.Objects

	l.Debug("Loading Execve Objects")
	if err := ebpf.LoadObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF execve objects: %v", err)
	}
	l.Info("loaded eBPF execve objects")

	l.Debug("Attaching to eBPF program")
	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	l.Info("attached to tracepoint", "group", "sched", "name", "sched_process_exec")

	return &ExecveMonitor{
		ctx:    ctx,
		logger: l,
		objs:   objs,
		tp:     tp,
	}
}

func (em *ExecveMonitor) Run(out chan<- event.Event) {
	rd, err := ringbuf.NewReader(em.objs.Events)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}
	defer rd.Close()
	em.logger.Info("execve monitor started -- listening for process executions")

	context.AfterFunc(em.ctx, func() {
		rd.Close()
	})

	var evt event.Event
	var raw_evt ebpf.ExecEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// Reader was closed (most likely be AfterFunc)
				em.logger.Info("ring buffer reader closed, stopping")
				em.Stop()

				return
			}

			// general failure to read from ring buffer
			em.logger.Error("error reading from ring buffer", "error", err)
			continue
		}

		// failure to decode event off of ring buffer
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			em.logger.Error("error decoding ring buffer event", "error", err)
			continue
		}

		// success

		evt.Type = event.Execve
		evt.PID = raw_evt.Pid
		evt.PPID = raw_evt.Ppid
		evt.UID = raw_evt.Uid
		evt.Comm = convert.Int8SliceToString(raw_evt.Comm[:])
		evt.Raw = raw_evt

		em.logger.Info("process_exec",
			"pid", raw_evt.Pid,
			"ppid", raw_evt.Ppid,
			"uid", raw_evt.Uid,
			"comm", evt.Comm,
			"filename", convert.Int8SliceToString(raw_evt.Filename[:]),
		)

		out <- evt
	}
}

func (em *ExecveMonitor) Stop() {
	em.tp.Close()
	em.objs.Close()
}
