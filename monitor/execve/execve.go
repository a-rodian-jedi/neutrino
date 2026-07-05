package execve

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/a-rodian-jedi/neutrino/dto/event"
	"github.com/a-rodian-jedi/neutrino/ebpf"
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
	rd     *ringbuf.Reader
	pool   *sync.Pool
}

// NewExecveMonitor returns a pointer to a fresh ExecveMonitor object.
// Additionally, it loads eBPF execve objects, attaches to the tracepoint, and
// provisions a reader for the eBPF ring buffer.
func NewExecveMonitor(ctx context.Context, l *slog.Logger, p *sync.Pool) *ExecveMonitor {
	var objs ebpf.Objects

	// Note: could check args here and give more friendly error messages rather than waiting for
	// nil dereference later if something is missing

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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}

	context.AfterFunc(ctx, func() {
		rd.Close()
	})

	return &ExecveMonitor{
		ctx:    ctx,
		logger: l,
		objs:   objs,
		tp:     tp,
		rd:     rd,
		pool:   p,
	}
}

func (em *ExecveMonitor) Run(out chan<- *event.Event) {
	// var raw_evt ebpf.ExecEvent
	evt := em.pool.Get().(*event.Event)

	for {
		record, err := em.rd.Read()
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
		// binary.Read according to benchmarks does 2 allocations and takes around 3600ns per op
		// if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw_evt); err != nil {
		// 	em.logger.Error("error decoding ring buffer event", "error", err)
		// 	continue
		// }
		// we can replace with an unsafe but very fast alternative if desired:
		if len(record.RawSample) < int(unsafe.Sizeof(ebpf.ExecEvent{})) {
			em.logger.Error("buffer too small for ExecEvent", "got", len(record.RawSample), "want", int(unsafe.Sizeof(ebpf.ExecEvent{})))
			continue
		}
		raw_evt := (*ebpf.ExecEvent)(unsafe.Pointer(&record.RawSample[0]))

		// success

		evt.Type = event.Execve
		evt.PID = raw_evt.Pid
		evt.PPID = raw_evt.Ppid
		evt.UID = raw_evt.Uid
		evt.Comm = raw_evt.Comm
		evt.Exec = *raw_evt

		em.logger.Info("process_exec",
			"pid", raw_evt.Pid,
			"ppid", raw_evt.Ppid,
			"uid", raw_evt.Uid,
			"comm", evt.Comm,
			"filename", raw_evt.Filename,
		)

		out <- evt
	}
}

func (em *ExecveMonitor) Stop() {
	em.tp.Close()
	em.objs.Close()
}
