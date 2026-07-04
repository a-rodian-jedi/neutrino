package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	bpf "github.com/a-rodian-jedi/neutrino/ebpf"
	"github.com/a-rodian-jedi/neutrino/internal/convert"
	nlog "github.com/a-rodian-jedi/neutrino/internal/logger"
)

var cpuprofile = flag.String("cpuprofile", "", "write CPU profile to file")

func main() {
	flag.Parse()

	// ── CPU Profiling (optional) ──────────────────────────────
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatalf("creating CPU profile: %v", err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatalf("starting CPU profile: %v", err)
		}
		defer pprof.StopCPUProfile()
	}

	// ── Structured Logger ─────────────────────────────────────
	logger := nlog.NewNeutrinoLogger(nlog.Info)

	// Loading TCP Connections
	// var tcp_objs bpf.TCPObjects
	// if err := bpf.LoadTCPConnections(&tcp_objs, nil); err != nil {
	// 	log.Fatalf("load eBPF tcp connections: %v", err)
	// }
	// defer tcp_objs.Close()

	// slog.Info("eBPF TCP connections loaded successfully")

	// ── Context + Signal Handling ─────────────────────────────
	// signal.NotifyContext ties OS signals directly to context cancellation.
	// When SIGINT or SIGTERM is received, ctx.Done() is closed.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Load eBPF Objects ─────────────────────────────────────
	// LoadObjects loads the compiled eBPF bytecode into the kernel
	// and returns handles to the programs and maps.
	var objs bpf.Objects
	if err := bpf.LoadObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	logger.Info("eBPF objects loaded successfully")

	// ── Attach to Tracepoint ──────────────────────────────────
	// link.Tracepoint attaches our eBPF program to the kernel's
	// sched/sched_process_exec tracepoint. Every execve() syscall
	// will now trigger our eBPF handler.
	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	logger.Info("attached to tracepoint", "group", "sched", "name", "sched_process_exec")

	// ── Ring Buffer Reader ────────────────────────────────────
	// ringbuf.NewReader creates a userspace reader for the eBPF ring buffer.
	// It blocks on Read() until an event is available or the reader is closed.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}
	defer rd.Close()

	// When the context is cancelled (Ctrl+C), close the reader.
	// This unblocks the rd.Read() call below with an error.
	context.AfterFunc(ctx, func() {
		logger.Info("shutting down: closing ring buffer reader")
		rd.Close()
	})

	logger.Info("neutrino agent started — listening for process executions")
	fmt.Fprintln(os.Stderr, "Press Ctrl+C to stop")

	// ── Event Loop ────────────────────────────────────────────
	var evt bpf.ExecEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// Reader was closed (by our AfterFunc above) — clean exit
				logger.Info("ring buffer reader closed, exiting")
				return
			}
			logger.Error("reading from ring buffer", "error", err)
			continue
		}

		// Decode the raw bytes into our Go struct.
		// binary.Read uses the struct's field sizes and order to map
		// the raw kernel bytes to Go fields.
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			logger.Error("decoding event", "error", err)
			continue
		}

		logger.Info("process_exec",
			"pid", evt.Pid,
			"ppid", evt.Ppid,
			"uid", evt.Uid,
			"comm", convert.Int8SliceToString(evt.Comm[:]),
			"filename", convert.Int8SliceToString(evt.Filename[:]),
		)
	}
}
