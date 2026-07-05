package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"sync"
	"syscall"

	"github.com/a-rodian-jedi/neutrino/dto/event"
	nlog "github.com/a-rodian-jedi/neutrino/internal/logger"
	"github.com/a-rodian-jedi/neutrino/monitor/execve"
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

	// ── Context + Signal Handling ─────────────────────────────
	// signal.NotifyContext ties OS signals directly to context cancellation.
	// When SIGINT or SIGTERM is received, ctx.Done() is closed.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	execveMonitor := execve.NewExecveMonitor(ctx, logger)
	execveResults := make(chan event.Event)
	wg.Add(1)
	go func() {
		defer wg.Done()
		execveMonitor.Run(execveResults)
	}()

	wg.Wait()

	logger.Info("exiting")

	// Loading TCP Connections
	// var tcp_objs bpf.TCPObjects
	// if err := bpf.LoadTCPConnections(&tcp_objs, nil); err != nil {
	// 	log.Fatalf("load eBPF tcp connections: %v", err)
	// }
	// defer tcp_objs.Close()

	// slog.Info("eBPF TCP connections loaded successfully")

}
