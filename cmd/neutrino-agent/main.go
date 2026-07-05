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

	// eventPool causes X (500, in this hardcoded case) number of *event.Events to be
	// allocated all at once and in play at a time. This means at higher throughput
	// levels we operate faster, GC works less (which means lower pause on cycle), and
	// our footprint is overall lower. At low traffic levels Get/Put of sync.Pool can
	// cause overhead that actually slows the agent down, but that should not matter
	// since the traffic levels are already low.
	// TODO: This could be wrapped in an EventPool object to dictate max size, etc, in the
	// case of extra allocation we could drop overflow to the GC. Additionally, this would
	// make the system more tunable.
	eventPool := sync.Pool{
		New: func() any {
			return &event.Event{}
		},
	}
	// pre-warm the pool with 500 events, hopefully enough to not need allocation again
	for i := 0; i < 500; i++ {
		eventPool.Put(&event.Event{})
	}

	events := make(chan *event.Event, 500)

	// ── Execve Monitor ────────────────────────────
	execveMonitor := execve.NewExecveMonitor(ctx, logger, &eventPool)
	wg.Add(1)
	go func() {
		defer wg.Done()
		execveMonitor.Run(events)
	}()
	// ── TCP Connect Monitor ────────────────────────────
	// TCP Connect runner goes here, and also writes to events

	wg.Wait()

	logger.Info("exiting")
}
