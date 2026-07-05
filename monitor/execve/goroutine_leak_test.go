package execve_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/a-rodian-jedi/neutrino/dto/event"
	"go.uber.org/goleak"
)

// TestMain applies goleak verification to ALL tests in this package.
// If any test in this file leaves a goroutine running after it completes,
// the test suite fails. This catches goroutine leaks from:
//   - Ring buffer readers that weren't closed
//   - context.AfterFunc callbacks that never returned
//   - Monitor goroutines that didn't respond to shutdown
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestNoGoroutineLeakOnShutdown verifies that the monitor's goroutine
// lifecycle (start → process events → context cancel → clean exit) does
// not leak goroutines.
//
// Since the real ExecveMonitor requires root and eBPF, this test
// simulates the exact same goroutine pattern used in main.go and Run():
//   - A producer goroutine reads from a data source and sends to a channel
//   - context.AfterFunc closes the data source on cancellation
//   - The producer exits when the data source is closed
//   - A WaitGroup tracks completion
func TestNoGoroutineLeakOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &sync.Pool{
		New: func() any {
			return &event.Event{}
		},
	}

	// Simulates the ring buffer — a channel that blocks on receive
	// until closed (like ringbuf.Reader.Read() returns ErrClosed)
	ringBuf := make(chan []byte)

	// context.AfterFunc closes the "reader" — mirrors execve.go line 55-57
	context.AfterFunc(ctx, func() {
		close(ringBuf)
	})

	events := make(chan *event.Event, 500)

	// Producer goroutine — mirrors the pattern in main.go lines 71-75
	var producerWg sync.WaitGroup
	producerWg.Add(1)
	go func() {
		defer producerWg.Done()

		for range ringBuf {
			evt := pool.Get().(*event.Event)
			evt.Type = event.Execve
			evt.PID = 1234
			events <- evt
		}
		// ringBuf was closed by AfterFunc → loop exits cleanly
	}()

	// Feed a few events before shutdown
	for i := 0; i < 5; i++ {
		ringBuf <- []byte{0x01}
	}

	// Trigger shutdown
	cancel()

	// Wait for producer to finish, then close events channel
	producerWg.Wait()
	close(events)

	// Drain remaining events
	for evt := range events {
		pool.Put(evt)
	}
}

// TestNoGoroutineLeakMultipleMonitors verifies that running multiple
// monitors concurrently (like main.go does with execve + tcp) doesn't
// leak goroutines on shutdown.
func TestNoGoroutineLeakMultipleMonitors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &sync.Pool{
		New: func() any {
			return &event.Event{}
		},
	}

	events := make(chan *event.Event, 500)
	var producerWg sync.WaitGroup

	// Spin up 3 "monitors" to simulate execve + tcp + future monitors
	for i := 0; i < 3; i++ {
		ringBuf := make(chan []byte, 10)

		context.AfterFunc(ctx, func() {
			close(ringBuf)
		})

		// Send a few events from each monitor before starting consumer
		for j := 0; j < 3; j++ {
			ringBuf <- []byte{0x01}
		}

		producerWg.Add(1)
		go func() {
			defer producerWg.Done()
			for range ringBuf {
				evt := pool.Get().(*event.Event)
				evt.PID = 1
				events <- evt
			}
		}()
	}

	// Let events flow briefly, then shut down
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Wait for all producers to finish, then close events channel
	producerWg.Wait()
	close(events)

	// Drain remaining events
	for evt := range events {
		pool.Put(evt)
	}
}
