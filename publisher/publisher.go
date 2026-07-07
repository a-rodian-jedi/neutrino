package publisher

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/a-rodian-jedi/neutrino/dto/event"
	"github.com/a-rodian-jedi/neutrino/internal/convert"
	"github.com/redis/go-redis/v9"
)

// EnrichedEvent represents the event payload sent to downstream systems (e.g. Redis).
// It contains fields that have been transformed into safe, consumable formats (e.g. strings).
type EnrichedEvent struct {
	Type     string `json:"type"`
	PID      uint32 `json:"pid"`
	PPID     uint32 `json:"ppid"`
	UID      uint32 `json:"uid"`
	Comm     string `json:"comm"`
	Filename string `json:"filename,omitempty"`
}

// EventPublisher reads raw events from a channel, enriches them,
// and publishes them to a Redis Pub/Sub channel.
type EventPublisher struct {
	ctx         context.Context
	logger      *slog.Logger
	pool        *sync.Pool
	redisClient *redis.Client
	numWorkers  int
	wg          sync.WaitGroup
}

// NewEventPublisher creates a new EventPublisher instance.
func NewEventPublisher(ctx context.Context, logger *slog.Logger, pool *sync.Pool, redisClient *redis.Client, numWorkers int) *EventPublisher {
	return &EventPublisher{
		ctx:         ctx,
		logger:      logger,
		pool:        pool,
		redisClient: redisClient,
		numWorkers:  numWorkers,
	}
}

// Run spawns the worker pool and starts processing events from the 'in' channel.
func (p *EventPublisher) Run(in <-chan *event.Event) {
	p.logger.Info("starting event publisher", "workers", p.numWorkers)

	for i := 0; i < p.numWorkers; i++ {
		p.wg.Add(1)
		go p.worker(i, in)
	}
}

// worker is the main loop for each worker goroutine. It reads events from the channel,
// processes them, and handles graceful shutdown.
func (p *EventPublisher) worker(id int, in <-chan *event.Event) {
	defer p.wg.Done()

	p.logger.Debug("publisher worker started", "worker_id", id)

	for {
		select {
		case evt, ok := <-in:
			if !ok {
				// Channel was closed
				p.logger.Debug("events channel closed, worker exiting", "worker_id", id)
				return
			}
			p.processEvent(evt)
		case <-p.ctx.Done():
			// Context was cancelled, drain the channel before exiting
			p.logger.Debug("context cancelled, worker draining channel", "worker_id", id)
			for evt := range in {
				p.processEvent(evt)
			}
			return
		}
	}
}

// processEvent handles enriching a single event, serializing it, publishing to Redis,
// and returning the event to the sync.Pool.
func (p *EventPublisher) processEvent(evt *event.Event) {
	// 1. Enrich the event (converting raw C byte arrays to Go strings)
	enriched := EnrichedEvent{
		PID:  evt.PID,
		PPID: evt.PPID,
		UID:  evt.UID,
		Comm: convert.Int8SliceToString(evt.Comm[:]),
	}

	switch evt.Type {
	case event.Execve:
		enriched.Type = "execve"
		enriched.Filename = convert.Int8SliceToString(evt.Exec.Filename[:])
	case event.TCPConnect:
		enriched.Type = "tcp_connect"
		// TODO: Add TCP-specific fields when ready (Daddr, Dport, etc.)
	}

	// 2. Serialize to JSON
	data, err := json.Marshal(enriched)
	if err != nil {
		p.logger.Error("failed to marshal enriched event", "error", err)
		p.pool.Put(evt) // ensure event is always returned to the pool
		return
	}

	// 3. Publish to Redis Pub/Sub
	err = p.redisClient.Publish(p.ctx, "neutrino.events", data).Err()
	if err != nil {
		p.logger.Error("failed to publish event to redis", "error", err)
	}

	// 4. Return the original event struct to the pool to prevent allocations
	p.pool.Put(evt)
}

// Stop blocks until all workers have finished draining the channel and exited.
func (p *EventPublisher) Stop() {
	p.wg.Wait()
	p.logger.Info("event publisher stopped")
}
