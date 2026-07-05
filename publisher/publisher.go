package publisher

import "context"

type EventPublisher struct {
}

// NewPublisher connects to Redis prepared to do high performance
// PubSub writes. While normally a configuration could be read here,
// for demo purposes this assumes localhost dev settings.
func NewPublisher(ctx context.Context) {

}
