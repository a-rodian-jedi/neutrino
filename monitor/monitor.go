package monitor

import "github.com/a-rodian-jedi/neutrino/dto/event"

type Monitor interface {
	Run(chan<- event.Event)
	Stop()
}
