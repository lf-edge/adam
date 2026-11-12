// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"

	uuid "github.com/satori/go.uuid"
)

// stream manages in-memory pub/sub of byte streams per device/app UUID.
// Subscribers register per device/app and receive published data over a channel.
// Publishing is non-blocking and lossless: each subscriber has an unbounded queue.
type stream struct {
	sync.RWMutex
	subscribers map[instanceID][]*streamSubscriber
}

type instanceID struct {
	// mandatory
	devUUID uuid.UUID

	// optional, leave empty when identifying device as a whole
	appUUID uuid.UUID
}

// streamSubscriber represents a single subscriber of a device stream.
// Published data is appended to an unbounded queue and drained into the
// output channel by a dedicated goroutine, so that a burst of entries (e.g. a
// whole gzipped log chunk uploaded by the device) is never dropped just because
// the HTTP client reads more slowly than the publisher writes.
type streamSubscriber struct {
	mu     sync.Mutex
	queue  [][]byte
	notify chan struct{} // capacity 1
	out    chan []byte
	done   chan struct{}
}

func (sub *streamSubscriber) enqueue(data []byte) {
	sub.mu.Lock()
	sub.queue = append(sub.queue, data)
	sub.mu.Unlock()
	select {
	case sub.notify <- struct{}{}:
	default:
	}
}

func (sub *streamSubscriber) pump() {
	defer close(sub.out)
	for {
		sub.mu.Lock()
		batch := sub.queue
		sub.queue = nil
		sub.mu.Unlock()

		if len(batch) == 0 {
			select {
			case <-sub.notify:
				continue
			case <-sub.done:
				return
			}
		}
		for _, data := range batch {
			select {
			case sub.out <- data:
			case <-sub.done:
				return
			}
		}
	}
}

// publish delivers data to all subscribers registered for the given device/app.
// It never blocks and never drops data for live subscribers.
func (s *stream) publish(id instanceID, data []byte) {
	s.RLock()
	defer s.RUnlock()

	for _, sub := range s.subscribers[id] {
		sub.enqueue(data)
	}
}

// subscribe registers a new subscriber for the given device/app.
// It returns:
//   - a read-only channel on which published data is delivered
//   - an unsubscribe function that removes the subscriber (idempotent)
//
// Once subscribe returns, every subsequently published item is guaranteed to
// be delivered (until unsubscribe is called). The channel is closed after
// unsubscribe. The returned unsubscribe function is safe to call multiple
// times.
func (s *stream) subscribe(id instanceID) (<-chan []byte, func()) {
	sub := &streamSubscriber{
		notify: make(chan struct{}, 1),
		out:    make(chan []byte, 100),
		done:   make(chan struct{}),
	}
	go sub.pump()

	s.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[instanceID][]*streamSubscriber)
	}
	s.subscribers[id] = append(s.subscribers[id], sub)
	s.Unlock()

	var once sync.Once

	unsubscribe := func() {
		once.Do(func() {
			s.Lock()
			subs := s.subscribers[id]
			for i := range subs {
				if subs[i] == sub {
					// Remove subscriber from the list.
					s.subscribers[id] = append(subs[:i], subs[i+1:]...)
					break
				}
			}
			// Clean up empty slice to avoid map growth.
			if len(s.subscribers[id]) == 0 {
				delete(s.subscribers, id)
			}
			s.Unlock()
			close(sub.done)
		})
	}

	return sub.out, unsubscribe
}
