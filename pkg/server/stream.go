// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"

	uuid "github.com/satori/go.uuid"
)

// stream manages in-memory pub/sub of byte streams per device/app UUID.
// Subscribers register per device/app and receive published data over a channel.
// Publishing is non-blocking; slow subscribers will have data dropped.
type stream struct {
	sync.RWMutex
	subscribers map[instanceID][]streamSubscriber
}

type instanceID struct {
	// mandatory
	devUUID uuid.UUID

	// optional, leave empty when identifying device as a whole
	appUUID uuid.UUID
}

// streamSubscriber represents a single subscriber of a device stream.
// Data is delivered over the channel. The channel is buffered to avoid
// blocking publishers.
type streamSubscriber struct {
	channel chan []byte
}

// publish delivers data to all subscribers registered for the given device/app.
// Delivery is non-blocking; if a subscriber's channel buffer is full,
// the message is dropped for that subscriber.
func (s *stream) publish(id instanceID, data []byte) {
	s.RLock()
	defer s.RUnlock()

	for _, sub := range s.subscribers[id] {
		select {
		case sub.channel <- data:
		default:
			// Drop if subscriber is slow.
		}
	}
}

// subscribe registers a new subscriber for the given device/app.
// It returns:
//   - a read-only channel on which published data is delivered
//   - an unsubscribe function that removes the subscriber (idempotent)
//
// The returned unsubscribe function is safe to call multiple times.
func (s *stream) subscribe(id instanceID) (<-chan []byte, func()) {
	s.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[instanceID][]streamSubscriber)
	}

	sub := streamSubscriber{
		channel: make(chan []byte, 100),
	}

	s.subscribers[id] = append(s.subscribers[id], sub)
	s.Unlock()

	var once sync.Once

	unsubscribe := func() {
		once.Do(func() {
			s.Lock()
			defer s.Unlock()

			subs := s.subscribers[id]
			for i := range subs {
				if subs[i].channel == sub.channel {
					// Remove subscriber from the list.
					s.subscribers[id] = append(subs[:i], subs[i+1:]...)
					break
				}
			}

			// Clean up empty slice to avoid map growth.
			if len(s.subscribers[id]) == 0 {
				delete(s.subscribers, id)
			}

			close(sub.channel)
		})
	}

	return sub.channel, unsubscribe
}
