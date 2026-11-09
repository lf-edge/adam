// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"testing"
	"time"
)

// A burst larger than any channel buffer must be delivered in full and in order.
func TestStreamBurstNotDropped(t *testing.T) {
	s := &stream{}
	id := instanceID{}
	c, unsub := s.subscribe(id)
	const n = 5000
	for i := 0; i < n; i++ {
		s.publish(id, []byte(fmt.Sprint(i)))
	}
	for i := 0; i < n; i++ {
		select {
		case b := <-c:
			if string(b) != fmt.Sprint(i) {
				t.Fatalf("entry %d: got %q", i, b)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for entry %d", i)
		}
	}
	unsub()
	unsub()
	if _, ok := <-c; ok {
		t.Fatal("channel not closed after unsubscribe")
	}
}
