// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"encoding/json"
	"errors"
	"github.com/go-redis/redis"
	"github.com/vmihailenco/msgpack/v4"
	"time"
)

// RedisStreamReader reads msgpack messages from Redis streams and turns then into JSON strings
type RedisStreamReader struct {
	// Redis client handle
	Client *redis.Client
	// Name of a stream
	Stream string
	// LineFeed whether to put a linefeed "\n" (0x0a) after each file
	LineFeed    bool

	// unconsumed data from the last message from the previous read
	data []byte
	// offset
	offset string
	// if set to true, next Read should return a linefeed character
	nextLF bool
}

// Read the next chunk of bytes (do we ever return EOF?)
func (d *RedisStreamReader) Read(p []byte) (n int, err error) {
	if d.Client == nil || d.Stream == "" {
		return 0, errors.New("redis connection and name of the stream required")
	}

	// cannot write if no space
	if len(p) == 0 {
		return 0, errors.New("must have at least one byte in slice to write")
	}
	// do we send a linefeed?
	if d.nextLF {
		p[0] = 0x0a
		d.nextLF = false
		return 1, nil
	}

	// lets see if we need to get some more messages from the stream first
	if len(d.data) == 0 {
		if d.offset == "" {
			d.offset = "0"
		}

		records, err := d.Client.XRead(&redis.XReadArgs{
			Streams: []string {d.Stream, d.offset},
			Block: time.Millisecond, // do a non-blocking read
			Count: 1,
		}).Result()
		// it is weird that the library would return "redis: nil" for a non-blocking read
		if (err != nil && err.Error() != "redis: nil") || len(records) > 1 {
			return 0, errors.New("failed to read from stream")
		}
		if records == nil || len(records[0].Messages) == 0 {
			return 0, nil
		} else {
			d.offset = records[0].Messages[0].ID
			s, ok := records[0].Messages[0].Values["object"].(string)
			if !ok {
				return 0, errors.New("failed to read from stream")
			}

			// maybe there's a clever way to go straight from msgpack -> JSON?
            var data interface{}
			err = msgpack.Unmarshal([]byte(s), &data)
			if err != nil {
				return 0, errors.New("failed to read from stream")
			}
			res, err := json.Marshal(data)
			if err != nil {
				return 0, errors.New("failed to read from stream")
			}

			d.data = res
		}
	}

	// transfer the data
	consumed := 0
	if len(d.data) > 0 {
		consumed = copy(p, d.data)
		d.data = d.data[consumed:]
	}

	// indicate that the next read should include a linefeed
	if d.LineFeed {
		d.nextLF = true
	}

	return consumed, nil
}