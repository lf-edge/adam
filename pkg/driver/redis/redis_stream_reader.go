// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"bytes"
	"errors"
	"io"
	"time"

	"github.com/go-redis/redis"
)

// RedisStreamReader reads msgpack messages from Redis streams and turns then into JSON strings
type RedisStreamReader struct {
	// Redis client handle
	Client *redis.Client
	// Name of a stream
	Stream string

	// offset
	offset string
}

// Next returns reader for the next chunk of data (message), its size and possible error
func (d *RedisStreamReader) Next() (io.Reader, int64, error) {
	if d.Client == nil || d.Stream == "" {
		return nil, 0, errors.New("redis connection and name of the stream required")
	}
	if d.offset == "" {
		d.offset = "0"
	}
	records, err := d.Client.XRead(&redis.XReadArgs{
		Streams: []string{d.Stream, d.offset},
		Block:   time.Millisecond, // do a non-blocking read
		Count:   1,
	}).Result()
	// it is weird that the library would return "redis: nil" for a non-blocking read
	if (err != nil && err.Error() != "redis: nil") || len(records) > 1 {
		return nil, 0, errors.New("failed to read from stream")
	}
	if records == nil || len(records[0].Messages) == 0 {
		return nil, 0, nil
	}
	d.offset = records[0].Messages[0].ID
	s, ok := records[0].Messages[0].Values["object"].(string)
	if !ok {
		return nil, 0, errors.New("failed to read from stream")
	}
	return bytes.NewReader([]byte(s)), int64(len([]byte(s))), nil
}
