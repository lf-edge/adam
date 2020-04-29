package driver

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/golang/protobuf/jsonpb"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
)

// LogsReader reads slice of logs protobuf messages
type LogsReader struct {
	Msgs       []*logs.LogBundle
	currentMsg int
	msgCache   []byte
	complete   bool
}

// Read the next chunk of bytes
func (r *LogsReader) Read(p []byte) (n int, err error) {
	if r.Msgs == nil {
		return 0, errors.New("uninitialized")
	}
	// if we already read everything, we are done
	if r.complete {
		return 0, io.EOF
	}
	// if we have no message converted, convert the next one
	if len(r.msgCache) == 0 {
		if len(r.Msgs) == 0 || r.currentMsg >= len(r.Msgs) {
			r.complete = true
			return 0, io.EOF
		}
		m := r.Msgs[r.currentMsg]
		r.currentMsg++

		// convert it
		buf := bytes.NewBuffer(make([]byte, 0))

		mler := jsonpb.Marshaler{}
		err = mler.Marshal(buf, m)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal protobuf message into json: %v", err)
		}
		r.msgCache = buf.Bytes()
	}
	// read the data from the msg cache
	copied := copy(p, r.msgCache)
	// truncate the msgCache
	if copied >= len(r.msgCache) {
		r.msgCache = r.msgCache[:0]
	} else {
		r.msgCache = r.msgCache[copied:]
	}
	// we do not worried about returning less than they requested; as long as we
	// do not return an io.EOF, they will come back for more
	return copied, nil
}

// InfoReader reads slice of info protobuf messages
type InfoReader struct {
	Msgs       []*info.ZInfoMsg
	currentMsg int
	msgCache   []byte
	complete   bool
}

// Read the next chunk of bytes
func (r *InfoReader) Read(p []byte) (n int, err error) {
	if r.Msgs == nil {
		return 0, errors.New("uninitialized")
	}
	// if we already read everything, we are done
	if r.complete {
		return 0, io.EOF
	}
	// if we have no message converted, convert the next one
	if len(r.msgCache) == 0 {
		if len(r.Msgs) == 0 || r.currentMsg >= len(r.Msgs) {
			r.complete = true
			return 0, io.EOF
		}
		m := r.Msgs[r.currentMsg]
		r.currentMsg++

		// convert it		b := make([]byte, 0)
		buf := bytes.NewBuffer(make([]byte, 0))

		mler := jsonpb.Marshaler{}
		err = mler.Marshal(buf, m)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal protobuf message into json: %v", err)
		}
		r.msgCache = buf.Bytes()
	}
	// read the data from the msg cache
	copied := copy(p, r.msgCache)
	// truncate the msgCache
	if copied >= len(r.msgCache) {
		r.msgCache = r.msgCache[:0]
	} else {
		r.msgCache = r.msgCache[copied:]
	}
	// we do not worried about returning less than they requested; as long as we
	// do not return an io.EOF, they will come back for more
	return copied, nil
}
