package driver_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/eve/api/go/logs"
)

// DirReader reads the contents of all files in a directory, sorted by whatever the OS does
func TestLogsReader(t *testing.T) {
	t.Run("no messages", func(t *testing.T) {
		dr := &driver.LogsReader{}
		b := make([]byte, 40)
		n, err := dr.Read(b)
		if n != 0 {
			t.Errorf("received %d bytes instead of expected %d", n, 0)
		}
		if !strings.HasPrefix(err.Error(), "uninitialized") {
			t.Errorf("mismatched error, expected 'uninitialized', had '%v'", err)
		}
	})
	t.Run("single message", func(t *testing.T) {
		lb := []*logs.LogBundle{
			&logs.LogBundle{
				Timestamp: &timestamp.Timestamp{
					Seconds: int64(1000),
				},
			},
		}

		// test a single read, and converting it to a reader
		t.Run("single read", func(t *testing.T) {
			dr := &driver.LogsReader{
				Msgs: lb,
			}
			buf := bytes.NewBuffer(make([]byte, 0))
			mler := jsonpb.Marshaler{}
			if err := mler.Marshal(buf, lb[0]); err != nil {
				t.Errorf("failed to marshal message into json: %v", err)
			}
			data := buf.Bytes()

			b := make([]byte, 40)
			n, err := dr.Read(b)

			if n != len(data) {
				t.Errorf("received %d bytes instead of expected %d", n, len(data))
			}
			if err != nil {
				t.Errorf("mismatched error, expected 'nil', had '%v'", err)
			}
			if !bytes.Equal(b[:n], data) {
				t.Errorf("mismatched data\nactual: '%s'\nexpected: '%s'", b[:n], data)
			}
		})
		t.Run("full read", func(t *testing.T) {
			dr := &driver.LogsReader{
				Msgs: lb,
			}
			buf := bytes.NewBuffer(make([]byte, 0))
			mler := jsonpb.Marshaler{}
			if err := mler.Marshal(buf, lb[0]); err != nil {
				t.Errorf("failed to marshal message into json: %v", err)
			}
			data := buf.Bytes()

			buf = bytes.NewBuffer(make([]byte, 0))
			n, err := io.Copy(buf, dr)

			if int(n) != len(data) {
				t.Errorf("received %d bytes instead of expected %d", n, len(data))
			}
			if err != nil {
				t.Errorf("mismatched error, expected 'nil', had '%v'", err)
			}
			output := buf.Bytes()
			if !bytes.Equal(output, data) {
				t.Errorf("mismatched data\nactual: %s\nexpected: %s", output, data)
			}
		})
	})
	t.Run("multiple messages", func(t *testing.T) {
		lb := []*logs.LogBundle{
			&logs.LogBundle{
				Timestamp: &timestamp.Timestamp{
					Seconds: int64(1000),
				},
			},
			&logs.LogBundle{
				Timestamp: &timestamp.Timestamp{
					Seconds: int64(2000),
				},
			},
		}
		// test a single read, and converting it to a reader
		t.Run("single read", func(t *testing.T) {
			dr := &driver.LogsReader{
				Msgs: lb,
			}
			buf := bytes.NewBuffer(make([]byte, 0))
			mler := jsonpb.Marshaler{}
			if err := mler.Marshal(buf, lb[0]); err != nil {
				t.Errorf("failed to marshal message into json: %v", err)
			}
			data := buf.Bytes()

			b := make([]byte, 40)
			n, err := dr.Read(b)

			if n != len(data) {
				t.Errorf("received %d bytes instead of expected %d", n, len(data))
			}
			if err != nil {
				t.Errorf("mismatched error, expected 'nil', had '%v'", err)
			}
			if !bytes.Equal(b[:n], data) {
				t.Errorf("mismatched data\nactual: '%s'\nexpected: '%s'", b[:n], data)
			}
		})
		t.Run("full read", func(t *testing.T) {
			dr := &driver.LogsReader{
				Msgs: lb,
			}
			buf := bytes.NewBuffer(make([]byte, 0))
			mler := jsonpb.Marshaler{}
			for _, m := range lb {
				if err := mler.Marshal(buf, m); err != nil {
					t.Errorf("failed to marshal message into json: %v", err)
				}
			}
			data := buf.Bytes()

			buf = bytes.NewBuffer(make([]byte, 0))
			n, err := io.Copy(buf, dr)

			if int(n) != len(data) {
				t.Errorf("received %d bytes instead of expected %d", n, len(data))
			}
			if err != nil {
				t.Errorf("mismatched error, expected 'nil', had '%v'", err)
			}
			output := buf.Bytes()
			if !bytes.Equal(output, data) {
				t.Errorf("mismatched data\nactual: %s\nexpected: %s", output, data)
			}
		})
	})
}
