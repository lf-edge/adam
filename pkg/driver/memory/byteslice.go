package memory

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lf-edge/adam/pkg/driver/common"
)

type ByteSlice struct {
	// we do this as a slice of byte slice, rather than a single byte slice,
	// because we need to track breaks, so we can delete from the beginning
	data         [][]byte
	currentRead  int
	readComplete bool
	maxSize      int
	size         int
}

func (bs *ByteSlice) Get(index int) ([]byte, error) {
	if len(bs.data) < index+1 {
		return nil, fmt.Errorf("array out of bounds: %d", index)
	}
	return bs.data[index], nil
}

func (bs *ByteSlice) Write(b []byte) (int, error) {
	// write it to the current one
	bs.data = append(bs.data, b[:])
	bs.size += len(b)
	for {
		if bs.size <= bs.maxSize {
			break
		}
		if len(bs.data) == 0 {
			break
		}
		bs.size -= len(bs.data[0])
		bs.data = bs.data[1:]
		// this will mess up the current reader, so we need to update it
		bs.currentRead--
	}
	return len(b), nil
}

func (bs *ByteSlice) Reader() (common.ChunkReader, error) {
	return bs, nil
}

// Next returns reader for the next chunk of data (message), its size and possible error
func (bs *ByteSlice) Next() (io.Reader, int64, error) {
	if len(bs.data) == 0 || bs.currentRead >= len(bs.data) {
		return nil, 0, io.EOF
	}
	reader := bytes.NewReader(bs.data[bs.currentRead])
	size := int64(len(bs.data[bs.currentRead]))
	bs.currentRead++
	return reader, size, nil
}
