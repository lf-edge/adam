package memory

import (
	"fmt"
	"io"
)

type ByteSlice struct {
	// we do this as a slice of byte slice, rather than a single byte slice,
	// because we need to track breaks, so we can delete from the beginning
	data         [][]byte
	dataCache    []byte
	currentRead  int
	readComplete bool
	maxSize      int
	size         int
}

func (bs ByteSlice) Get(index int) ([]byte, error) {
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

func (bs ByteSlice) Reader() (io.Reader, error) {
	return bs, nil
}

func (bs ByteSlice) Read(p []byte) (int, error) {
	if bs.readComplete {
		return 0, io.EOF
	}
	// start with the current read
	if len(bs.dataCache) == 0 {
		if len(bs.data) == 0 || bs.currentRead >= len(bs.data) {
			bs.readComplete = true
			return 0, io.EOF
		}
		// include the linefeed
		bs.dataCache = append(bs.data[bs.currentRead], 0x0a)
		bs.currentRead++
	}
	// read the data from the msg cache
	copied := copy(p, bs.dataCache)
	// truncate the dataCache
	if copied >= len(bs.dataCache) {
		bs.dataCache = bs.dataCache[:0]
	} else {
		bs.dataCache = bs.dataCache[copied:]
	}
	// we do not worried about returning less than they requested; as long as we
	// do not return an io.EOF, they will come back for more
	return copied, nil
}
