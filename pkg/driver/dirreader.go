package driver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
)

// DirReader reads the contents of all files in a directory, sorted by whatever the OS does
type DirReader struct {
	// Path path to the directory to read content from
	Path        string
	dir         *os.File
	fileCache   []os.FileInfo
	currentFile *os.File
	complete    bool
}

// Read the next chunk of bytes
func (d *DirReader) Read(p []byte) (n int, err error) {
	if d.Path == "" {
		return 0, errors.New("directory to read required")
	}
	if d.dir == nil {
		dir, err := os.Open(d.Path)
		if err != nil {
			return 0, fmt.Errorf("unable to read directory %s: %v", d.Path, err)
		}
		d.dir = dir
	}
	// if we already read everything, we are done
	if d.complete {
		return 0, io.EOF
	}
	// if we have no open file, and are not complete, then we start from scratch
	if d.currentFile == nil {
		if err := d.nextFile(); err != nil {
			return 0, err
		}
	}
	// at this point, d.currentFile cannot be nil
	b := make([]byte, len(p))
	read, err := d.currentFile.Read(b)
	if read > 0 {
		copy(p, b)
	}
	// we had an error but it wasn't end of file
	// or we had no error at all
	if err == nil || (err != nil && err != io.EOF) {
		return read, err
	}
	// we had an EOF; try to get the next file. Three possibilities:
	// - we had an EOF: no more files, so just return the EOF
	// - we had a non-EOF error: return it
	// - we had no error, so keep going
	if err := d.nextFile(); err != nil {
		return 0, err
	}

	return read, nil
}

func (d *DirReader) nextFile() error {
	if d.complete {
		return io.EOF
	}
	// find the next file that is a regular file
	// if none is found, either return io.EOF or, if watching,
	// wait for one
	for {
		if len(d.fileCache) > 0 {
			break
		}
		entries, err := d.dir.Readdir(10)
		// even if it is an EOF, we return it
		if err != nil {
			d.complete = true
			return err
		}
		// nothing left to read
		if len(entries) == 0 {
			d.complete = true
			return io.EOF
		}
		// take only regular files
		files := make([]os.FileInfo, 0)
		for _, e := range entries {
			if e.Mode().IsRegular() {
				files = append(files, e)
			}
		}
		d.fileCache = files
	}

	var fi os.FileInfo
	// at this point we have files in the cache, or have reloaded it
	switch len(d.fileCache) {
	case 0:
		// if we have 0, nothing left
		d.complete = true
		return io.EOF
	case 1:
		fi = d.fileCache[0]
		d.fileCache = d.fileCache[:0]
	default:
		fi = d.fileCache[0]
		d.fileCache = d.fileCache[1:]
	}
	// open the file
	f, err := os.Open(path.Join(d.Path, fi.Name()))
	if err != nil {
		d.complete = true
		return err
	}
	d.currentFile = f
	return nil
}
