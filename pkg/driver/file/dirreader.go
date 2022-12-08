package file

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
)

// DirReader reads the contents of all files in a directory, sorted by whatever the OS does and then lexicographically
type DirReader struct {
	// Path path to the directory to read content from
	Path string
	// MaxFiles maximum files to load in cache, or 0 for the entire directory
	MaxFiles    int
	dir         *os.File
	fileCache   []os.FileInfo
	currentFile *os.File
	currentSize int64
	complete    bool
}

// Next returns reader for the next chunk of data (message), its size and possible error
func (d *DirReader) Next() (io.Reader, int64, error) {
	if d.Path == "" {
		return nil, 0, errors.New("directory to read required")
	}
	if d.dir == nil {
		dir, err := os.Open(d.Path)
		if err != nil {
			return nil, 0, fmt.Errorf("unable to read directory %s: %v", d.Path, err)
		}
		d.dir = dir
	}
	// if we already read everything, we are done
	if d.complete {
		return nil, 0, io.EOF
	}
	if err := d.nextFile(); err != nil {
		return nil, 0, err
	}
	return d.currentFile, d.currentSize, nil
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
		entries, err := d.dir.Readdir(d.MaxFiles)
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
		// and sort
		sort.Slice(files, func(i int, j int) bool {
			return files[i].Name() < files[j].Name()
		})
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
	fstat, err := d.currentFile.Stat()
	if err != nil {
		return fmt.Errorf("unable to stat file %v", err)
	}
	d.currentSize = fstat.Size()
	return nil
}
