package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func WriteRename(fileName string, b []byte) error {
	dirName := filepath.Dir(fileName)
	// Do atomic rename to avoid partially written files
	tmpfile, err := os.CreateTemp(dirName, "tmp")
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(b)
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	// Make sure the file is flushed from buffers onto the disk
	if err := tmpfile.Sync(); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s) failed to sync temp file: %s",
			fileName, err)
		return errors.New(errStr)
	}

	if err := tmpfile.Close(); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}

	if err := os.Rename(tmpfile.Name(), fileName); err != nil {
		errStr := fmt.Sprintf("writeRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}

	return DirSync(filepath.Dir(fileName))
}

// DirSync flushes changes made to a directory.
func DirSync(dirName string) error {
	f, err := os.OpenFile(dirName, os.O_RDONLY, 0755)
	if err != nil {
		return err
	}

	err = f.Sync()
	if err != nil {
		f.Close()
		return err
	}

	// Not a deferred call, because DirSync is a critical
	// path. Better safe then sorry, and we better check all the
	// errors including one returned by close()
	err = f.Close()
	return err
}
