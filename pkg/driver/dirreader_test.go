package driver_test

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/lf-edge/adam/pkg/driver"
)

// DirReader reads the contents of all files in a directory, sorted by whatever the OS does
func TestDirReader(t *testing.T) {
	t.Run("no path", func(t *testing.T) {
		dr := &driver.DirReader{}
		b := make([]byte, 40)
		n, err := dr.Read(b)
		if n != 0 {
			t.Errorf("received %d bytes instead of expected %d", n, 0)
		}
		if !strings.HasPrefix(err.Error(), "directory to read required") {
			t.Errorf("mismatched error, expected 'directory to read', had '%v'", err)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		dr := &driver.DirReader{
			Path: "/this/is/a/asasas/that/does/not/exist",
		}
		b := make([]byte, 40)
		n, err := dr.Read(b)
		if n != 0 {
			t.Errorf("received %d bytes instead of expected %d", n, 0)
		}
		if !strings.HasPrefix(err.Error(), "unable to read directory") {
			t.Errorf("mismatched error, expected 'directory to read', had '%v'", err)
		}
	})
	t.Run("empty directory", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "dirreader_test")
		if err != nil {
			t.Fatalf("failure to create temporary directory: %v", err)
		}
		defer os.RemoveAll(dir)
		dr := &driver.DirReader{
			Path: dir,
		}
		b := make([]byte, 40)
		n, err := dr.Read(b)
		if n != 0 {
			t.Errorf("received %d bytes instead of expected %d", n, 0)
		}
		if err != io.EOF {
			t.Errorf("mismatched error, expected 'EOF', had '%v'", err)
		}
	})
	t.Run("single small file", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "dirreader_test")
		if err != nil {
			t.Fatalf("failure to create temporary directory: %v", err)
		}
		// create the file that is smaller than our buffer
		data := []byte("Really small file")
		if err := ioutil.WriteFile(path.Join(dir, "A"), data, 0644); err != nil {
			t.Fatalf("failure to write temporary file: %v", err)
		}
		defer os.RemoveAll(dir)
		dr := &driver.DirReader{
			Path: dir,
		}
		b := make([]byte, 40)
		n, err := dr.Read(b)
		if n != len(data) {
			t.Errorf("received %d bytes instead of expected %d", n, len(data))
		}
		if err != nil {
			t.Errorf("mismatched error, expected 'nil', had '%v'", err)
		}
		if !bytes.Equal(b[:n], data[:n]) {
			t.Errorf("mismatched data\nactual: '%s'\nexpected: '%s'", b[:n], data[:n])
		}

		// now read again to check EOF
		n, err = dr.Read(b)
		if n != 0 {
			t.Errorf("received %d bytes instead of expected %d", n, 0)
		}
		if err != io.EOF {
			t.Errorf("mismatched error, expected 'EOF', had '%v'", err)
		}
	})
	t.Run("single large file", func(t *testing.T) {
		data := []byte("Really large file with lots of data bigger than our buffer")
		dir, err := ioutil.TempDir("", "dirreader_test")
		if err != nil {
			t.Fatalf("failure to create temporary directory: %v", err)
		}
		// create the file that is larger than our buffer
		if err := ioutil.WriteFile(path.Join(dir, "A"), data, 0644); err != nil {
			t.Fatalf("failure to write temporary file: %v", err)
		}
		defer os.RemoveAll(dir)

		// test a single read, and converting it to a reader
		t.Run("single read", func(t *testing.T) {
			dr := &driver.DirReader{
				Path: dir,
			}
			b := make([]byte, 40)
			n, err := dr.Read(b)
			if n != len(b) {
				t.Errorf("received %d bytes instead of expected %d", n, len(b))
			}
			if err != nil {
				t.Errorf("mismatched error, expected 'nil', had '%v'", err)
			}
			if !bytes.Equal(b, data[0:40]) {
				t.Errorf("mismatched data\nactual: %s\nexpected: %s", b, data[0:40])
			}
		})
		t.Run("full read", func(t *testing.T) {
			dr := &driver.DirReader{
				Path: dir,
			}
			b := make([]byte, 0)
			buf := bytes.NewBuffer(b)
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
	t.Run("multiple files", func(t *testing.T) {
		data1 := []byte("Really large file with lots of data bigger than our buffer")
		data2 := []byte("yet another file with lots of gibberish data to put in")

		dir, err := ioutil.TempDir("", "dirreader_test")
		if err != nil {
			t.Fatalf("failure to create temporary directory: %v", err)
		}
		// create the multiple files that together are larger than our buffer
		if err := ioutil.WriteFile(path.Join(dir, "A"), data1, 0644); err != nil {
			t.Fatalf("failure to write temporary file: %v", err)
		}
		if err := ioutil.WriteFile(path.Join(dir, "B"), data2, 0644); err != nil {
			t.Fatalf("failure to write temporary file: %v", err)
		}

		defer os.RemoveAll(dir)

		// test a single read, and converting it to a reader
		t.Run("single read", func(t *testing.T) {
			dr := &driver.DirReader{
				Path: dir,
			}
			b := make([]byte, 40)
			n, err := dr.Read(b)
			if n != len(b) {
				t.Errorf("received %d bytes instead of expected %d", n, len(b))
			}
			if err != nil {
				t.Errorf("mismatched error, expected 'nil', had '%v'", err)
			}
			if !bytes.Equal(b, data1[0:40]) {
				t.Errorf("mismatched data\nactual: %s\nexpected: %s", b, data1[0:40])
			}
		})
		t.Run("full read", func(t *testing.T) {
			dr := &driver.DirReader{
				Path: dir,
			}
			b := make([]byte, 0)
			buf := bytes.NewBuffer(b)
			n, err := io.Copy(buf, dr)

			expected := append(data1, data2...)
			if int(n) != len(expected) {
				t.Errorf("received %d bytes instead of expected %d", n, len(expected))
			}
			if err != nil {
				t.Errorf("mismatched error, expected 'nil', had '%v'", err)
			}
			output := buf.Bytes()
			if !bytes.Equal(output, expected) {
				t.Errorf("mismatched data\nactual: %s\nexpected: %s", output, expected)
			}
		})
	})
}
