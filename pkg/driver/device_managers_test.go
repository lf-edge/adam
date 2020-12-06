package driver_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"

	"github.com/stretchr/testify/assert"
)

func TestURLs(t *testing.T) {
	for _, url := range []string{"redis://localhost:123/0", "redis://username:password@localhost/1", "redis://"} {
		t.Run("redis-url", func(t *testing.T) {
			var mgr driver.DeviceManager
			for _, mgr = range driver.GetDeviceManagers() {
				if ok, _ := mgr.Init(url, common.MaxSizes{}); ok {
					break
				}
			}

			assert.Equal(t, "redis", mgr.Name())
		})
	}

	// create a temporary working dir, because the file driver actually creates the directories
	tmpdir, err := ioutil.TempDir("", "adam-driver-test")
	if err != nil {
		t.Fatalf("could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(tmpdir)
	for _, url := range []string{"", path.Join(tmpdir, "foo/bar/baz"), "http://google.com", "/etc/hosts", "redis://a.b:1/2/3/4"} {
		t.Run("non-redis-url", func(t *testing.T) {
			var mgr driver.DeviceManager
			for _, mgr = range driver.GetDeviceManagers() {
				if ok, _ := mgr.Init(url, common.MaxSizes{}); ok {
					break
				}
			}

			assert.NotEqual(t, "redis", mgr.Name())
		})
	}
}
