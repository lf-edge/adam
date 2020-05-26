package driver_test

import (
	"testing"

	"github.com/lf-edge/adam/pkg/driver"

	"github.com/stretchr/testify/assert"
)

func TestURLs(t *testing.T) {
	for _, url := range []string{"redis://localhost:123/0", "redis://username:password@localhost/1", "redis://"} {
		t.Run("redis-url", func(t *testing.T) {
			var mgr driver.DeviceManager
			for _, mgr = range driver.GetDeviceManagers() {
				if ok, _ := mgr.Init(url, 0, 0, 0); ok {
					break
				}
			}

			assert.Equal(t, "redis", mgr.Name())
		})
	}

	for _, url := range []string{"", "foo/bar/baz", "http://google.com", "/etc/hosts", "redis://a.b:1/2/3/4"} {
		t.Run("non-redis-url", func(t *testing.T) {
			var mgr driver.DeviceManager
			for _, mgr = range driver.GetDeviceManagers() {
				if ok, _ := mgr.Init(url, 0, 0, 0); ok {
					break
				}
			}

			assert.NotEqual(t, "redis", mgr.Name())
		})
	}
}
