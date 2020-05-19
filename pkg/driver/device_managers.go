// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"github.com/lf-edge/adam/pkg/driver/file"
	"github.com/lf-edge/adam/pkg/driver/memory"
	"github.com/lf-edge/adam/pkg/driver/redis"
)

// GetDeviceManagers get list of supported device managers
// slice of registered device managers
// goes through them in order
// called as a func so that the handler disappears after the server first is created
func GetDeviceManagers() []DeviceManager {
	return []DeviceManager{
		&memory.DeviceManager{},
		&redis.DeviceManager{},
		&file.DeviceManager{}, // this needs to be the last catch-all one
	}
}
