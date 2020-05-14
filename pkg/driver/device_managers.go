// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

// GetDeviceManagers get list of supported device managers
// slice of registered device managers
// goes through them in order
// called as a func so that the handler disappears after the server first is created
func GetDeviceManagers() []DeviceManager {
	return []DeviceManager{
		&DeviceManagerMemory{},
		&DeviceManagerRedis{},
		&DeviceManagerFile{}, // this needs to be the last catch-all one
	}
}
