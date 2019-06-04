package server

// slice of registered device managers
// goes through them in order
// called as a func so that the handler disappears after the server first is created
func getDeviceManagers() []DeviceManager {
	return []DeviceManager{
		&DeviceManagerMemory{},
		&DeviceManagerFile{},
	}
}
