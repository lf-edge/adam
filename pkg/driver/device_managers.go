package driver

// GetDeviceManagers get list of supported device managers
// slice of registered device managers
// goes through them in order
// called as a func so that the handler disappears after the server first is created
func GetDeviceManagers() []DeviceManager {
	return []DeviceManager{
		&DeviceManagerMemory{},
		&DeviceManagerFile{},
	}
}
