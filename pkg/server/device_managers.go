package server

// slice of registered device managers
// goes through them in order
var deviceManagers = []DeviceManager{
	&DeviceManagerMemory{},
	&DeviceManagerFile{},
}
