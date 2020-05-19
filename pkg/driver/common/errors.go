package common

// NotFoundError error representing that an item was not found
type NotFoundError struct {
	Err string
}

func (n *NotFoundError) Error() string {
	return n.Err
}

// InvalidCertError error representing that a certificate is not valid
type InvalidCertError struct {
	Err string
}

func (n *InvalidCertError) Error() string {
	return n.Err
}

// InvalidSerialError error representing that a serial is not valid
type InvalidSerialError struct {
	Err string
}

func (n *InvalidSerialError) Error() string {
	return n.Err
}

// UsedSerialError error representing that a serial was used already
type UsedSerialError struct {
	Err string
}

func (n *UsedSerialError) Error() string {
	return n.Err
}
