package server

import (
	"crypto/x509"
	"fmt"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
)

type deviceManagerMemory struct {
	onboardCerts map[string]map[string]bool
	deviceCerts  map[string]uuid.UUID
	devices      map[uuid.UUID]deviceStorage
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *deviceManagerMemory) SetCacheTimeout(timeout int) {
}

// CheckOnboardCert see if a particular certificate plus serial combinaton is valid
func (d *deviceManagerMemory) CheckOnboardCert(cert *x509.Certificate, serial string) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("invalid nil certificate")
	}
	if !d.checkValidOnboardSerial(cert, serial) {
		return false, nil
	}
	if d.getOnboardSerialDevice(cert, serial) != nil {
		return false, nil
	}
	return true, nil
}

// CheckDeviceCert see if a particular certificate is a valid registered device certificate
func (d *deviceManagerMemory) CheckDeviceCert(cert *x509.Certificate) (*uuid.UUID, error) {
	if cert == nil {
		return nil, fmt.Errorf("invalid nil certificate")
	}
	certStr := string(cert.Raw)
	if u, ok := d.deviceCerts[certStr]; ok {
		return &u, nil
	}
	return nil, nil
}

// RegisterDeviceCert register a new device cert
func (d *deviceManagerMemory) RegisterDeviceCert(cert, onboard *x509.Certificate, serial string) (*uuid.UUID, error) {
	// first check if it already exists - this also checks for nil cert
	u, err := d.CheckDeviceCert(cert)
	if err != nil {
		return nil, err
	}
	// if we found a uuid, then it already exists
	if u != nil {
		return nil, fmt.Errorf("device already registered")
	}
	// generate a new uuid
	unew, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("error generating uuid for device: %v", err)
	}
	// register the cert for this uuid
	d.deviceCerts[string(cert.Raw)] = unew
	// create a structure for this device
	d.devices[unew] = deviceStorage{
		onboard: onboard,
		serial:  serial,
	}
	return &unew, nil
}

// WriteInfo write an info message
func (d *deviceManagerMemory) WriteInfo(m *info.ZInfoMsg) error {
	// make sure it is not nil
	if m == nil {
		return fmt.Errorf("invalid nil message")
	}
	// get the uuid
	u, err := uuid.FromString(m.DevId)
	if err != nil {
		return fmt.Errorf("unable to retrieve valid device UUID from message as %s: %v", m.DevId, err)
	}
	// now look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", m.DevId)
	}
	// append the messages
	dev.info = append(dev.info, m)
	return nil
}

// WriteLogs write a message of logs
func (d *deviceManagerMemory) WriteLogs(m *logs.LogBundle) error {
	// make sure it is not nil
	if m == nil {
		return fmt.Errorf("invalid nil message")
	}
	// get the uuid
	u, err := uuid.FromString(m.DevID)
	if err != nil {
		return fmt.Errorf("unable to retrieve valid device UUID from message as %s: %v", m.DevID, err)
	}
	// now look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", m.DevID)
	}
	// append the messages
	dev.logs = append(dev.logs, m)
	return nil
}

// WriteMetrics write a metrics message
func (d *deviceManagerMemory) WriteMetrics(m *metrics.ZMetricMsg) error {
	// make sure it is not nil
	if m == nil {
		return fmt.Errorf("invalid nil message")
	}
	// get the uuid
	u, err := uuid.FromString(m.DevID)
	if err != nil {
		return fmt.Errorf("unable to retrieve valid device UUID from message as %s: %v", m.DevID, err)
	}
	// now look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", m.DevID)
	}
	// append the messages
	dev.metrics = append(dev.metrics, m)
	return nil
}

// GetConfig retrieve the config for a particular device
func (d *deviceManagerMemory) GetConfig(u uuid.UUID) (*config.EdgeDevConfig, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.config, nil
}

// checkValidOnboardSerial see if a particular certificate+serial combinaton is valid
// does **not** check if it has been used
func (d *deviceManagerMemory) checkValidOnboardSerial(cert *x509.Certificate, serial string) bool {
	certStr := string(cert.Raw)
	if c, ok := d.onboardCerts[certStr]; ok {
		// accept the specific serial or the wildcard
		if _, ok := c[serial]; ok {
			return true
		}
		if _, ok := c["*"]; ok {
			return true
		}
	}
	return false
}

// getOnboardSerialDevice see if a particular certificate+serial combinaton has been used and get its device uuid
func (d *deviceManagerMemory) getOnboardSerialDevice(cert *x509.Certificate, serial string) *uuid.UUID {
	certStr := string(cert.Raw)
	for uid, dev := range d.devices {
		dCertStr := string(dev.onboard.Raw)
		if dCertStr == certStr && serial == dev.serial {
			return &uid
		}
	}
	return nil
}
