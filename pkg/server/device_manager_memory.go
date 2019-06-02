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
	onboardCerts map[string]*x509.Certificate
	deviceCerts  map[string]uuid.UUID
	devices      map[uuid.UUID]deviceStorage
}
type deviceStorage struct {
	cert    *x509.Certificate
	info    []*info.ZInfoMsg
	metrics []*metrics.ZMetricMsg
	logs    []*logs.LogBundle
	config  *config.EdgeDevConfig
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *deviceManagerMemory) SetCacheTimeout(timeout int) {
}

// CheckOnboardCert see if a particular certificate is a valid onboard certificate
func (d *deviceManagerMemory) CheckOnboardCert(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("invalid nil certificate")
	}
	certStr := string(cert.Raw)
	if _, ok := d.onboardCerts[certStr]; ok {
		return true, nil
	}
	return false, nil
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
func (d *deviceManagerMemory) RegisterDeviceCert(cert *x509.Certificate) (*uuid.UUID, error) {
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
	d.deviceCerts[string(cert.Raw)] = unew
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
