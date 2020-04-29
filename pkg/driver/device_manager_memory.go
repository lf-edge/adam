// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
)

// DeviceManagerMemory implementation of DeviceManager with an ephemeral memory backing store
type DeviceManagerMemory struct {
	onboardCerts map[string]map[string]bool
	deviceCerts  map[string]uuid.UUID
	devices      map[uuid.UUID]deviceStorage
}

// Name return name
func (d *DeviceManagerMemory) Name() string {
	return "memory"
}

// Database return database path
func (d *DeviceManagerMemory) Database() string {
	return "memory"
}

// Init initialize, valid only with a blank URL
func (d *DeviceManagerMemory) Init(s string) (bool, error) {
	if s != "" {
		return false, nil
	}
	return true, nil
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *DeviceManagerMemory) SetCacheTimeout(timeout int) {
}

// OnboardCheck see if a particular certificate plus serial combinaton is valid
func (d *DeviceManagerMemory) OnboardCheck(cert *x509.Certificate, serial string) error {
	if cert == nil {
		return fmt.Errorf("invalid nil certificate")
	}
	if err := d.checkValidOnboardSerial(cert, serial); err != nil {
		return err
	}
	if d.getOnboardSerialDevice(cert, serial) != nil {
		return &UsedSerialError{err: fmt.Sprintf("serial already used for onboarding certificate: %s", serial)}
	}
	return nil
}

// OnboardRemove remove an onboard certificate based on Common Name
func (d *DeviceManagerMemory) OnboardRemove(cn string) error {
	cert, _, err := d.OnboardGet(cn)
	if err != nil {
		return err
	}
	delete(d.onboardCerts, string(cert.Raw))
	return nil
}

// OnboardClear remove all onboarding certs
func (d *DeviceManagerMemory) OnboardClear() error {
	d.onboardCerts = map[string]map[string]bool{}
	return nil
}

// OnboardGet get the onboard certificate and serials based on Common Name
func (d *DeviceManagerMemory) OnboardGet(cn string) (*x509.Certificate, []string, error) {
	if cn == "" {
		return nil, nil, fmt.Errorf("empty cn")
	}
	for certStr, serials := range d.onboardCerts {
		certRaw := []byte(certStr)
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse certificate: %v", err)
		}
		if cert.Subject.CommonName == cn {
			serialSlice := make([]string, 0, len(serials))
			for k := range serials {
				serialSlice = append(serialSlice, k)
			}
			return cert, serialSlice, nil
		}
	}
	return nil, nil, &NotFoundError{err: fmt.Sprintf("onboard cn not found: %s", cn)}
}

// OnboardList list all of the known Common Names for onboard
func (d *DeviceManagerMemory) OnboardList() ([]string, error) {
	cns := make([]string, 0, len(d.onboardCerts))
	for certStr := range d.onboardCerts {
		certRaw := []byte(certStr)
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %v", err)
		}
		cns = append(cns, cert.Subject.CommonName)
	}
	return cns, nil
}

// DeviceCheckCert see if a particular certificate is a valid registered device certificate
func (d *DeviceManagerMemory) DeviceCheckCert(cert *x509.Certificate) (*uuid.UUID, error) {
	if cert == nil {
		return nil, fmt.Errorf("invalid nil certificate")
	}
	certStr := string(cert.Raw)
	if u, ok := d.deviceCerts[certStr]; ok {
		return &u, nil
	}
	return nil, nil
}

// DeviceRemove remove a device
func (d *DeviceManagerMemory) DeviceRemove(u *uuid.UUID) error {
	cert, _, _, err := d.DeviceGet(u)
	if err != nil {
		return err
	}
	delete(d.devices, *u)
	if cert != nil {
		delete(d.deviceCerts, string(cert.Raw))
	}
	return nil
}

// DeviceClear remove all devices
func (d *DeviceManagerMemory) DeviceClear() error {
	d.deviceCerts = make(map[string]uuid.UUID)
	d.devices = make(map[uuid.UUID]deviceStorage)
	return nil
}

// DeviceGet get an individual device by UUID
func (d *DeviceManagerMemory) DeviceGet(u *uuid.UUID) (*x509.Certificate, *x509.Certificate, string, error) {
	if u == nil {
		return nil, nil, "", fmt.Errorf("empty UUID")
	}
	if _, ok := d.devices[*u]; ok {
		return d.devices[*u].cert, d.devices[*u].onboard, d.devices[*u].serial, nil
	}
	return nil, nil, "", &NotFoundError{err: fmt.Sprintf("device uuid not found: %s", u.String())}
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManagerMemory) DeviceList() ([]*uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(d.devices))
	for u := range d.devices {
		ids = append(ids, u)
	}
	pids := make([]*uuid.UUID, 0, len(ids))
	for i := range ids {
		pids = append(pids, &ids[i])
	}
	return pids, nil
}

// DeviceRegister register a new device cert
func (d *DeviceManagerMemory) DeviceRegister(cert, onboard *x509.Certificate, serial string) (*uuid.UUID, error) {
	// first check if it already exists - this also checks for nil cert
	u, err := d.DeviceCheckCert(cert)
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
	if d.devices == nil {
		d.devices = make(map[uuid.UUID]deviceStorage)
	}
	d.devices[unew] = deviceStorage{
		onboard: onboard,
		serial:  serial,
		config:  createBaseConfig(unew),
	}
	return &unew, nil
}

// OnboardRegister register a new onboard certificate and its serials or update an existing one
func (d *DeviceManagerMemory) OnboardRegister(cert *x509.Certificate, serial []string) error {
	if cert == nil {
		return fmt.Errorf("empty nil certificate")
	}
	if d.onboardCerts == nil {
		d.onboardCerts = map[string]map[string]bool{}
	}
	certStr := string(cert.Raw)
	serialList := map[string]bool{}
	for _, s := range serial {
		serialList[s] = true
	}
	d.onboardCerts[certStr] = serialList

	return nil
}

// WriteInfo write an info message
func (d *DeviceManagerMemory) WriteInfo(m *info.ZInfoMsg) error {
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
	d.devices[u] = dev
	return nil
}

// WriteLogs write a message of logs
func (d *DeviceManagerMemory) WriteLogs(m *logs.LogBundle) error {
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
	d.devices[u] = dev
	return nil
}

// WriteMetrics write a metrics message
func (d *DeviceManagerMemory) WriteMetrics(m *metrics.ZMetricMsg) error {
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
	d.devices[u] = dev
	return nil
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManagerMemory) GetConfig(u uuid.UUID) (*config.EdgeDevConfig, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.config, nil
}

// GetConfigResponse retrieve the config for a particular device
func (d *DeviceManagerMemory) GetConfigResponse(u uuid.UUID) (*config.ConfigResponse, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}

	response := &config.ConfigResponse{}

	h := sha256.New()
	computeConfigElementSha(h, dev.config)
	configHash := h.Sum(nil)

	response.Config = dev.config
	response.ConfigHash = base64.URLEncoding.EncodeToString(configHash)
	return response, nil
}

// SetConfig set the config for a particular device
func (d *DeviceManagerMemory) SetConfig(u uuid.UUID, m *config.EdgeDevConfig) error {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if m == nil {
		return fmt.Errorf("empty configuration")
	}
	// check for UUID mismatch
	if m.Id == nil || m.Id.Uuid != u.String() {
		return fmt.Errorf("mismatched UUID")
	}
	dev.config = m
	return nil
}

// checkValidOnboardSerial see if a particular certificate+serial combinaton is valid
// does **not** check if it has been used
func (d *DeviceManagerMemory) checkValidOnboardSerial(cert *x509.Certificate, serial string) error {
	certStr := string(cert.Raw)
	if c, ok := d.onboardCerts[certStr]; ok {
		// accept the specific serial or the wildcard
		if _, ok := c[serial]; ok {
			return nil
		}
		if _, ok := c["*"]; ok {
			return nil
		}
		return &InvalidSerialError{err: fmt.Sprintf("unknown serial: %s", serial)}
	}
	return &InvalidCertError{err: "unknown onboarding certificate"}
}

// getOnboardSerialDevice see if a particular certificate+serial combinaton has been used and get its device uuid
func (d *DeviceManagerMemory) getOnboardSerialDevice(cert *x509.Certificate, serial string) *uuid.UUID {
	certStr := string(cert.Raw)
	for uid, dev := range d.devices {
		dCertStr := string(dev.onboard.Raw)
		if dCertStr == certStr && serial == dev.serial {
			return &uid
		}
	}
	return nil
}

// GetLogsReader get the logs for a given uuid
func (d *DeviceManagerMemory) GetLogsReader(u uuid.UUID) (io.Reader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	r := &LogsReader{
		Msgs: dev.logs,
	}
	return r, nil
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManagerMemory) GetInfoReader(u uuid.UUID) (io.Reader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	r := &InfoReader{
		Msgs: dev.info,
	}
	return r, nil
}
