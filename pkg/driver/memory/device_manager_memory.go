// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
)

const (
	MB                    = common.MB
	maxLogSizeMemory      = 10 * MB
	maxInfoSizeMemory     = 10 * MB
	maxMetricSizeMemory   = 10 * MB
	maxRequestsSizeMemory = 10 * MB
)

// DeviceManager implementation of DeviceManager with an ephemeral memory backing store
type DeviceManager struct {
	onboardCerts    map[string]map[string]bool
	deviceCerts     map[string]uuid.UUID
	devices         map[uuid.UUID]common.DeviceStorage
	maxLogSize      int
	maxInfoSize     int
	maxMetricSize   int
	maxRequestsSize int
}

// Name return name
func (d *DeviceManager) Name() string {
	return "memory"
}

// Database return database path
func (d *DeviceManager) Database() string {
	return "memory"
}

// MaxLogSize return the default maximum log size in bytes for this device manager
func (d *DeviceManager) MaxLogSize() int {
	return maxLogSizeMemory
}

// MaxInfoSize return the maximum info size in bytes for this device manager
func (d *DeviceManager) MaxInfoSize() int {
	return maxInfoSizeMemory
}

// MaxMetricSize return the maximum metrics size in bytes for this device manager
func (d *DeviceManager) MaxMetricSize() int {
	return maxMetricSizeMemory
}

// MaxRequestsSize return the maximum request logs size in bytes for this device manager
func (d *DeviceManager) MaxRequestsSize() int {
	return maxRequestsSizeMemory
}

// Init initialize, valid only with a blank URL
func (d *DeviceManager) Init(s string, maxLogSize, maxInfoSize, maxMetricSize, maxRequestsSize int) (bool, error) {
	if s != "" {
		return false, nil
	}
	if maxLogSize == 0 {
		maxLogSize = maxLogSizeMemory
	}
	if maxInfoSize == 0 {
		maxInfoSize = maxInfoSizeMemory
	}
	if maxMetricSize == 0 {
		maxMetricSize = maxMetricSizeMemory
	}
	if maxRequestsSize == 0 {
		maxRequestsSize = maxRequestsSizeMemory
	}
	d.maxLogSize = maxLogSize
	d.maxInfoSize = maxInfoSize
	d.maxMetricSize = maxMetricSize
	d.maxRequestsSize = maxRequestsSize
	return true, nil
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *DeviceManager) SetCacheTimeout(timeout int) {
}

// OnboardCheck see if a particular certificate plus serial combinaton is valid
func (d *DeviceManager) OnboardCheck(cert *x509.Certificate, serial string) error {
	if cert == nil {
		return fmt.Errorf("invalid nil certificate")
	}
	if err := d.checkValidOnboardSerial(cert, serial); err != nil {
		return err
	}
	if d.getOnboardSerialDevice(cert, serial) != nil {
		return &common.UsedSerialError{Err: fmt.Sprintf("serial already used for onboarding certificate: %s", serial)}
	}
	return nil
}

// OnboardRemove remove an onboard certificate based on Common Name
func (d *DeviceManager) OnboardRemove(cn string) error {
	cert, _, err := d.OnboardGet(cn)
	if err != nil {
		return err
	}
	delete(d.onboardCerts, string(cert.Raw))
	return nil
}

// OnboardClear remove all onboarding certs
func (d *DeviceManager) OnboardClear() error {
	d.onboardCerts = map[string]map[string]bool{}
	return nil
}

// OnboardGet get the onboard certificate and serials based on Common Name
func (d *DeviceManager) OnboardGet(cn string) (*x509.Certificate, []string, error) {
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
	return nil, nil, &common.NotFoundError{Err: fmt.Sprintf("onboard cn not found: %s", cn)}
}

// OnboardList list all of the known Common Names for onboard
func (d *DeviceManager) OnboardList() ([]string, error) {
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
func (d *DeviceManager) DeviceCheckCert(cert *x509.Certificate) (*uuid.UUID, error) {
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
func (d *DeviceManager) DeviceRemove(u *uuid.UUID) error {
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
func (d *DeviceManager) DeviceClear() error {
	d.deviceCerts = make(map[string]uuid.UUID)
	d.devices = make(map[uuid.UUID]common.DeviceStorage)
	return nil
}

// DeviceGet get an individual device by UUID
func (d *DeviceManager) DeviceGet(u *uuid.UUID) (*x509.Certificate, *x509.Certificate, string, error) {
	if u == nil {
		return nil, nil, "", fmt.Errorf("empty UUID")
	}
	if _, ok := d.devices[*u]; ok {
		return d.devices[*u].Cert, d.devices[*u].Onboard, d.devices[*u].Serial, nil
	}
	return nil, nil, "", &common.NotFoundError{Err: fmt.Sprintf("device uuid not found: %s", u.String())}
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManager) DeviceList() ([]*uuid.UUID, error) {
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
func (d *DeviceManager) DeviceRegister(cert, onboard *x509.Certificate, serial string) (*uuid.UUID, error) {
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
		d.devices = make(map[uuid.UUID]common.DeviceStorage)
	}
	d.devices[unew] = common.DeviceStorage{
		Onboard: onboard,
		Serial:  serial,
		Config:  common.CreateBaseConfig(unew),
		Logs: &ByteSlice{
			maxSize: d.maxLogSize,
		},
		Info: &ByteSlice{
			maxSize: d.maxInfoSize,
		},
		Metrics: &ByteSlice{
			maxSize: d.maxMetricSize,
		},
	}
	return &unew, nil
}

// OnboardRegister register a new onboard certificate and its serials or update an existing one
func (d *DeviceManager) OnboardRegister(cert *x509.Certificate, serial []string) error {
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

// WriteRequest record a request
func (d *DeviceManager) WriteRequest(req common.ApiRequest) error {
	var emptyUUID uuid.UUID
	if uuid.Equal(req.UUID, emptyUUID) {
		return fmt.Errorf("no device given")
	}
	if dev, ok := d.devices[req.UUID]; ok {
		dev.AddRequest(&req)
		return nil
	}
	return fmt.Errorf("device not found: %s", req.UUID)
}

// WriteInfo write an info message
func (d *DeviceManager) WriteInfo(m *info.ZInfoMsg) error {
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
	dev.AddInfo(m)
	d.devices[u] = dev
	return nil
}

// WriteLogs write a message of logs
func (d *DeviceManager) WriteLogs(m *logs.LogBundle) error {
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
	// each slice in dev.logs is allowed up to `memoryLogSlicePart` of the total maxSize
	dev.AddLog(m)
	d.devices[u] = dev
	return nil
}

// WriteMetrics write a metrics message
func (d *DeviceManager) WriteMetrics(m *metrics.ZMetricMsg) error {
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
	dev.AddMetrics(m)
	d.devices[u] = dev
	return nil
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManager) GetConfig(u uuid.UUID) (*config.EdgeDevConfig, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Config, nil
}

// GetConfigResponse retrieve the config for a particular device
func (d *DeviceManager) GetConfigResponse(u uuid.UUID) (*config.ConfigResponse, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}

	response := &config.ConfigResponse{}

	h := sha256.New()
	common.ComputeConfigElementSha(h, dev.Config)
	configHash := h.Sum(nil)

	response.Config = dev.Config
	response.ConfigHash = base64.URLEncoding.EncodeToString(configHash)
	return response, nil
}

// SetConfig set the config for a particular device
func (d *DeviceManager) SetConfig(u uuid.UUID, m *config.EdgeDevConfig) error {
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
	dev.Config = m
	return nil
}

// checkValidOnboardSerial see if a particular certificate+serial combinaton is valid
// does **not** check if it has been used
func (d *DeviceManager) checkValidOnboardSerial(cert *x509.Certificate, serial string) error {
	certStr := string(cert.Raw)
	if c, ok := d.onboardCerts[certStr]; ok {
		// accept the specific serial or the wildcard
		if _, ok := c[serial]; ok {
			return nil
		}
		if _, ok := c["*"]; ok {
			return nil
		}
		return &common.InvalidSerialError{Err: fmt.Sprintf("unknown serial: %s", serial)}
	}
	return &common.InvalidCertError{Err: "unknown onboarding certificate"}
}

// getOnboardSerialDevice see if a particular certificate+serial combinaton has been used and get its device uuid
func (d *DeviceManager) getOnboardSerialDevice(cert *x509.Certificate, serial string) *uuid.UUID {
	certStr := string(cert.Raw)
	for uid, dev := range d.devices {
		dCertStr := string(dev.Onboard.Raw)
		if dCertStr == certStr && serial == dev.Serial {
			return &uid
		}
	}
	return nil
}

// GetLogsReader get the logs for a given uuid
func (d *DeviceManager) GetLogsReader(u uuid.UUID) (io.Reader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Logs, nil
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManager) GetInfoReader(u uuid.UUID) (io.Reader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Info, nil
}

// GetRequestsReader get the requests for a given uuid
func (d *DeviceManager) GetRequestsReader(u uuid.UUID) (io.Reader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Requests, nil
}
