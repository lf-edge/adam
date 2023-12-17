// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/lf-edge/adam/pkg/driver/common"
	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

const (
	MB                       = common.MB
	maxLogSizeMemory         = 10 * MB
	maxInfoSizeMemory        = 10 * MB
	maxMetricSizeMemory      = 10 * MB
	maxRequestsSizeMemory    = 10 * MB
	maxFlowMessageSizeMemory = 10 * MB
	maxAppLogsSizeMemory     = 10 * MB
)

// DeviceManager implementation of DeviceManager with an ephemeral memory backing store
type DeviceManager struct {
	onboardCerts       map[string]map[string]bool
	deviceCerts        map[string]uuid.UUID
	devices            map[uuid.UUID]common.DeviceStorage
	maxLogSize         int
	maxInfoSize        int
	maxMetricSize      int
	maxRequestsSize    int
	maxFlowMessageSize int
	maxAppLogsSize     int
	globalOptions      []byte
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

// MaxAppLogsSize return the maximum app logs size in bytes for this device manager
func (d *DeviceManager) MaxAppLogsSize() int {
	return maxAppLogsSizeMemory
}

// MaxFlowMessageSize return the maximum FlowMessage logs size in bytes for this device manager
func (d *DeviceManager) MaxFlowMessageSize() int {
	return maxFlowMessageSizeMemory
}

// Init initialize, valid only with a blank URL
func (d *DeviceManager) Init(s string, sizes common.MaxSizes) (bool, error) {
	if s != "" {
		return false, nil
	}

	if sizes.MaxLogSize == 0 {
		d.maxLogSize = maxLogSizeMemory
	} else {
		d.maxLogSize = sizes.MaxLogSize
	}
	if sizes.MaxInfoSize == 0 {
		d.maxInfoSize = maxInfoSizeMemory
	} else {
		d.maxInfoSize = sizes.MaxInfoSize
	}
	if sizes.MaxMetricSize == 0 {
		d.maxMetricSize = maxMetricSizeMemory
	} else {
		d.maxMetricSize = sizes.MaxMetricSize
	}
	if sizes.MaxRequestsSize == 0 {
		d.maxRequestsSize = maxRequestsSizeMemory
	} else {
		d.maxRequestsSize = sizes.MaxRequestsSize
	}
	if sizes.MaxAppLogsSize == 0 {
		d.maxAppLogsSize = maxAppLogsSizeMemory
	} else {
		d.maxAppLogsSize = sizes.MaxAppLogsSize
	}
	if sizes.MaxFlowMessageSize == 0 {
		d.maxFlowMessageSize = maxFlowMessageSizeMemory
	} else {
		d.maxFlowMessageSize = sizes.MaxFlowMessageSize
	}
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

// DeviceCheckCertHash see if a particular certificate hash is a valid registered device certificate
func (d *DeviceManager) DeviceCheckCertHash(hash []byte) (*uuid.UUID, error) {
	if hash == nil {
		return nil, fmt.Errorf("invalid empty hash")
	}
	for k, u := range d.deviceCerts {
		s := sha256.Sum256([]byte(k))
		if bytes.Equal(hash, s[:]) {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("cert hash not found")
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
func (d *DeviceManager) DeviceRegister(unew uuid.UUID, cert, onboard *x509.Certificate, serial string, conf []byte) error {
	// first check if it already exists - this also checks for nil cert
	u, err := d.DeviceCheckCert(cert)
	if err != nil {
		return err
	}
	// if we found a uuid, then it already exists
	if u != nil {
		return fmt.Errorf("device already registered")
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
		Config:  conf,
		Logs: &ByteSlice{
			maxSize: d.maxLogSize,
		},
		Info: &ByteSlice{
			maxSize: d.maxInfoSize,
		},
		Metrics: &ByteSlice{
			maxSize: d.maxMetricSize,
		},
		FlowMessage: &ByteSlice{
			maxSize: d.maxFlowMessageSize,
		},
		AppLogs: map[uuid.UUID]common.BigData{},
	}
	return nil
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
func (d *DeviceManager) WriteRequest(u uuid.UUID, b []byte) error {
	if dev, ok := d.devices[u]; ok {
		dev.AddRequest(b)
		return nil
	}
	return fmt.Errorf("device not found: %s", u)
}

// WriteInfo write an info message
func (d *DeviceManager) WriteInfo(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// now look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u)
	}
	// append the messages
	dev.AddInfo(b)
	d.devices[u] = dev
	return nil
}

// WriteLogs write a message of logs
func (d *DeviceManager) WriteLogs(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}

	// now look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u)
	}
	// append the messages
	// each slice in dev.logs is allowed up to `memoryLogSlicePart` of the total maxSize
	dev.AddLogs(b)
	d.devices[u] = dev
	return nil
}

// appExists return if an app has been created
func (d *DeviceManager) appExists(u, instanceID uuid.UUID) bool {
	if _, ok := d.devices[u]; !ok {
		return false
	}
	if _, ok := d.devices[u].AppLogs[instanceID]; !ok {
		return false
	}
	return true
}

// WriteAppInstanceLogs write a message of AppInstanceLogBundle
func (d *DeviceManager) WriteAppInstanceLogs(instanceID uuid.UUID, deviceID uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	dev, ok := d.devices[deviceID]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", deviceID)
	}
	if !d.appExists(deviceID, instanceID) {
		d.devices[deviceID].AppLogs[instanceID] = &ByteSlice{
			maxSize: d.maxAppLogsSize,
		}
	}
	return dev.AddAppLog(instanceID, b)
}

// WriteMetrics write a metrics message
func (d *DeviceManager) WriteMetrics(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// now look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u)
	}
	// append the messages
	dev.AddMetrics(b)
	d.devices[u] = dev
	return nil
}

// WriteCerts write an attestation certs information
func (d *DeviceManager) WriteCerts(u uuid.UUID, b []byte) error {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	dev.AttestCerts = b
	return nil
}

// GetCerts retrieve the attest certs for a particular device
func (d *DeviceManager) GetCerts(u uuid.UUID) ([]byte, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.AttestCerts, nil
}

// WriteStorageKeys write storage keys information
func (d *DeviceManager) WriteStorageKeys(u uuid.UUID, b []byte) error {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	dev.StorageKeys = b
	return nil
}

// GetStorageKeys retrieve storage keys for a particular device
func (d *DeviceManager) GetStorageKeys(u uuid.UUID) ([]byte, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.StorageKeys, nil
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManager) GetConfig(u uuid.UUID) ([]byte, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Config, nil
}

// SetConfig set the config for a particular device
func (d *DeviceManager) SetConfig(u uuid.UUID, b []byte) error {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	dev.Config = b
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
func (d *DeviceManager) GetLogsReader(u uuid.UUID) (common.ChunkReader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Logs.Reader()
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManager) GetInfoReader(u uuid.UUID) (common.ChunkReader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Info.Reader()
}

// GetRequestsReader get the requests for a given uuid
func (d *DeviceManager) GetRequestsReader(u uuid.UUID) (common.ChunkReader, error) {
	// look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	return dev.Requests.Reader()
}

// WriteFlowMessage write FlowMessage
func (d *DeviceManager) WriteFlowMessage(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// now look up the device by uuid
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u)
	}
	d.devices[u] = dev
	// append the messages
	return dev.AddFlowRecord(b)
}

// GetUUID get UuidResponse for device by uuid
func (d *DeviceManager) GetUUID(u uuid.UUID) ([]byte, error) {
	// check that the device actually exists
	_, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	ur := &eveuuid.UuidResponse{Uuid: u.String()}
	return proto.Marshal(ur)
}

func (d *DeviceManager) SetDeviceOptions(u uuid.UUID, b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("empty options")
	}
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("no device UUID %s", u)
	}
	dev.Options = b
	return nil
}

func (d *DeviceManager) GetDeviceOptions(u uuid.UUID) ([]byte, error) {
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("no device UUID %s", u)
	}
	if dev.Options == nil {
		cfg := common.CreateBaseDeviceOptions(u)
		err := d.SetDeviceOptions(u, cfg)
		if err != nil {
			return nil, fmt.Errorf("cannot set default options for %s: %s", u, err)
		}
	}
	return dev.Options, nil
}

func (d *DeviceManager) SetGlobalOptions(b []byte) error {
	d.globalOptions = b
	return nil
}

func (d *DeviceManager) GetGlobalOptions() ([]byte, error) {
	if d.globalOptions == nil {
		err := d.SetGlobalOptions(common.CreateBaseGlobalOptions())
		if err != nil {
			return nil, err
		}
	}
	return d.globalOptions, nil
}
