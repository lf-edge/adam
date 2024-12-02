// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/adam/pkg/util"
	ax "github.com/lf-edge/adam/pkg/x509"
	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

const (
	// DeviceCertFilename the location in the device-specific directory that contains the device certificate
	DeviceCertFilename = "device-certificate.pem"
	// DeviceOnboardFilename the location in the device-specific directory that contains the onboarding certificate used
	DeviceOnboardFilename     = "onboard-certificate.pem"
	deviceConfigFilename      = "config.json"
	deviceAttestCertsFilename = "certs.json"
	deviceStorageKeysFilename = "storage-keys.json"
	deviceSerialFilename      = "serial.txt"
	onboardCertFilename       = "cert.pem"
	onboardCertSerials        = "onboard-serials.txt"
	deviceOptionsFilename     = "options.json"
	globalOptionsFilename     = "global-options.json"
	logDir                    = "logs"
	metricsDir                = "metrics"
	infoDir                   = "info"
	deviceDir                 = "device"
	onboardDir                = "onboard"
	requestsDir               = "requests"
	flowMessageDir            = "flow_message"
	MB                        = common.MB
	maxLogSizeFile            = 100 * MB
	maxInfoSizeFile           = 100 * MB
	maxMetricSizeFile         = 100 * MB
	maxRequestsSizeFile       = 100 * MB
	maxAppLogsSizeFile        = 100 * MB
	maxFlowMessageSizeFile    = 100 * MB
	fileSplit                 = 10
)

type ManagedFile struct {
	dir         string
	file        *os.File
	maxSize     int64
	currentSize int64
	totalSize   int64
	dirReader   *DirReader
}

func (m *ManagedFile) Get(index int) ([]byte, error) {
	return nil, errors.New("unsupported")
}

func (m *ManagedFile) Write(b []byte) (int, error) {
	if m.file == nil {
		f, err := openTimestampFile(m.dir)
		if err != nil {
			return 0, fmt.Errorf("failed to open file: %v", err)
		}
		m.file = f
	}
	written, err := m.file.Write(b)
	if err != nil {
		return 0, fmt.Errorf("failed to write log: %v", err)
	}
	m.currentSize += int64(written)
	m.totalSize += int64(written)

	// do we need to open a new file?
	if m.currentSize > m.maxSize/fileSplit {
		m.file.Close()
		f, err := openTimestampFile(m.dir)
		if err != nil {
			return 0, fmt.Errorf("failed top open file: %v", err)
		}
		// use the new log file pointer and reset the size
		m.file = f
		m.currentSize = 0
	}

	if m.totalSize > m.maxSize {
		// get all of the files from the directory
		fi, err := os.ReadDir(m.dir)
		if err != nil {
			return written, fmt.Errorf("could not read directory %s: %v", m.dir, err)
		}
		// sort the file names
		sort.Slice(fi, func(i int, j int) bool {
			return fi[i].Name() < fi[j].Name()
		})
		for _, f := range fi {
			if m.totalSize < m.maxSize {
				break
			}
			filename := path.Join(m.dir, f.Name())
			fileInfo, err := os.Stat(filename)
			if err != nil {
				return written, fmt.Errorf("could not get file info for %s: %v", filename, err)
			}
			size := fileInfo.Size()
			if err := os.Remove(filename); err != nil {
				return written, fmt.Errorf("failed to remove %s: %v", filename, err)
			}
			m.totalSize -= size
		}
	}

	return written, nil
}

func (m *ManagedFile) Reader() (common.ChunkReader, error) {
	r := &DirReader{
		Path: m.dir,
	}
	return r, nil
}

// DeviceManager implementation of DeviceManager interface with a directory as the backing store
type DeviceManager struct {
	databasePath string
	cacheTimeout int
	lastUpdate   time.Time
	// thse are for caching only
	onboardCerts            map[string]map[string]bool
	deviceCerts             map[string]uuid.UUID
	devices                 map[uuid.UUID]common.DeviceStorage
	maxLogSize              int
	maxInfoSize             int
	maxMetricSize           int
	maxRequestsSize         int
	maxFlowMessageSize      int
	maxAppLogsSize          int
	currentLogFile          *os.File
	currentInfoFile         *os.File
	currentMetricFile       *os.File
	currentRequestsFile     *os.File
	currentLogFileSize      int
	currentInfoFileSize     int
	currentMetricFileSize   int
	currentRequestsFileSize int
}

// Name return name
func (d *DeviceManager) Name() string {
	return "file"
}

// Database return database path
func (d *DeviceManager) Database() string {
	return d.databasePath
}

// MaxLogSize return the default maximum log size in bytes for this device manager
func (d *DeviceManager) MaxLogSize() int {
	return maxLogSizeFile
}

// MaxInfoSize return the default maximum info size in bytes for this device manager
func (d *DeviceManager) MaxInfoSize() int {
	return maxInfoSizeFile
}

// MaxMetricSize return the maximum metrics size in bytes for this device manager
func (d *DeviceManager) MaxMetricSize() int {
	return maxMetricSizeFile
}

// MaxRequestsSize return the maximum request logs size in bytes for this device manager
func (d *DeviceManager) MaxRequestsSize() int {
	return maxRequestsSizeFile
}

// MaxAppLogsSize return the maximum app logs size in bytes for this device manager
func (d *DeviceManager) MaxAppLogsSize() int {
	return maxAppLogsSizeFile
}

// MaxFlowMessageSize return the maximum FlowMessage logs size in bytes for this device manager
func (d *DeviceManager) MaxFlowMessageSize() int {
	return maxFlowMessageSizeFile
}

// Init check if a URL is valid and initialize
func (d *DeviceManager) Init(s string, sizes common.MaxSizes) (bool, error) {
	// parse the URL
	// we accept the following:
	// - scheme = file
	// - invalid URL (everything is path)
	URL, err := url.Parse(s)
	if err != nil {
		return false, err
	}
	if URL.Scheme != "file" && URL.Scheme != "" {
		return false, nil
	}
	fi, err := os.Stat(s)
	if err == nil && !fi.IsDir() {
		return false, fmt.Errorf("database path %s exists and is not a directory", s)
	}
	// we use MkdirAll, since we are willing to continue if the directory already exists; we only error if we cannot make it
	err = os.MkdirAll(s, 0755)
	if err != nil {
		return false, fmt.Errorf("could not create database path %s: %v", s, err)
	}
	d.databasePath = s

	// ensure everything exists
	err = d.initializeDB()
	if err != nil {
		return false, err
	}

	if sizes.MaxLogSize == 0 {
		d.maxLogSize = maxLogSizeFile
	} else {
		d.maxLogSize = sizes.MaxLogSize
	}
	if sizes.MaxInfoSize == 0 {
		d.maxInfoSize = maxInfoSizeFile
	} else {
		d.maxInfoSize = sizes.MaxInfoSize
	}
	if sizes.MaxMetricSize == 0 {
		d.maxMetricSize = maxMetricSizeFile
	} else {
		d.maxMetricSize = sizes.MaxMetricSize
	}
	if sizes.MaxRequestsSize == 0 {
		d.maxRequestsSize = maxRequestsSizeFile
	} else {
		d.maxRequestsSize = sizes.MaxRequestsSize
	}
	if sizes.MaxAppLogsSize == 0 {
		d.maxAppLogsSize = maxAppLogsSizeFile
	} else {
		d.maxAppLogsSize = sizes.MaxAppLogsSize
	}
	if sizes.MaxFlowMessageSize == 0 {
		d.maxFlowMessageSize = maxFlowMessageSizeFile
	} else {
		d.maxFlowMessageSize = sizes.MaxFlowMessageSize
	}

	return true, nil
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *DeviceManager) SetCacheTimeout(timeout int) {
	d.cacheTimeout = timeout
}

// OnboardCheck see if a particular certificate and serial combination is valid
func (d *DeviceManager) OnboardCheck(cert *x509.Certificate, serial string) error {
	// do not accept a nil certificate
	if cert == nil {
		return fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	if err := d.checkValidOnboardSerial(cert, serial); err != nil {
		return err
	}
	if d.getOnboardSerialDevice(cert, serial) != nil {
		return &common.UsedSerialError{Err: fmt.Sprintf("serial already used for onboarding certificate: %s", serial)}
	}
	return nil
}

// OnboardGet get the onboard cert and its serials based on Common Name
func (d *DeviceManager) OnboardGet(cn string) (*x509.Certificate, []string, error) {
	if cn == "" {
		return nil, nil, fmt.Errorf("empty cn")
	}
	// easiest to just check the filesystem
	onboardDir := d.getOnboardPath(cn)
	// does it exist?
	found, err := exists(onboardDir)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading onboard directory: %v", err)
	}
	if !found {
		return nil, nil, &common.NotFoundError{Err: fmt.Sprintf("onboard directory not found %s", onboardDir)}
	}

	// get the certificate and serials
	certPath := path.Join(onboardDir, onboardCertFilename)
	cert, err := ax.ReadCert(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading onboard certificate at %s: %v", certPath, err)
	}
	serialPath := path.Join(onboardDir, onboardCertSerials)
	serial, err := os.ReadFile(serialPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading onboard serials at %s: %v", serialPath, err)
	}
	// done
	return cert, strings.Fields(string(serial)), nil
}

// OnboardList list all of the known Common Names for onboard
func (d *DeviceManager) OnboardList() ([]string, error) {
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	cns := make([]string, 0)
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

// OnboardRemove remove an onboard certificate based on Common Name
func (d *DeviceManager) OnboardRemove(cn string) error {
	_, _, err := d.OnboardGet(cn)
	if err != nil {
		return err
	}
	onboardPath := d.getOnboardPath(cn)
	// remove the directory
	err = os.RemoveAll(onboardPath)
	if err != nil {
		return fmt.Errorf("unable to remove the onboard directory: %v", err)
	}
	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	return nil
}

// OnboardClear remove all onboarding certs
func (d *DeviceManager) OnboardClear() error {
	// remove the directory and clear the cache
	onboardPath := path.Join(d.databasePath, onboardDir)
	candidates, err := os.ReadDir(onboardPath)
	if err != nil {
		return fmt.Errorf("unable to read onboarding certificates at %s: %v", onboardPath, err)
	}
	// remove each directory
	for _, fi := range candidates {
		// we only are interested in directories
		if !fi.IsDir() {
			continue
		}
		name := fi.Name()
		f := path.Join(onboardPath, name)
		err = os.RemoveAll(f)
		if err != nil {
			return fmt.Errorf("unable to remove the onboard directory: %v", err)
		}
	}
	d.onboardCerts = map[string]map[string]bool{}
	return nil
}

// DeviceCheckCert see if a particular certificate is a valid registered device certificate
func (d *DeviceManager) DeviceCheckCert(cert *x509.Certificate) (*uuid.UUID, error) {
	if cert == nil {
		return nil, fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	if u, ok := d.deviceCerts[string(cert.Raw)]; ok {
		return &u, nil
	}
	return nil, nil
}

// DeviceCheckCertHash see if a particular certificate hash is a valid registered device certificate
func (d *DeviceManager) DeviceCheckCertHash(hash []byte) (*uuid.UUID, error) {
	if hash == nil {
		return nil, fmt.Errorf("invalid empty hash")
	}
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Redis: %v", err)
	}
	for k, u := range d.deviceCerts {
		s := sha256.Sum256([]byte(k))
		if bytes.Equal(hash, s[:]) {
			return &u, nil
		}
	}
	return nil, nil
}

// DeviceRemove remove a device
func (d *DeviceManager) DeviceRemove(u *uuid.UUID) error {
	_, _, _, err := d.DeviceGet(u)
	if err != nil {
		return err
	}
	// remove the directory
	devicePath := d.getDevicePath(*u)
	err = os.RemoveAll(devicePath)
	if err != nil {
		return fmt.Errorf("unable to remove the device directory: %v", err)
	}
	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	return nil
}

// DeviceClear remove all devices
func (d *DeviceManager) DeviceClear() error {
	// remove the directory and clear the cache
	devicePath := path.Join(d.databasePath, deviceDir)
	candidates, err := os.ReadDir(devicePath)
	if err != nil {
		return fmt.Errorf("unable to read device certificates at %s: %v", devicePath, err)
	}
	// remove each directory
	for _, fi := range candidates {
		// we only are interested in directories
		if !fi.IsDir() {
			continue
		}
		name := fi.Name()
		f := path.Join(devicePath, name)
		err = os.RemoveAll(f)
		if err != nil {
			return fmt.Errorf("unable to remove the device directory: %v", err)
		}
	}
	d.deviceCerts = map[string]uuid.UUID{}
	d.devices = map[uuid.UUID]common.DeviceStorage{}
	return nil
}

// DeviceGet get an individual device by UUID
func (d *DeviceManager) DeviceGet(u *uuid.UUID) (*x509.Certificate, *x509.Certificate, string, error) {
	if u == nil {
		return nil, nil, "", fmt.Errorf("empty UUID")
	}
	// easiest to just check the filesystem
	devicePath := d.getDevicePath(*u)
	// does it exist?
	found, err := exists(devicePath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error reading device directory: %v", err)
	}
	if !found {
		return nil, nil, "", &common.NotFoundError{Err: fmt.Sprintf("device directory %s not found", onboardDir)}
	}
	// get the certificate, onboard certificate, serial
	certPath := path.Join(devicePath, DeviceCertFilename)
	cert, err := ax.ReadCert(certPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error reading device certificate at %s: %v", certPath, err)
	}

	certPath = path.Join(devicePath, DeviceOnboardFilename)
	onboard, err := ax.ReadCert(certPath)
	// we can accept not reading the onboard cert
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, "", fmt.Errorf("error reading onboard certificate at %s: %v", certPath, err)
	}
	serialPath := path.Join(devicePath, deviceSerialFilename)
	serial, err := os.ReadFile(serialPath)
	// we can accept not reading the onboard serial
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, "", fmt.Errorf("error reading device serial at %s: %v", serialPath, err)
	}
	// done
	return cert, onboard, string(serial), nil
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManager) DeviceList() ([]*uuid.UUID, error) {
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
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

// initDevice initialize all structures for one device
func (d *DeviceManager) initDevice(u uuid.UUID) error {
	// create filesystem tree and subdirs for the new device
	devicePath := d.getDevicePath(u)
	err := os.MkdirAll(devicePath, 0755)
	if err != nil {
		return fmt.Errorf("error creating new device tree %s: %v", devicePath, err)
	}

	// create the necessary directories for data uploads
	for _, p := range []string{logDir, metricsDir, infoDir, requestsDir} {
		cur := path.Join(devicePath, p)
		err = os.MkdirAll(cur, 0755)
		if err != nil {
			return fmt.Errorf("error creating new device sub-path %s: %v", cur, err)
		}
	}

	// save new one to cache - just the serial and onboard; the rest is on disk
	if d.deviceCerts == nil {
		d.deviceCerts = map[string]uuid.UUID{}
	}

	if d.devices == nil {
		d.devices = map[uuid.UUID]common.DeviceStorage{}
	}
	if d.maxLogSize == 0 {
		d.maxLogSize = maxLogSizeFile
	}
	if d.maxInfoSize == 0 {
		d.maxInfoSize = maxInfoSizeFile
	}
	if d.maxMetricSize == 0 {
		d.maxMetricSize = maxMetricSizeFile
	}

	d.devices[u] = common.DeviceStorage{
		Logs: &ManagedFile{
			dir:     path.Join(devicePath, logDir),
			maxSize: int64(d.maxLogSize),
		},
		Info: &ManagedFile{
			dir:     path.Join(devicePath, infoDir),
			maxSize: int64(d.maxInfoSize),
		},
		Metrics: &ManagedFile{
			dir:     path.Join(devicePath, metricsDir),
			maxSize: int64(d.maxMetricSize),
		},
		Requests: &ManagedFile{
			dir:     path.Join(devicePath, requestsDir),
			maxSize: int64(d.maxRequestsSize),
		},
		FlowMessage: &ManagedFile{
			dir:     path.Join(devicePath, flowMessageDir),
			maxSize: int64(d.maxFlowMessageSize),
		},
		AppLogs: map[uuid.UUID]common.BigData{},
	}

	return nil
}

// DeviceRegister register a new device cert
func (d *DeviceManager) DeviceRegister(unew uuid.UUID, cert, onboard *x509.Certificate, serial string, conf []byte) error {
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	// check if it already exists - this also checks for nil cert
	u, err := d.DeviceCheckCert(cert)
	if err != nil {
		return err
	}
	// if we found a uuid, then it already exists
	if u != nil {
		return fmt.Errorf("device already registered")
	}

	// create filesystem tree and subdirs for the new device
	if err := d.initDevice(unew); err != nil {
		return fmt.Errorf("error initializing device: %v", err)
	}
	devicePath := d.getDevicePath(unew)

	// save the device certificate
	certPath := path.Join(devicePath, DeviceCertFilename)
	err = ax.WriteCert(cert.Raw, certPath, true)
	if err != nil {
		return fmt.Errorf("error saving device certificate to %s: %v", certPath, err)
	}

	// save the onboard certificate and serial, if provided
	certPath = path.Join(devicePath, DeviceOnboardFilename)
	if onboard != nil {
		err = ax.WriteCert(onboard.Raw, certPath, true)
		if err != nil {
			return fmt.Errorf("error saving device onboard certificate to %s: %v", certPath, err)
		}
	}
	if serial != "" {
		serialPath := path.Join(devicePath, deviceSerialFilename)
		err = os.WriteFile(serialPath, []byte(serial), 0644)
		if err != nil {
			return fmt.Errorf("error saving device serial to %s: %v", serialPath, err)
		}
	}
	// save the base configuration
	err = d.writeJSONFile(unew, "", deviceConfigFilename, conf)
	if err != nil {
		return fmt.Errorf("error saving device config to %s: %v", deviceConfigFilename, err)
	}

	// save new one to cache - just the serial and onboard; the rest is on disk
	d.deviceCerts[string(cert.Raw)] = unew

	// this already was initialized in initDevice()
	ds := d.devices[unew]
	ds.Serial = serial
	ds.Onboard = onboard

	return nil
}

// OnboardRegister register an onboard cert and update its serials
func (d *DeviceManager) OnboardRegister(cert *x509.Certificate, serial []string) error {
	if cert == nil {
		return fmt.Errorf("empty nil certificate")
	}
	certStr := string(cert.Raw)
	cn := cert.Subject.CommonName

	// ensure everything exists
	err := d.initializeDB()
	if err != nil {
		return err
	}
	// update the filesystem
	// onboard cert file
	onboardPath := path.Join(d.databasePath, onboardDir, common.GetOnboardCertName(cn))
	// need the directory
	err = os.MkdirAll(onboardPath, 0755)
	if err != nil {
		return fmt.Errorf("unable to create onboard certificate path path %s: %v", onboardPath, err)
	}
	f := path.Join(onboardPath, onboardCertFilename)
	// fix contents!!
	err = ax.WriteCert(cert.Raw, f, true)
	if err != nil {
		return fmt.Errorf("unable to write onboard cert file %s: %v", f, err)
	}
	// serials file
	f = path.Join(onboardPath, onboardCertSerials)
	err = os.WriteFile(f, []byte(strings.Join(serial, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("unable to write onboard serials file %s: %v", f, err)
	}

	// update the cache
	if d.onboardCerts == nil {
		d.onboardCerts = map[string]map[string]bool{}
	}
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
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}
	dev := d.devices[u]
	return dev.AddInfo(b)
}

// WriteLogs write a message of logs
func (d *DeviceManager) WriteLogs(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}
	dev := d.devices[u]
	return dev.AddLogs(b)
}

// appExists return if an app has been created
func (d *DeviceManager) appExists(u, instanceID uuid.UUID) bool {
	_, err := os.Stat(d.getAppPath(u, instanceID))
	if err != nil {
		return false
	}
	if _, ok := d.devices[u]; !ok {
		return false
	}
	return true
}

// WriteAppInstanceLogs write a message of AppInstanceLogBundle
func (d *DeviceManager) WriteAppInstanceLogs(instanceID uuid.UUID, deviceID uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) == 0 {
		return nil
	}
	// get the uuid
	// check that the device actually exists
	if !d.deviceExists(deviceID) {
		return fmt.Errorf("unregistered device UUID: %s", deviceID)
	}
	if !d.appExists(deviceID, instanceID) {
		d.devices[deviceID].AppLogs[instanceID] = &ManagedFile{
			dir:     d.getAppPath(deviceID, instanceID),
			maxSize: int64(d.maxAppLogsSize),
		}
	}
	dev := d.devices[deviceID]
	return dev.AddAppLog(instanceID, b)
}

// WriteMetrics write a metrics message
func (d *DeviceManager) WriteMetrics(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}
	dev := d.devices[u]
	return dev.AddMetrics(b)
}

// WriteCerts write an attestation certs information
func (d *DeviceManager) WriteCerts(u uuid.UUID, b []byte) error {
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	// save the base configuration
	err = d.writeJSONFile(u, "", deviceAttestCertsFilename, b)
	if err != nil {
		return fmt.Errorf("error saving attestation to %s: %v", deviceAttestCertsFilename, err)
	}
	return nil
}

// GetCerts retrieve the attest certs for a particular device
func (d *DeviceManager) GetCerts(u uuid.UUID) ([]byte, error) {
	// read the config from disk
	fullAttestPath := path.Join(d.getDevicePath(u), deviceAttestCertsFilename)
	b, err := os.ReadFile(fullAttestPath)
	if err != nil {
		return nil, fmt.Errorf("could not read certificates from %s: %v", fullAttestPath, err)
	}

	return b, nil
}

// WriteStorageKeys write storage keys information
func (d *DeviceManager) WriteStorageKeys(u uuid.UUID, b []byte) error {
	// refresh cache from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh cache from filesystem: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	err = d.writeJSONFile(u, "", deviceStorageKeysFilename, b)
	if err != nil {
		return fmt.Errorf("error saving storage keys to %s: %v", deviceStorageKeysFilename, err)
	}
	return nil
}

// GetStorageKeys retrieve storage keys for a particular device
func (d *DeviceManager) GetStorageKeys(u uuid.UUID) ([]byte, error) {
	// read storage keys from disk
	fullStorageKeysPath := path.Join(d.getDevicePath(u), deviceStorageKeysFilename)
	b, err := os.ReadFile(fullStorageKeysPath)
	if err != nil {
		return nil, fmt.Errorf("could not read storage keys from %s: %v", fullStorageKeysPath, err)
	}

	return b, nil
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManager) GetConfig(u uuid.UUID) ([]byte, error) {
	// read the config from disk
	fullConfigPath := path.Join(d.getDevicePath(u), deviceConfigFilename)
	b, err := os.ReadFile(fullConfigPath)
	switch {
	case err != nil && os.IsNotExist(err):
		// create the base file if it does not exist
		b = common.CreateBaseConfig(u)
		err = d.writeJSONFile(u, "", deviceConfigFilename, b)
		if err != nil {
			return nil, fmt.Errorf("error saving device config to %s: %v", deviceConfigFilename, err)
		}
	case err != nil:
		return nil, fmt.Errorf("could not read config from %s: %v", fullConfigPath, err)
	}

	return b, nil
}

// SetConfig set the config for a particular device
func (d *DeviceManager) SetConfig(u uuid.UUID, b []byte) error {
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	// save the base configuration
	err = d.writeJSONFile(u, "", deviceConfigFilename, b)
	if err != nil {
		return fmt.Errorf("error saving device config to %s: %v", deviceConfigFilename, err)
	}
	return nil
}

// refreshCache refresh cache from disk
func (d *DeviceManager) refreshCache() error {
	// is it time to update the cache again?
	now := time.Now()
	if now.Sub(d.lastUpdate).Seconds() < float64(d.cacheTimeout) {
		return nil
	}

	// ensure everything exists
	err := d.initializeDB()
	if err != nil {
		return err
	}

	// create new vars to hold while we load
	d.onboardCerts = make(map[string]map[string]bool)
	d.deviceCerts = make(map[string]uuid.UUID)
	d.devices = make(map[uuid.UUID]common.DeviceStorage)

	// scan the onboard path for all files which end in ".pem" and load them
	onboardPath := path.Join(d.databasePath, onboardDir)
	candidates, err := os.ReadDir(onboardPath)
	if err != nil {
		return fmt.Errorf("unable to read onboarding certificates at %s: %v", onboardPath, err)
	}
	// check each file to make sure it is an onboarding cert
	for _, fi := range candidates {
		// we only are interested in directories
		if !fi.IsDir() {
			continue
		}
		name := fi.Name()
		f := path.Join(onboardPath, name, onboardCertFilename)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		if err != nil {
			continue
		}

		// read the file
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read onboard certificate file %s: %v", f, err)
		}
		// convert into a certificate
		certPem, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to onboard certificate: %v", f, err)
		}
		certStr := string(cert.Raw)
		d.onboardCerts[certStr] = make(map[string]bool)

		// get the serial list
		f = path.Join(onboardPath, name, onboardCertSerials)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		//   we already have the onboard cert saved, so no serials to add
		if err != nil {
			continue
		}
		b, err = os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read onboard serial file %s: %v", f, err)
		}
		// convert the []byte to string, split and save
		for _, serial := range strings.Fields(string(b)) {
			d.onboardCerts[certStr][serial] = true
		}
	}

	// scan the device path for each dir which is the UUID
	//   and in each one, if a cert exists with the appropriate name, load it
	devicePath := path.Join(d.databasePath, deviceDir)
	candidates, err = os.ReadDir(devicePath)
	if err != nil {
		return fmt.Errorf("unable to read devices at %s: %v", devicePath, err)
	}
	// check each directory to see if it is a valid device directory
	for _, fi := range candidates {
		// we only are interested in directories
		if !fi.IsDir() {
			continue
		}
		name := fi.Name()
		// convert the path name to a UUID
		u, err := uuid.FromString(name)
		if err != nil {
			return fmt.Errorf("unable to convert device uuid from directory name %s: %v", name, err)
		}
		devicePath := d.getDevicePath(u)

		// load the device certificate
		f := path.Join(devicePath, DeviceCertFilename)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		if err != nil {
			continue
		}
		// read the file
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device certificate file %s: %v", f, err)
		}
		// convert into a certificate
		certPem, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to device certificate: %v", f, err)
		}
		certStr := string(cert.Raw)
		d.deviceCerts[certStr] = u
		if err := d.initDevice(u); err != nil {
			return fmt.Errorf("unable to initialize device structure for device %s: %v", u, err)
		}

		// load the device onboarding certificate and serial
		f = path.Join(devicePath, DeviceOnboardFilename)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		if err != nil {
			continue
		}
		// read the file
		b, err = os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device onboard certificate file %s: %v", f, err)
		}
		// convert into a certificate
		certPem, _ = pem.Decode(b)
		cert, err = x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to device onboard certificate: %v", f, err)
		}
		devItem := d.devices[u]
		devItem.Onboard = cert
		d.devices[u] = devItem
		// and the serial
		f = path.Join(devicePath, deviceSerialFilename)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		if err != nil {
			continue
		}
		// read the file
		b, err = os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device serial file %s: %v", f, err)
		}
		devItem = d.devices[u]
		devItem.Serial = string(b)
		d.devices[u] = devItem
	}

	// mark the time we updated
	d.lastUpdate = now
	return nil
}

// initialize dirs, in case they do not exist
func (d *DeviceManager) initializeDB() error {
	for _, p := range []string{deviceDir, onboardDir} {
		pdir := path.Join(d.databasePath, p)
		err := os.MkdirAll(pdir, 0755)
		if err != nil {
			return fmt.Errorf("unable to initialize database path %s: %v", pdir, err)
		}
	}
	return nil
}

// getDevicePath get the path for a given device
func (d *DeviceManager) getDevicePath(u uuid.UUID) string {
	return GetDevicePath(d.databasePath, u)
}

// getDevicePath get the path for a given device
func (d *DeviceManager) getAppPath(u, instanceID uuid.UUID) string {
	return filepath.Join(GetDevicePath(d.databasePath, u), instanceID.String())
}

// getOnboardPath get the path for a given onboard
func (d *DeviceManager) getOnboardPath(cn string) string {
	return path.Join(d.databasePath, onboardDir, cn)
}

func openTimestampFile(filename string) (*os.File, error) {
	// open a new one
	fullPath := path.Join(filename, time.Now().Format("2006-01-02T15:04:05.111"))
	return os.Create(fullPath)
}

// writeProtobufToJSONFile write a protobuf to a named file in the given directory
func (d *DeviceManager) writeProtobufToJSONFile(u uuid.UUID, dir, filename string, msg proto.Message) error {
	b, err := util.ProtobufToBytes(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	return d.writeJSONFile(u, dir, filename, b)
}

// writeJSONFile write json to a named file in the given directory
func (d *DeviceManager) writeJSONFile(u uuid.UUID, dir, filename string, b []byte) error {
	// if dir == "", then path.Join() automatically ignores it
	fullPath := path.Join(d.getDevicePath(u), dir, filename)
	f, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", fullPath, err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}
	// no need to f.Close() as it happens automatically
	return nil
}

// deviceExists return if a device has been created
func (d *DeviceManager) deviceExists(u uuid.UUID) bool {
	_, err := os.Stat(d.getDevicePath(u))
	if err != nil {
		return false
	}
	if _, ok := d.devices[u]; !ok {
		return false
	}
	return true
}

// checkValidOnboardSerial see if a particular certificate+serial combinaton is valid
// does **not** check if it has been used
func (d *DeviceManager) checkValidOnboardSerial(cert *x509.Certificate, serial string) error {
	if c, ok := d.onboardCerts[string(cert.Raw)]; ok {
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
		if dev.Onboard == nil {
			continue
		}
		dCertStr := string(dev.Onboard.Raw)
		if dCertStr == certStr && serial == dev.Serial {
			return &uid
		}
	}
	return nil
}

// GetDevicePath get the path for a given device
func GetDevicePath(databasePath string, u uuid.UUID) string {
	return path.Join(databasePath, deviceDir, u.String())
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// GetLogsReader get the logs for a given uuid
func (d *DeviceManager) GetLogsReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return d.devices[u].Logs.Reader()
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManager) GetInfoReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return d.devices[u].Info.Reader()
}

// GetRequestsReader get the requests for a given uuid
func (d *DeviceManager) GetRequestsReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return d.devices[u].Requests.Reader()
}

// WriteFlowMessage write FlowMessage
func (d *DeviceManager) WriteFlowMessage(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}
	dev := d.devices[u]
	return dev.AddFlowRecord(b)
}

// GetUUID get UuidResponse for device by uuid
func (d *DeviceManager) GetUUID(u uuid.UUID) ([]byte, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	ur := &eveuuid.UuidResponse{Uuid: u.String()}
	return proto.Marshal(ur)
}

func (d *DeviceManager) SetDeviceOptions(u uuid.UUID, b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("empty options")
	}
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}
	// save the device configuration
	err := d.writeJSONFile(u, "", deviceOptionsFilename, b)
	if err != nil {
		return fmt.Errorf("error saving options to %s: %v", deviceOptionsFilename, err)
	}
	return nil
}

func (d *DeviceManager) GetDeviceOptions(u uuid.UUID) ([]byte, error) {
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	// read options from disk
	fullOptionsPath := path.Join(d.getDevicePath(u), deviceOptionsFilename)
	b, err := os.ReadFile(fullOptionsPath)
	if err != nil {
		// if error another than not exists than return
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("could not read options from %s: %v", fullOptionsPath, err)
		}
		// if is not exists, try to create default options
		cfg := common.CreateBaseDeviceOptions(u)
		err = d.SetDeviceOptions(u, cfg)
		if err != nil {
			return nil, fmt.Errorf("cannot set default options for %s: %s", u, err)
		}
		return cfg, nil
	}
	return b, nil
}

func (d *DeviceManager) SetGlobalOptions(b []byte) error {
	return os.WriteFile(filepath.Join(d.databasePath, globalOptionsFilename), b, 0666)
}

func (d *DeviceManager) GetGlobalOptions() ([]byte, error) {
	return os.ReadFile(filepath.Join(d.databasePath, globalOptionsFilename))
}
