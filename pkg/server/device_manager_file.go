package server

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
	ax "github.com/zededa/adam/pkg/x509"
)

const (
	// DeviceCertFilename the location in the device-specific directory that contains the device certificate
	DeviceCertFilename = "device-certificate.pem"
	// DeviceOnboardFilename the location in the device-specific directory that contains the onboarding certificate used
	DeviceOnboardFilename = "onboard-certificate.pem"
	deviceConfigFilename  = "config.json"
	deviceSerialFilename  = "serial.txt"
	onboardCertFilename   = "cert.pem"
	onboardCertSerials    = "onboard-serials.txt"
	logDir                = "logs"
	metricsDir            = "metrics"
	infoDir               = "info"
	deviceDir             = "device"
	onboardDir            = "onboard"
)

// DeviceManagerFile implementation of DeviceManager interface with a directory as the backing store
type DeviceManagerFile struct {
	databasePath string
	cacheTimeout int
	lastUpdate   time.Time
	// thse are for caching only
	onboardCerts map[string]map[string]bool
	deviceCerts  map[string]uuid.UUID
	devices      map[uuid.UUID]deviceStorage
}

// Name return name
func (d *DeviceManagerFile) Name() string {
	return "file"
}

// Init check if a URL is valid and initialize
func (d *DeviceManagerFile) Init(s string) (bool, error) {
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

	return true, nil
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *DeviceManagerFile) SetCacheTimeout(timeout int) {
	d.cacheTimeout = timeout
}

// OnboardCheck see if a particular certificate and serial combination is valid
func (d *DeviceManagerFile) OnboardCheck(cert *x509.Certificate, serial string) (bool, error) {
	// do not accept a nil certificate
	if cert == nil {
		return false, fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return false, fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	if !d.checkValidOnboardSerial(cert, serial) {
		return false, nil
	}
	if d.getOnboardSerialDevice(cert, serial) != nil {
		return false, nil
	}
	return true, nil
}

// OnboardGet get the onboard cert and its serials based on Common Name
func (d *DeviceManagerFile) OnboardGet(cn string) (*x509.Certificate, []string, error) {
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
		return nil, nil, &NotFoundError{err: fmt.Sprintf("onboard directory not found %s", onboardDir)}
	}

	// get the certificate and serials
	certPath := path.Join(onboardDir, onboardCertFilename)
	cert, err := ax.ReadCert(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading onboard certificate at %s: %v", certPath, err)
	}
	serialPath := path.Join(onboardDir, onboardCertSerials)
	serial, err := ioutil.ReadFile(serialPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading onboard serials at %s: %v", serialPath, err)
	}
	// done
	return cert, strings.Fields(string(serial)), nil
}

// OnboardList list all of the known Common Names for onboard
func (d *DeviceManagerFile) OnboardList() ([]string, error) {
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
func (d *DeviceManagerFile) OnboardRemove(cn string) error {
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
func (d *DeviceManagerFile) OnboardClear() error {
	// remove the directory and clear the cache
	onboardPath := path.Join(d.databasePath, onboardDir)
	candidates, err := ioutil.ReadDir(onboardPath)
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
func (d *DeviceManagerFile) DeviceCheckCert(cert *x509.Certificate) (*uuid.UUID, error) {
	if cert == nil {
		return nil, fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	certStr := string(cert.Raw)
	if u, ok := d.deviceCerts[certStr]; ok {
		return &u, nil
	}
	return nil, nil
}

// DeviceRemove remove a device
func (d *DeviceManagerFile) DeviceRemove(u *uuid.UUID) error {
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
func (d *DeviceManagerFile) DeviceClear() error {
	// remove the directory and clear the cache
	devicePath := path.Join(d.databasePath, deviceDir)
	candidates, err := ioutil.ReadDir(devicePath)
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
	d.devices = map[uuid.UUID]deviceStorage{}
	return nil
}

// DeviceGet get an individual device by UUID
func (d *DeviceManagerFile) DeviceGet(u *uuid.UUID) (*x509.Certificate, *x509.Certificate, string, error) {
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
		return nil, nil, "", &NotFoundError{err: fmt.Sprintf("device directory %s not found", onboardDir)}
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
	serial, err := ioutil.ReadFile(serialPath)
	// we can accept not reading the onboard serial
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, "", fmt.Errorf("error reading device serial at %s: %v", serialPath, err)
	}
	// done
	return cert, onboard, string(serial), nil
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManagerFile) DeviceList() ([]*uuid.UUID, error) {
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	ids := make([]*uuid.UUID, 0, len(d.devices))
	for u := range d.devices {
		ids = append(ids, &u)
	}
	return ids, nil
}

// DeviceRegister register a new device cert
func (d *DeviceManagerFile) DeviceRegister(cert, onboard *x509.Certificate, serial string) (*uuid.UUID, error) {
	// refresh certs from filesystem, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	// check if it already exists - this also checks for nil cert
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

	// create filesystem tree and subdirs for the new device
	devicePath := d.getDevicePath(unew)
	err = os.MkdirAll(devicePath, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating new device tree %s: %v", devicePath, err)
	}

	// save the device certificate
	certPath := path.Join(devicePath, DeviceCertFilename)
	err = ax.WriteCert(cert.Raw, certPath, true)
	if err != nil {
		return nil, fmt.Errorf("error saving device certificate to %s: %v", certPath, err)
	}

	// save the onboard certificate and serial
	certPath = path.Join(devicePath, DeviceOnboardFilename)
	err = ax.WriteCert(onboard.Raw, certPath, true)
	if err != nil {
		return nil, fmt.Errorf("error saving device onboard certificate to %s: %v", certPath, err)
	}
	serialPath := path.Join(devicePath, deviceSerialFilename)
	err = ioutil.WriteFile(serialPath, []byte(serial), 0644)
	if err != nil {
		return nil, fmt.Errorf("error saving device serial to %s: %v", serialPath, err)
	}
	// save the base configuration
	err = d.writeProtobufToJSONFile(unew, "", deviceConfigFilename, createBaseConfig(unew))
	if err != nil {
		return nil, fmt.Errorf("error saving device config to %s: %v", deviceConfigFilename, err)
	}

	// create the necessary directories for data uploads
	for _, p := range []string{logDir, metricsDir, infoDir} {
		cur := path.Join(devicePath, p)
		err = os.MkdirAll(cur, 0755)
		if err != nil {
			return nil, fmt.Errorf("error creating new device sub-path %s: %v", cur, err)
		}
	}

	// save new one to cache - just the serial and onboard; the rest is on disk
	d.deviceCerts[string(cert.Raw)] = unew
	d.devices[unew] = deviceStorage{
		onboard: onboard,
		serial:  serial,
	}

	return &unew, nil
}

// OnboardRegister register an onboard cert and update its serials
func (d *DeviceManagerFile) OnboardRegister(cert *x509.Certificate, serial []string) error {
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
	onboardPath := path.Join(d.databasePath, onboardDir, getOnboardCertName(cn))
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
	err = ioutil.WriteFile(f, []byte(strings.Join(serial, "\n")), 0644)
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

// WriteInfo write an info message
func (d *DeviceManagerFile) WriteInfo(m *info.ZInfoMsg) error {
	// make sure it is not nil
	if m == nil {
		return fmt.Errorf("invalid nil message")
	}
	// get the uuid
	u, err := uuid.FromString(m.DevId)
	if err != nil {
		return fmt.Errorf("unable to retrieve valid device UUID from message as %s: %v", m.DevId, err)
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", m.DevId)
	}
	err = d.writeProtobufToJSONFile(u, infoDir, fmt.Sprintf("%d", m.AtTimeStamp.Seconds), m)
	if err != nil {
		return fmt.Errorf("failed to write info to file: %v", err)
	}
	return nil
}

// WriteLogs write a message of logs
func (d *DeviceManagerFile) WriteLogs(m *logs.LogBundle) error {
	// make sure it is not nil
	if m == nil {
		return fmt.Errorf("invalid nil message")
	}
	// get the uuid
	u, err := uuid.FromString(m.DevID)
	if err != nil {
		return fmt.Errorf("unable to retrieve valid device UUID from message as %s: %v", m.DevID, err)
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", m.DevID)
	}
	err = d.writeProtobufToJSONFile(u, logDir, fmt.Sprintf("%d", m.Timestamp.Seconds), m)
	if err != nil {
		return fmt.Errorf("failed to write logs to file: %v", err)
	}
	return nil
}

// WriteMetrics write a metrics message
func (d *DeviceManagerFile) WriteMetrics(m *metrics.ZMetricMsg) error {
	// make sure it is not nil
	if m == nil {
		return fmt.Errorf("invalid nil message")
	}
	// get the uuid
	u, err := uuid.FromString(m.DevID)
	if err != nil {
		return fmt.Errorf("unable to retrieve valid device UUID from message as %s: %v", m.DevID, err)
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", m.DevID)
	}
	err = d.writeProtobufToJSONFile(u, metricsDir, fmt.Sprintf("%d", m.AtTimeStamp.Seconds), m)
	if err != nil {
		return fmt.Errorf("failed to write metrics to file: %v", err)
	}
	return nil
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManagerFile) GetConfig(u uuid.UUID) (*config.EdgeDevConfig, error) {
	// hold our config
	msg := &config.EdgeDevConfig{}
	// read the config from disk
	fullConfigPath := path.Join(d.getDevicePath(u), deviceConfigFilename)
	b, err := ioutil.ReadFile(fullConfigPath)
	switch {
	case err != nil && os.IsNotExist(err):
		// create the base file if it does not exist
		msg = createBaseConfig(u)
		err = d.writeProtobufToJSONFile(u, "", deviceConfigFilename, msg)
		if err != nil {
			return nil, fmt.Errorf("error saving device config to %s: %v", deviceConfigFilename, err)
		}
	case err != nil:
		return nil, fmt.Errorf("could not read config from %s: %v", fullConfigPath, err)
	default:
		// convert it to the message format
		err = jsonpb.UnmarshalString(string(b), msg)
		if err != nil {
			return nil, fmt.Errorf("error parsing the config to protobuf: %v", err)
		}
	}

	return msg, nil
}

// refreshCache refresh cache from disk
func (d *DeviceManagerFile) refreshCache() error {
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
	onboardCerts := make(map[string]map[string]bool)
	deviceCerts := make(map[string]uuid.UUID)
	devices := make(map[uuid.UUID]deviceStorage)

	// scan the onboard path for all files which end in ".pem" and load them
	onboardPath := path.Join(d.databasePath, onboardDir)
	candidates, err := ioutil.ReadDir(onboardPath)
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
		b, err := ioutil.ReadFile(f)
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
		onboardCerts[certStr] = make(map[string]bool)

		// get the serial list
		f = path.Join(onboardPath, name, onboardCertSerials)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		//   we already have the onboard cert saved, so no serials to add
		if err != nil {
			continue
		}
		b, err = ioutil.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read onboard serial file %s: %v", f, err)
		}
		// convert the []byte to string, split and save
		for _, serial := range strings.Fields(string(b)) {
			onboardCerts[certStr][serial] = true
		}
	}
	// replace the existing onboard certificates
	d.onboardCerts = onboardCerts

	// scan the device path for each dir which is the UUID
	//   and in each one, if a cert exists with the appropriate name, load it
	devicePath := path.Join(d.databasePath, deviceDir)
	candidates, err = ioutil.ReadDir(devicePath)
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
		b, err := ioutil.ReadFile(f)
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
		deviceCerts[certStr] = u
		devices[u] = deviceStorage{}

		// load the device onboarding certificate and serial
		f = path.Join(devicePath, DeviceOnboardFilename)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		if err != nil {
			continue
		}
		// read the file
		b, err = ioutil.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device onboard certificate file %s: %v", f, err)
		}
		// convert into a certificate
		certPem, _ = pem.Decode(b)
		cert, err = x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to device onboard certificate: %v", f, err)
		}
		certStr = string(cert.Raw)
		if err != nil {
			return fmt.Errorf("unable to convert device uuid from directory name %s: %v", name, err)
		}
		devItem := devices[u]
		devItem.onboard = cert
		devices[u] = devItem
		// and the serial
		f = path.Join(devicePath, deviceSerialFilename)
		_, err = os.Stat(f)
		// if we cannot list the file, we do not care why, just continue
		if err != nil {
			continue
		}
		// read the file
		b, err = ioutil.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device serial file %s: %v", f, err)
		}
		devItem = devices[u]
		devItem.serial = string(b)
		devices[u] = devItem
	}
	// replace the existing device certificates
	d.deviceCerts = deviceCerts
	// replace the existing device cache
	d.devices = devices

	// mark the time we updated
	d.lastUpdate = now
	return nil
}

// initialize dirs, in case they do not exist
func (d *DeviceManagerFile) initializeDB() error {
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
func (d *DeviceManagerFile) getDevicePath(u uuid.UUID) string {
	return GetDevicePath(d.databasePath, u)
}

// getOnboardPath get the path for a given onboard
func (d *DeviceManagerFile) getOnboardPath(cn string) string {
	return path.Join(d.databasePath, onboardDir, cn)
}

// writeProtobufToJSONFile write a protobuf to a named file in the given directory
func (d *DeviceManagerFile) writeProtobufToJSONFile(u uuid.UUID, dir, filename string, msg proto.Message) error {
	// if dir == "", then path.Join() automatically ignores it
	fullPath := path.Join(d.getDevicePath(u), dir, filename)
	f, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", fullPath, err)
	}
	defer f.Close()
	mler := jsonpb.Marshaler{}
	err = mler.Marshal(f, msg)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	// no need to f.Close() as it happens automatically
	return nil
}

// deviceExists return if a device has been created
func (d *DeviceManagerFile) deviceExists(u uuid.UUID) bool {
	_, err := os.Stat(d.getDevicePath(u))
	if err != nil {
		return false
	}
	return true
}

// checkValidOnboardSerial see if a particular certificate+serial combinaton is valid
// does **not** check if it has been used
func (d *DeviceManagerFile) checkValidOnboardSerial(cert *x509.Certificate, serial string) bool {
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
func (d *DeviceManagerFile) getOnboardSerialDevice(cert *x509.Certificate, serial string) *uuid.UUID {
	certStr := string(cert.Raw)
	for uid, dev := range d.devices {
		dCertStr := string(dev.onboard.Raw)
		if dCertStr == certStr && serial == dev.serial {
			return &uid
		}
	}
	return nil
}

// GetDevicePath get the path for a given device
func GetDevicePath(databasePath string, u uuid.UUID) string {
	return path.Join(databasePath, deviceDir, u.String())
}

func getOnboardCertName(cn string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9\\.\\-]`)
	return re.ReplaceAllString(cn, "_")
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
