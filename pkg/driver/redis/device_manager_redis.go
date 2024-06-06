// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/lf-edge/adam/pkg/driver/common"
	ax "github.com/lf-edge/adam/pkg/x509"
	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	uuid "github.com/satori/go.uuid"
	"github.com/vmihailenco/msgpack/v4"
	"google.golang.org/protobuf/proto"
)

const (
	// Our current schema for Redis database is that aside from logs, info and metrics
	// everything else is kept in Redis hashes with the following mapping:
	onboardCertsHash       = "ONBOARD_CERTS"        // CN -> string (certificate PEM)
	onboardSerialsHash     = "ONBOARD_SERIALS"      // CN -> []string (list of serial #s)
	deviceSerialsHash      = "DEVICE_SERIALS"       // UUID -> string (single serial #)
	deviceOnboardCertsHash = "DEVICE_ONBOARD_CERTS" // UUID -> string (certificate PEM)
	deviceCertsHash        = "DEVICE_CERTS"         // UUID -> string (certificate PEM)
	deviceConfigsHash      = "DEVICE_CONFIGS"       // UUID -> json (EVE config json representation)
	deviceAttestCertsHash  = "DEVICE_ATTEST_CERTS"  //UUID -> json (EVE attest certs request json representation)
	deviceStorageKeysHash  = "DEVICE_STORAGE_KEYS"  //UUID -> json (EVE storage keys json representation)
	deviceOptionsHash      = "DEVICE_OPTIONS"       //UUID -> json (options json representation)
	globalOptionsHash      = "GLOBAL_OPTIONS"       //GLOBAL_OPTIONS -> json (options json representation)

	// Logs, info and metrics are managed by Redis streams named after device UUID as in:
	//    LOGS_EVE_<UUID>
	//    INFO_EVE_<UUID>
	//    METRICS_EVE_<UUID>
	// with each stream element having a single key pair:
	//   "object" -> msgpack serialized object
	// see MkStreamEntry() for details
	deviceLogsStream        = "LOGS_EVE_"
	deviceInfoStream        = "INFO_EVE_"
	deviceMetricsStream     = "METRICS_EVE_"
	deviceRequestsStream    = "REQUESTS_EVE_"
	deviceFlowMessageStream = "FLOW_MESSAGE_EVE_"
	deviceAppLogsStream     = "APPS_EVE_"

	ioTimeout  = 10 * time.Second
	maxRetries = 5

	MB                   = common.MB
	maxLogSizeRedis      = 100 * MB
	maxInfoSizeRedis     = 100 * MB
	maxMetricSizeRedis   = 100 * MB
	maxRequestsSizeRedis = 100 * MB
	maxFlowMessageRedis  = 100 * MB
	maxAppLogsSizeRedis  = 100 * MB
)

// ManagedStream stream of data interface
type ManagedStream struct {
	name   string
	client *redis.Client
}

func (m *ManagedStream) Get(index int) ([]byte, error) {
	return nil, errors.New("unsupported")
}

func (m *ManagedStream) Write(b []byte) (int, error) {
	// XXX: lets see if this blocks
	if _, err := m.client.XAdd(&redis.XAddArgs{
		Stream: m.name,
		ID:     "*",
		Values: mkStreamEntry(b),
	}).Result(); err != nil {
		return 0, fmt.Errorf("failed to put message into a stream %s: %v", m.name, err)
	}
	return len(b), nil
}

func (m *ManagedStream) Reader() (common.ChunkReader, error) {
	r := &RedisStreamReader{
		Client: m.client,
		Stream: m.name,
	}
	return r, nil
}

// DeviceManager implementation of DeviceManager interface with a Redis DB as the backing store
type DeviceManager struct {
	client       *redis.Client
	databaseNet  string
	databaseURL  string
	databaseID   int
	cacheTimeout int
	lastUpdate   time.Time
	// these are for caching only
	onboardCerts map[string]map[string]bool
	deviceCerts  map[string]uuid.UUID
	devices      map[uuid.UUID]common.DeviceStorage
}

// Name return name
func (d *DeviceManager) Name() string {
	return "redis"
}

// Database return database hostname and port
func (d *DeviceManager) Database() string {
	return d.databaseURL
}

// MaxLogSize return the default maximum log size in bytes for this device manager
func (d *DeviceManager) MaxLogSize() int {
	return maxLogSizeRedis
}

// MaxInfoSize return the default maximum info size in bytes for this device manager
func (d *DeviceManager) MaxInfoSize() int {
	return maxInfoSizeRedis
}

// MaxMetricSize return the maximum metrics size in bytes for this device manager
func (d *DeviceManager) MaxMetricSize() int {
	return maxMetricSizeRedis
}

// MaxRequestsSize return the maximum requests log size in bytes for this device manager
func (d *DeviceManager) MaxRequestsSize() int {
	return maxRequestsSizeRedis
}

// MaxAppLogsSize return the maximum app logs size in bytes for this device manager
func (d *DeviceManager) MaxAppLogsSize() int {
	return maxAppLogsSizeRedis
}

// MaxFlowMessageSize return the maximum FlowMessage logs size in bytes for this device manager
func (d *DeviceManager) MaxFlowMessageSize() int {
	return maxFlowMessageRedis
}

// Init check if a URL is valid and initialize
func (d *DeviceManager) Init(s string, sizes common.MaxSizes) (bool, error) {
	URL, err := url.Parse(s)
	if err != nil || URL.Scheme != "redis" {
		return false, err
	}

	d.databaseNet = "tcp"

	if URL.Host != "" {
		d.databaseURL = URL.Host
	} else {
		d.databaseURL = "localhost:6379"
	}
	if URL.Path != "" {
		if d.databaseID, err = strconv.Atoi(strings.Trim(URL.Path, "/")); err != nil {
			return false, err
		}
	} else {
		d.databaseID = 0
	}

	d.client = redis.NewClient(&redis.Options{
		Network:      d.databaseNet,
		Addr:         d.databaseURL,
		Password:     URL.User.Username(), // yes, I know!
		DB:           d.databaseID,
		ReadTimeout:  ioTimeout,
		WriteTimeout: ioTimeout,
		MaxRetries:   maxRetries,
	})

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
	// refresh certs from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Redis: %v", err)
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

	cert, err := d.readCert(onboardCertsHash, cn)
	if err != nil {
		return nil, nil, err
	}

	s, err := d.client.HGet(onboardSerialsHash, cn).Result()
	if err != nil && errors.Is(err, redis.Nil) {
		return nil, nil, &common.NotFoundError{Err: fmt.Sprintf("device not found %s", cn)}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error reading onboard serials for %s: %v", cn, err)
	}
	var serials []string
	if err = msgpack.Unmarshal([]byte(s), &serials); err != nil {
		return nil, nil, fmt.Errorf("error decoding onboard serials for %s %v (%s)", cn, err, s)
	}
	return cert, serials, nil
}

// OnboardList list all of the known Common Names for onboard
func (d *DeviceManager) OnboardList() ([]string, error) {
	// refresh certs from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Redis: %v", err)
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
func (d *DeviceManager) OnboardRemove(cn string) (result error) {
	result = d.transactionDrop([][]string{{onboardCertsHash, cn}, {onboardSerialsHash, cn}})
	if result == nil {
		result = d.refreshCache()
	}
	return
}

// OnboardClear remove all onboarding certs
func (d *DeviceManager) OnboardClear() error {
	if err := d.transactionDrop([][]string{{onboardCertsHash}, {onboardSerialsHash}}); err != nil {
		return fmt.Errorf("unable to remove the onboarding certificates/serials: %v", err)
	}

	d.onboardCerts = map[string]map[string]bool{}
	return nil
}

// DeviceCheckCert see if a particular certificate is a valid registered device certificate
func (d *DeviceManager) DeviceCheckCert(cert *x509.Certificate) (*uuid.UUID, error) {
	if cert == nil {
		return nil, fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Redis: %v", err)
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
	// refresh certs from Redis, if needed - includes checking if necessary based on timer
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
	return nil, fmt.Errorf("cert hash not found")
}

// DeviceRemove remove a device
func (d *DeviceManager) DeviceRemove(u *uuid.UUID) error {
	k := u.String()
	streams := [][]string{
		{deviceCertsHash, k},
		{deviceConfigsHash, k},
		{deviceOnboardCertsHash, k},
		{deviceAttestCertsHash, k},
		{deviceStorageKeysHash, k},
		{deviceOptionsHash, k},
		{deviceSerialsHash, k},
		{deviceInfoStream + k},
		{deviceLogsStream + k},
		{deviceMetricsStream + k},
		{deviceFlowMessageStream + k},
		{deviceRequestsStream + k},
	}
	for appUUID := range d.devices[*u].AppLogs {
		streams = append(streams, []string{deviceAppLogsStream + k + "_" + appUUID.String()})
	}
	err := d.transactionDrop(streams)

	if err != nil {
		return fmt.Errorf("unable to remove the device %s %v", k, err)
	}
	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh device cache: %v", err)
	}
	return nil
}

// DeviceClear remove all devices
func (d *DeviceManager) DeviceClear() error {
	streams := [][]string{
		{deviceConfigsHash},
		{deviceSerialsHash},
		{deviceCertsHash},
		{deviceAttestCertsHash},
		{deviceStorageKeysHash},
		{deviceOnboardCertsHash},
		{deviceOptionsHash}}

	for u, dev := range d.devices {
		streams = append(streams,
			[]string{deviceMetricsStream + u.String()},
			[]string{deviceLogsStream + u.String()},
			[]string{deviceInfoStream + u.String()},
			[]string{deviceFlowMessageStream + u.String()},
			[]string{deviceRequestsStream + u.String()})
		for appUUID := range dev.AppLogs {
			streams = append(streams, []string{deviceAppLogsStream + u.String() + "_" + appUUID.String()})
		}
	}

	err := d.transactionDrop(streams)

	if err != nil {
		return fmt.Errorf("unable to remove all devices %v", err)
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

	// first lets get the device certificate
	cert, err := d.readCert(deviceCertsHash, u.String())
	if err != nil {
		return nil, nil, "", fmt.Errorf("error reading device certificate for %s: %v", u.String(), err)
	}

	// now lets get the device onboarding certificate
	onboard, err := d.readCert(deviceOnboardCertsHash, u.String())
	if err != nil {
		return nil, nil, "", fmt.Errorf("error reading onboarding certificate for %s: %v", u.String(), err)
	}

	serial, err := d.client.HGet(deviceSerialsHash, u.String()).Result()
	if err != nil && errors.Is(err, redis.Nil) {
		return nil, nil, "", &common.NotFoundError{Err: fmt.Sprintf("device not found %s", u)}
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("error reading device serial for %s: %v", u.String(), err)
	}
	// somehow device serials are best effort
	return cert, onboard, serial, nil
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManager) DeviceList() ([]*uuid.UUID, error) {
	// refresh certs from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Redis: %v", err)
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

// DeviceRegister register a new device cert
func (d *DeviceManager) DeviceRegister(unew uuid.UUID, cert, onboard *x509.Certificate, serial string, conf []byte) error {
	// refresh certs from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Redis: %v", err)
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

	// save the device certificate
	err = d.writeCert(cert.Raw, deviceCertsHash, unew.String(), true)
	if err != nil {
		return err
	}

	// save the onboard certificate and serial, if provided
	if onboard != nil {
		err = d.writeCert(onboard.Raw, deviceOnboardCertsHash, unew.String(), true)
		if err != nil {
			return err
		}
	}
	if serial != "" {
		if _, err = d.client.HSet(deviceSerialsHash, unew.String(), serial).Result(); err == nil {
			_, err = d.client.Save().Result()
		}
		if err != nil {
			return fmt.Errorf("error saving device serial for %v: %v", unew, err)
		}
	}

	// save the base configuration
	err = d.writeJSONMsgPack(unew, deviceConfigsHash, conf)
	if err != nil {
		return fmt.Errorf("error saving device config for %v: %v", unew, err)
	}

	// save new one to cache - just the serial and onboard; the rest is on disk
	d.deviceCerts[string(cert.Raw)] = unew
	d.devices[unew] = d.initDevice(unew, onboard, serial)
	ds := d.devices[unew]

	// create the necessary Redis streams for this device
	for _, ms := range []common.BigData{ds.Logs, ds.Info, ds.Metrics, ds.Requests} {
		if _, err := ms.Write([]byte("")); err != nil {
			return fmt.Errorf("error creating stream: %v", err)
		}
	}

	return nil
}

// initDevice initialize a device
func (d *DeviceManager) initDevice(u uuid.UUID, onboard *x509.Certificate, serial string) common.DeviceStorage {
	return common.DeviceStorage{
		Onboard: onboard,
		Serial:  serial,
		Logs: &ManagedStream{
			name:   deviceLogsStream + u.String(),
			client: d.client,
		},
		Info: &ManagedStream{
			name:   deviceInfoStream + u.String(),
			client: d.client,
		},
		Metrics: &ManagedStream{
			name:   deviceMetricsStream + u.String(),
			client: d.client,
		},
		FlowMessage: &ManagedStream{
			name:   deviceFlowMessageStream + u.String(),
			client: d.client,
		},
		Requests: &ManagedStream{
			name:   deviceRequestsStream + u.String(),
			client: d.client,
		},
		AppLogs: map[uuid.UUID]common.BigData{},
	}
}

// OnboardRegister register an onboard cert and update its serials
func (d *DeviceManager) OnboardRegister(cert *x509.Certificate, serial []string) error {
	if cert == nil {
		return fmt.Errorf("empty nil certificate")
	}
	certStr := string(cert.Raw)
	cn := common.GetOnboardCertName(cert.Subject.CommonName)

	if err := d.writeCert(cert.Raw, onboardCertsHash, cn, true); err != nil {
		return fmt.Errorf("failed to write onboardCertsHash %v: %v", cn, err)
	}

	v, err := msgpack.Marshal(&serial)
	if err != nil {
		return fmt.Errorf("failed to serialize serials %v: %v", serial, err)
	}

	if _, err = d.client.HSet(onboardSerialsHash, cn, v).Result(); err == nil {
		_, err = d.client.Save().Result()
	}
	if err != nil {
		return fmt.Errorf("failed to save serials %v: %v", serial, err)
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
		if err := dev.AddRequest(b); err != nil {
			return fmt.Errorf("AddRequest error: %s", err)
		}
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
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("device not found: %s", u)
	}
	return dev.AddInfo(b)
}

// WriteLogs write a message of logs
func (d *DeviceManager) WriteLogs(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("device not found: %s", u)
	}
	return dev.AddLogs(b)
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
		d.devices[deviceID].AppLogs[instanceID] = &ManagedStream{
			name:   fmt.Sprintf("%s%s_%s", deviceAppLogsStream, deviceID.String(), instanceID.String()),
			client: d.client,
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
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("device not found: %s", u)
	}
	return dev.AddMetrics(b)
}

// WriteCerts write an attestation certs information
func (d *DeviceManager) WriteCerts(u uuid.UUID, b []byte) error {
	// pre-flight checks to bail early
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}

	// refresh certs from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Redis: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}

	if _, err = d.client.HSet(deviceAttestCertsHash, u.String(), string(b)).Result(); err == nil {
		_, err = d.client.Save().Result()
	}
	if err != nil {
		return fmt.Errorf("failed to save attest certs for %s: %v", u.String(), err)
	}
	return nil
}

// GetCerts retrieve the attest certs for a particular device
func (d *DeviceManager) GetCerts(u uuid.UUID) ([]byte, error) {
	// hold our config
	var b []byte
	data, err := d.client.HGet(deviceAttestCertsHash, u.String()).Result()
	if err != nil && errors.Is(err, redis.Nil) {
		return nil, &common.NotFoundError{Err: fmt.Sprintf("no attestation certificates found for device %s", u)}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get attest for %s: %v", u.String(), err)
	} else {
		b = []byte(data)
	}

	return b, nil
}

// WriteStorageKeys write storage keys information
func (d *DeviceManager) WriteStorageKeys(u uuid.UUID, b []byte) error {
	// pre-flight checks to bail early
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}

	// refresh cache from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Redis: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}

	if _, err = d.client.HSet(deviceStorageKeysHash, u.String(), string(b)).Result(); err == nil {
		_, err = d.client.Save().Result()
	}
	if err != nil {
		return fmt.Errorf("failed to save storage keys for %s: %v", u.String(), err)
	}
	return nil
}

// GetStorageKeys retrieve storage keys for a particular device
func (d *DeviceManager) GetStorageKeys(u uuid.UUID) ([]byte, error) {
	// hold our config
	var b []byte
	data, err := d.client.HGet(deviceStorageKeysHash, u.String()).Result()
	if err != nil && errors.Is(err, redis.Nil) {
		return nil, &common.NotFoundError{Err: fmt.Sprintf("no storage keys found for device %s", u)}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get storage keys for %s: %v", u.String(), err)
	} else {
		b = []byte(data)
	}

	return b, nil
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManager) GetConfig(u uuid.UUID) ([]byte, error) {
	// hold our config
	var b []byte
	data, err := d.client.HGet(deviceConfigsHash, u.String()).Result()
	switch {
	case err != nil && errors.Is(err, redis.Nil):
		// if config doesn't exist - create an empty one
		b = common.CreateBaseConfig(u)
		if _, err = d.client.HSet(deviceConfigsHash, u.String(), string(b)).Result(); err == nil {
			_, err = d.client.Save().Result()
		}
		if err != nil {
			return nil, fmt.Errorf("failed to save config for %s: %v", u.String(), err)
		}
	case err != nil:
		return nil, fmt.Errorf("failed to get config for %s: %v", u.String(), err)
	default:
		b = []byte(data)
	}

	return b, nil
}

// SetConfig set the config for a particular device
func (d *DeviceManager) SetConfig(u uuid.UUID, b []byte) error {
	// pre-flight checks to bail early
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}

	// refresh certs from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Redis: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}

	if _, err = d.client.HSet(deviceConfigsHash, u.String(), string(b)).Result(); err == nil {
		_, err = d.client.Save().Result()
	}
	if err != nil {
		return fmt.Errorf("failed to save config for %s: %v", u.String(), err)
	}
	return nil
}

// GetLogsReader get the logs for a given uuid
func (d *DeviceManager) GetLogsReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Logs.Reader()
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManager) GetInfoReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Info.Reader()
}

// GetRequestsReader get the requests for a given uuid
func (d *DeviceManager) GetRequestsReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Requests.Reader()
}

// refreshCache refresh cache from disk
func (d *DeviceManager) refreshCache() error {
	// is it time to update the cache again?
	now := time.Now()
	if now.Sub(d.lastUpdate).Seconds() < float64(d.cacheTimeout) {
		return nil
	}
	stats := d.client.PoolStats()
	if stats.Timeouts > 0 {
		log.Printf("Pool timeouts: %d", stats.Timeouts)
	}

	// create new vars to hold while we load
	onboardCerts := make(map[string]map[string]bool)
	deviceCerts := make(map[string]uuid.UUID)
	devices := make(map[uuid.UUID]common.DeviceStorage)

	// scan the onboarding certs
	ocerts, err := d.client.HGetAll(onboardCertsHash).Result()
	if err != nil {
		return fmt.Errorf("failed to retrieve onboarding certificated from %s %v", onboardCertsHash, err)
	}

	for u, c := range ocerts {
		certPem, _ := pem.Decode([]byte(c))
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from %s to onboard certificate: %v", c, err)
		}
		certStr := string(cert.Raw)

		v, err := d.client.HGet(onboardSerialsHash, u).Result()
		if err != nil && errors.Is(err, redis.Nil) {
			log.Printf("unabled to get a serial for %s: %v", u, err)
			continue
		}
		if err != nil {
			return fmt.Errorf("error getting serials for %s: %v", u, err)
		}

		onboardCerts[certStr] = make(map[string]bool)

		var serials []string
		err = msgpack.Unmarshal([]byte(v), &serials)
		if err != nil {
			return fmt.Errorf("unable to unmarshal onboard serials %s: %v", v, err)
		}
		for _, serial := range serials {
			onboardCerts[certStr][serial] = true
		}
	}
	// replace the existing onboard certificates
	d.onboardCerts = onboardCerts

	// scan the device certs
	dcerts, err := d.client.HGetAll(deviceCertsHash).Result()
	if err != nil {
		return fmt.Errorf("failed to retrieve device certificates from %s %v", deviceCertsHash, err)
	}

	// check each Redis hash to see if it is valid
	for k, c := range dcerts {
		// convert the path name to a UUID
		u, err := uuid.FromString(k)
		if err != nil {
			return fmt.Errorf("unable to convert device uuid from Redis hash name %s: %v", u, err)
		}

		// load the device certificate
		certPem, _ := pem.Decode([]byte(c))
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to device certificate: %v", c, err)
		}
		certStr := string(cert.Raw)
		deviceCerts[certStr] = u
		devices[u] = d.initDevice(u, cert, "") // start with no serial, as it will be added further down
	}
	// replace the existing device certificates
	d.deviceCerts = deviceCerts

	// scan the device onboarding certs
	docerts, err := d.client.HGetAll(deviceOnboardCertsHash).Result()
	if err != nil {
		return fmt.Errorf("failed to retrieve device certificates from %s %v", deviceCertsHash, err)
	}

	// check each Redis hash to see if it is valid
	for k, b := range docerts {
		// convert the path name to a UUID
		u, err := uuid.FromString(k)
		if err != nil {
			return fmt.Errorf("unable to convert device uuid from Redis hash name %s: %v", u, err)
		}

		certPem, _ := pem.Decode([]byte(b))
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to device onboard certificate: %v", b, err)
		}
		if _, present := devices[u]; !present {
			devices[u] = d.initDevice(u, nil, "") // start with a blank serial and no device cert
		}
		// because of the "cannot assign to struct field" golang issue
		devItem := devices[u]
		devItem.Onboard = cert
		devices[u] = devItem
	}

	// scan the device onboarding certs
	dserials, err := d.client.HGetAll(deviceSerialsHash).Result()
	if err != nil {
		return fmt.Errorf("failed to retrieve device certificates from %s %v", deviceCertsHash, err)
	}

	for k, s := range dserials {
		// convert the path name to a UUID
		u, err := uuid.FromString(k)
		if err != nil {
			return fmt.Errorf("unable to convert device uuid from Redis hash name %s: %v", u, err)
		}
		if _, present := devices[u]; !present {
			devices[u] = d.initDevice(u, nil, s)
		}
		devItem := devices[u]
		devItem.Serial = s
		devices[u] = devItem
	}

	for deviceID, device := range devices {
		prefix := deviceAppLogsStream + deviceID.String() + "_"
		appLogKeys, err := d.client.Keys(prefix + "*").Result()
		if err != nil {
			return fmt.Errorf("failed to retrieve device app logs streams %v", err)
		}
		for _, el := range appLogKeys {
			instanceID, err := uuid.FromString(strings.TrimPrefix(el, prefix))
			if err != nil {
				return fmt.Errorf("cannot parse device app logs stream %v", err)
			}
			device.AppLogs[instanceID] = &ManagedStream{
				name:   prefix + instanceID.String(),
				client: d.client,
			}
		}
	}
	// replace the existing device cache
	d.devices = devices

	// mark the time we updated
	d.lastUpdate = now
	return nil
}

// writeProtobufToJSONMsgPack write a protobuf to a named hash in Redis
func (d *DeviceManager) writeProtobufToJSONMsgPack(u uuid.UUID, hash string, msg proto.Message) error {
	s, err := msgpack.Marshal(&msg)
	if err != nil {
		return fmt.Errorf("can't marshal proto message %v", err)
	}
	return d.writeJSONMsgPack(u, hash, s)
}

// writeJSONMsgPack write a JSON to a named hash in Redis
func (d *DeviceManager) writeJSONMsgPack(u uuid.UUID, hash string, b []byte) error {
	var err error
	if _, err = d.client.HSet(hash, u.String(), string(b)).Result(); err == nil {
		_, err = d.client.Save().Result()
	}
	if err != nil {
		return fmt.Errorf("can't save message for %s in %s: %v", u.String(), hash, err)
	}
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

func (d *DeviceManager) transactionDrop(keys [][]string) (result error) {
	// transactionality of this function is currently a lie: later on we
	// will turn it into one, but for now lets just hope that we never
	// get into an inconsistent state between all these objects that need
	// to be droppped
	for _, k := range keys {
		switch len(k) {
		case 1:
			if i, err := d.client.Del(k[0]).Result(); i != 1 || err != nil {
				result = fmt.Errorf("couldn't drop %s with error %d/%v (previous error in transaction %v)",
					k[0], i, err, result)
			}
		case 2:
			if i, err := d.client.HDel(k[0], k[1]).Result(); i != 1 || err != nil {
				result = fmt.Errorf("couldn't drop %s[%s] with error %d/%v (previous error in transaction %v)",
					k[0], k[1], i, err, result)
			}
		default:
			panic("transactionDrop should never be called with keys that are less than 1 or more than 2 elements")
		}
	}
	return
}

func (d *DeviceManager) readCert(hash string, key string) (*x509.Certificate, error) {
	v, err := d.client.HGet(hash, key).Result()
	if err != nil {
		return nil, fmt.Errorf("error reading certificate for %s from hash %s: %v", key, hash, err)
	}

	if cert, err := ax.ParseCert([]byte(v)); err != nil {
		return nil, fmt.Errorf("error decoding onboard certificate for %s from hash %s: %v (%s)", key, hash, err, v)
	} else {
		return cert, nil
	}
}

// WriteCert write cert bytes to a path, after pem encoding them. Do not overwrite unless force is true.
func (d *DeviceManager) writeCert(cert []byte, hash string, uuid string, force bool) error {
	// make sure we have the paths we need, and that they are not already taken, unless we were told to force
	if hash == "" {
		return fmt.Errorf("certPath must not be empty")
	}

	if _, err := d.client.HGet(hash, uuid).Result(); err == nil && !force {
		return fmt.Errorf("certificate for %s already exists in %s", uuid, hash)
	}
	certPem := ax.PemEncodeCert(cert)
	if b, err := d.client.HSet(hash, uuid, certPem).Result(); err != nil || (!b && !force) {
		return fmt.Errorf("failed to write certificate for %s: %v", uuid, err)
	}
	if _, err := d.client.Save().Result(); err != nil {
		return fmt.Errorf("failed to write certificate for %s: %v", uuid, err)
	}

	return nil
}

func mkStreamEntry(body []byte) map[string]interface{} {
	return map[string]interface{}{"version": "1", "object": string(body)}
}

// WriteFlowMessage write FlowMessage
func (d *DeviceManager) WriteFlowMessage(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("device not found: %s", u)
	}
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
	// pre-flight checks to bail early
	if len(b) < 1 {
		return fmt.Errorf("empty options")
	}

	// refresh cache from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh from Redis: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}

	if _, err = d.client.HSet(deviceOptionsHash, u.String(), string(b)).Result(); err == nil {
		_, err = d.client.Save().Result()
	}
	if err != nil {
		return fmt.Errorf("failed to save options for %s: %v", u.String(), err)
	}
	return nil
}

func (d *DeviceManager) GetDeviceOptions(u uuid.UUID) ([]byte, error) {
	// refresh cache from Redis, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh from Redis: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID %s", u.String())
	}
	data, err := d.client.HGet(deviceOptionsHash, u.String()).Result()
	if err != nil {
		cfg := common.CreateBaseDeviceOptions(u)
		err = d.SetDeviceOptions(u, cfg)
		if err == nil {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to get options for %s: %v", u.String(), err)
	} else {
		return []byte(data), nil
	}
}

func (d *DeviceManager) SetGlobalOptions(b []byte) error {
	// pre-flight checks to bail early
	if len(b) < 1 {
		return fmt.Errorf("empty options")
	}
	var err error
	if _, err = d.client.HSet(globalOptionsHash, globalOptionsHash, string(b)).Result(); err == nil {
		_, err = d.client.Save().Result()
	}
	if err != nil {
		return fmt.Errorf("failed to save options for %s: %v", globalOptionsHash, err)
	}
	return nil
}

func (d *DeviceManager) GetGlobalOptions() ([]byte, error) {
	data, err := d.client.HGet(globalOptionsHash, globalOptionsHash).Result()
	if err != nil {
		cfg := common.CreateBaseGlobalOptions()
		err = d.SetGlobalOptions(cfg)
		if err == nil {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to get options for %s: %v", globalOptionsHash, err)
	} else {
		return []byte(data), nil
	}
}
