// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/vmihailenco/msgpack/v4"

	ax "github.com/lf-edge/adam/pkg/x509"
	uuid "github.com/satori/go.uuid"
)

const (
	MB                      = common.MB
	maxLogSizePostgres      = 100 * MB
	maxInfoSizePostgres     = 100 * MB
	maxMetricSizePostgres   = 100 * MB
	maxRequestsSizePostgres = 100 * MB
	maxAppLogsSizePostgres  = 100 * MB
)

//DBType to write objects into DB
type DBType string

const (
	DBTypeLog     DBType = "log"
	DBTypeInfo    DBType = "info"
	DBTypeMetric  DBType = "metric"
	DBTypeRequest DBType = "request"
	DBTypeAppLog  DBType = "applog"
)

// ManagedStream stream of data interface
type ManagedStream struct {
	variant DBType
	id      uuid.UUID
	client  *pgxpool.Pool
}

func (m *ManagedStream) Get(_ int) ([]byte, error) {
	return nil, errors.New("unsupported")
}

func (m *ManagedStream) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	switch m.variant {
	case DBTypeLog, DBTypeInfo, DBTypeMetric, DBTypeRequest, DBTypeAppLog:
		row := m.client.QueryRow(context.Background(),
			fmt.Sprintf("INSERT INTO %s (ref, data) VALUES($1, $2) RETURNING id", m.variant), m.id.String(), b)
		if row == nil {
			return 0, fmt.Errorf("cannot insert row: %s", m.variant)
		}
		var id uint32
		if err := row.Scan(&id); err != nil {
			return 0, fmt.Errorf("cannot scan id: %s", err)
		}
		notification, err := json.Marshal(map[string]string{"id": fmt.Sprint(id), "ref": m.id.String()})
		if err != nil {
			return 0, err
		}
		if _, err := m.client.Exec(context.Background(),
			fmt.Sprintf("NOTIFY %s, '%s'", m.variant, notification)); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("not implemented: %s", m.variant)
	}
	return len(b), nil
}

func (m *ManagedStream) Reader() (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}

// DeviceManager implementation of DeviceManager interface with a Postgres DB as the backing store
type DeviceManager struct {
	client       *pgxpool.Pool
	database     string
	cacheTimeout int
	lastUpdate   time.Time
	// these are for caching only
	onboardCerts map[string]map[string]bool
	deviceCerts  map[string]uuid.UUID
	devices      map[uuid.UUID]common.DeviceStorage
}

// Name return name
func (d *DeviceManager) Name() string {
	return "postgres"
}

// Database return database hostname and port
func (d *DeviceManager) Database() string {
	return d.database
}

// MaxLogSize return the default maximum log size in bytes for this device manager
func (d *DeviceManager) MaxLogSize() int {
	return maxLogSizePostgres
}

// MaxInfoSize return the default maximum info size in bytes for this device manager
func (d *DeviceManager) MaxInfoSize() int {
	return maxInfoSizePostgres
}

// MaxMetricSize return the maximum metrics size in bytes for this device manager
func (d *DeviceManager) MaxMetricSize() int {
	return maxMetricSizePostgres
}

// MaxRequestsSize return the maximum requests log size in bytes for this device manager
func (d *DeviceManager) MaxRequestsSize() int {
	return maxRequestsSizePostgres
}

// MaxAppLogsSize return the maximum app logs size in bytes for this device manager
func (d *DeviceManager) MaxAppLogsSize() int {
	return maxAppLogsSizePostgres
}

// Init check if a URL is valid and initialize
func (d *DeviceManager) Init(s string, _ common.MaxSizes) (bool, error) {
	URL, err := url.Parse(s)
	if err != nil || URL.Scheme != "postgres" {
		return false, err
	}
	d.database = "postgres"
	for {
		d.client, err = pgxpool.Connect(context.Background(), s)
		if err != nil {
			time.Sleep(5 * time.Second)
			fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
			continue
		}
		break
	}
	if err := createSchema(d.client); err != nil {
		return false, err
	}
	return true, nil
}

// createSchema creates database schema for User and Story models.
func createSchema(db *pgxpool.Pool) error {
	if _, err := db.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS device
(id uuid PRIMARY KEY, 
cert bytea,
onboard bytea,
serial text,
config jsonb)`); err != nil {
		return err
	}
	if _, err := db.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS onboard
(id text PRIMARY KEY, 
cert bytea,
serials bytea)`); err != nil {
		return err
	}
	if _, err := db.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS app
(id uuid PRIMARY KEY, 
ref uuid,
CONSTRAINT fk_app
   FOREIGN KEY(ref) 
   REFERENCES device(id)
   ON DELETE CASCADE)`); err != nil {
		return err
	}
	for _, el := range []DBType{DBTypeLog, DBTypeInfo, DBTypeMetric, DBTypeRequest} {
		if _, err := db.Exec(context.Background(), fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s
(id SERIAL PRIMARY KEY, 
ref uuid,
data jsonb,
CONSTRAINT fk_%s
   FOREIGN KEY(ref) 
   REFERENCES device(id)
   ON DELETE CASCADE)`, el, el)); err != nil {
			return err
		}
	}
	if _, err := db.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS applog
(id SERIAL PRIMARY KEY, 
ref uuid,
data jsonb,
CONSTRAINT fk_applog
   FOREIGN KEY(ref) 
   REFERENCES app(id)
   ON DELETE CASCADE)`); err != nil {
		return err
	}
	return nil
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
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Postgres: %v", err)
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

	cert, serials, err := d.readCertOnboard(cn)
	if err != nil {
		return nil, nil, err
	}
	return cert, serials, nil
}

// OnboardList list all of the known Common Names for onboard
func (d *DeviceManager) OnboardList() ([]string, error) {
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Postgres: %v", err)
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
	if _, err := d.client.Exec(context.Background(), "DELETE FROM onboard WHERE id = $1", cn); err != nil {
		return err
	}
	return nil
}

// OnboardClear remove all onboarding certs
func (d *DeviceManager) OnboardClear() error {
	if _, err := d.client.Exec(context.Background(), "DELETE FROM onboard"); err != nil {
		return err
	}

	d.onboardCerts = map[string]map[string]bool{}
	return nil
}

// DeviceCheckCert see if a particular certificate is a valid registered device certificate
func (d *DeviceManager) DeviceCheckCert(cert *x509.Certificate) (*uuid.UUID, error) {
	if cert == nil {
		return nil, fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}
	certStr := string(cert.Raw)
	if u, ok := d.deviceCerts[certStr]; ok {
		return &u, nil
	}
	return nil, nil
}

// DeviceRemove remove a device
func (d *DeviceManager) DeviceRemove(u *uuid.UUID) error {
	if _, err := d.client.Exec(context.Background(), "DELETE FROM device WHERE id = $1", u.String()); err != nil {
		return err
	}
	// refresh the cache
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh device cache: %v", err)
	}
	return nil
}

// DeviceClear remove all devices
func (d *DeviceManager) DeviceClear() error {
	if _, err := d.client.Exec(context.Background(), "DELETE FROM device"); err != nil {
		return err
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

	row := d.client.QueryRow(context.Background(), "SELECT cert, onboard, serial FROM device where id = $1", u.String())
	var cert []byte
	var onboard []byte
	serial := ""
	if err := row.Scan(&cert, &onboard, &serial); err != nil {
		return nil, nil, "", err
	}

	devCert, err := ax.ParseCert(cert)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error decoding device certificate for %s: %v (%s)", u.String(), err, cert)
	}

	onboardCert, err := ax.ParseCert(onboard)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error decoding onboard certificate for %s: %v (%s)", u.String(), err, onboard)
	}
	// somehow device serials are best effort
	return devCert, onboardCert, serial, nil
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManager) DeviceList() ([]*uuid.UUID, error) {
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Postgres: %v", err)
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
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Postgres: %v", err)
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
	if _, err := d.client.Exec(context.Background(), "INSERT INTO device(id, cert, onboard, serial, config) VALUES ($1,$2,$3,$4,$5)",
		unew.String(), ax.PemEncodeCert(cert.Raw), ax.PemEncodeCert(onboard.Raw), serial, conf); err != nil {
		return fmt.Errorf("failed to save config for %s: %v", u.String(), err)
	}

	// save new one to cache - just the serial and onboard; the rest is on disk
	d.deviceCerts[string(cert.Raw)] = unew
	d.devices[unew] = d.initDevice(unew, onboard, serial)
	ds := d.devices[unew]

	// create the necessary Postgres streams for this device
	for _, ms := range []common.BigData{ds.Logs, ds.Info, ds.Metrics, ds.Requests} {
		if _, err := ms.Write([]byte("")); err != nil {
			return fmt.Errorf("error creating stream: %v", err)
		}
	}

	return nil
}

// initDevice initialize a device
func (d *DeviceManager) initDevice(id uuid.UUID, onboard *x509.Certificate, serial string) common.DeviceStorage {
	return common.DeviceStorage{
		Onboard: onboard,
		Serial:  serial,
		Logs: &ManagedStream{
			variant: DBTypeLog,
			id:      id,
			client:  d.client,
		},
		Info: &ManagedStream{
			variant: DBTypeInfo,
			id:      id,
			client:  d.client,
		},
		Metrics: &ManagedStream{
			variant: DBTypeMetric,
			id:      id,
			client:  d.client,
		},
		Requests: &ManagedStream{
			variant: DBTypeRequest,
			id:      id,
			client:  d.client,
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

	if err := d.writeCertOnboard(cert.Raw, cn, serial); err != nil {
		return err
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
		return dev.AddRequest(b)
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
		if _, err := d.client.Exec(context.Background(), "INSERT INTO app(id,ref) VALUES ($1,$2)", instanceID.String(), deviceID.String()); err != nil {
			return fmt.Errorf("cannot create app: %s", err)
		}
		d.devices[deviceID].AppLogs[instanceID] = &ManagedStream{
			variant: DBTypeAppLog,
			id:      instanceID,
			client:  d.client,
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

// GetConfig retrieve the config for a particular device
func (d *DeviceManager) GetConfig(u uuid.UUID) ([]byte, error) {

	row := d.client.QueryRow(context.Background(), "SELECT config FROM device where id = $1", u.String())
	var config []byte
	if err := row.Scan(&config); err != nil {
		return nil, err
	}
	return config, nil
}

// SetConfig set the config for a particular device
func (d *DeviceManager) SetConfig(u uuid.UUID, b []byte) error {
	// pre-flight checks to bail early
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}

	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if _, err := d.client.Exec(context.Background(), "UPDATE device SET config = $1 WHERE id = $2",
		b, u.String()); err != nil {
		return fmt.Errorf("failed to save config for %s: %v", u.String(), err)
	}
	return nil
}

// GetLogsReader get the logs for a given uuid
func (d *DeviceManager) GetLogsReader(u uuid.UUID) (io.Reader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Logs.Reader()
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManager) GetInfoReader(u uuid.UUID) (io.Reader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Info.Reader()
}

// GetRequestsReader get the requests for a given uuid
func (d *DeviceManager) GetRequestsReader(u uuid.UUID) (io.Reader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Requests.Reader()
}

// refreshCache refresh cache from disk
func (d *DeviceManager) refreshCache() error { // is it time to update the cache again?
	now := time.Now()
	if now.Sub(d.lastUpdate).Seconds() < float64(d.cacheTimeout) {
		return nil
	}

	// create new vars to hold while we load
	onboardCerts := make(map[string]map[string]bool)
	deviceCerts := make(map[string]uuid.UUID)
	devices := make(map[uuid.UUID]common.DeviceStorage)

	rows1, err := d.client.Query(context.Background(), "select cert, serials FROM onboard")
	if err != nil {
		return fmt.Errorf("failed to retrieve onboarding certificates %v", err)
	}
	defer rows1.Close()
	for rows1.Next() {
		var certBytes []byte
		var serialsBytes []byte
		if err := rows1.Scan(&certBytes, &serialsBytes); err != nil {
			return err
		}
		certPem, _ := pem.Decode(certBytes)
		if certPem == nil {
			return fmt.Errorf("unable to convert data from %s", certBytes)
		}
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from %s to onboard certificate: %v", certBytes, err)
		}
		certStr := string(cert.Raw)

		onboardCerts[certStr] = make(map[string]bool)

		var serials []string
		err = msgpack.Unmarshal(serialsBytes, &serials)
		if err != nil {
			return fmt.Errorf("unable to unmarshal onboard serials %s: %v", serialsBytes, err)
		}
		for _, serial := range serials {
			onboardCerts[certStr][serial] = true
		}
	}
	if err = rows1.Err(); err != nil {
		return err
	}
	// replace the existing onboard certificates
	d.onboardCerts = onboardCerts

	rows2, err := d.client.Query(context.Background(), "select id, cert, onboard, serial, config FROM device")
	if err != nil {
		return fmt.Errorf("failed to retrieve devices %v", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var id string
		var certBytes []byte
		var onboardBytes []byte
		var serial string
		var configBytes []byte
		if err := rows2.Scan(&id, &certBytes, &onboardBytes, &serial, &configBytes); err != nil {
			return err
		}
		// load the device certificate
		certPem, _ := pem.Decode(certBytes)
		if certPem == nil {
			return fmt.Errorf("unable to convert data from %s", certBytes)
		}
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from %s to device certificate: %v", certBytes, err)
		}
		certStr := string(cert.Raw)
		u, err := uuid.FromString(id)
		if err != nil {
			return fmt.Errorf("unable to convert data from uuid %v", err)
		}
		deviceCerts[certStr] = u
		devices[u] = d.initDevice(u, cert, serial) // start with no serial, as it will be added further down

		certPem, _ = pem.Decode(onboardBytes)
		cert, err = x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from %s to device onboard certificate: %v", onboardBytes, err)
		}
		// because of the "cannot assign to struct field" golang issue
		devItem := devices[u]
		devItem.Onboard = cert
		devItem.Config = configBytes
		devices[u] = devItem
	}
	if err = rows2.Err(); err != nil {
		return err
	}
	// replace the existing device certificates
	d.deviceCerts = deviceCerts

	rows3, err := d.client.Query(context.Background(), "select id, ref FROM app")
	if err != nil {
		return fmt.Errorf("failed to retrieve devices %v", err)
	}
	defer rows3.Close()
	for rows3.Next() {
		var id string
		var di string
		if err := rows3.Scan(&id, &di); err != nil {
			return err
		}
		u, err := uuid.FromString(id)
		if err != nil {
			return fmt.Errorf("unable to convert data from uuid %v", err)
		}
		du, err := uuid.FromString(di)
		if err != nil {
			return fmt.Errorf("unable to convert data from uuid %v", err)
		}
		devices[du].AppLogs[u] = &ManagedStream{
			variant: DBTypeAppLog,
			id:      u,
			client:  d.client,
		}
	}
	if err = rows3.Err(); err != nil {
		return err
	}
	// replace the existing device cache
	d.devices = devices

	// mark the time we updated
	d.lastUpdate = now
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

func (d *DeviceManager) readCertOnboard(cn string) (*x509.Certificate, []string, error) {

	row := d.client.QueryRow(context.Background(), "SELECT cert, serials FROM onboard WHERE id = $1", cn)
	var certBytes []byte
	var serialsBytes []byte
	if err := row.Scan(&certBytes, &serialsBytes); err != nil {
		return nil, nil, err
	}
	var serials []string
	err := msgpack.Unmarshal(serialsBytes, &serials)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to unmarshal onboard serials %s: %v", serialsBytes, err)
	}

	if cert, err := ax.ParseCert(certBytes); err != nil {
		return nil, nil, fmt.Errorf("error decoding onboard certificate for %s: %v (%s)", cn, err, certBytes)
	} else {
		return cert, serials, nil
	}
}

// WriteCert write cert bytes to a path, after pem encoding them
func (d *DeviceManager) writeCertOnboard(cert []byte, cn string, serials []string) error {
	// make sure we have the paths we need, and that they are not already taken, unless we were told to force
	row := d.client.QueryRow(context.Background(), "SELECT exists (SELECT true FROM onboard where id = $1)", cn)
	var exists bool
	if err := row.Scan(&exists); err != nil {
		return err
	}
	certPem := ax.PemEncodeCert(cert)
	if certPem == nil {
		return fmt.Errorf("cannot decode cert: %s", cert)
	}
	v, err := msgpack.Marshal(&serials)
	if err != nil {
		return fmt.Errorf("failed to serialize serials %v: %v", serials, err)
	}
	if !exists {
		if _, err := d.client.Exec(context.Background(), "INSERT INTO onboard(id,cert,serials) VALUES ($1,$2,$3)", cn, certPem, v); err != nil {
			return fmt.Errorf("cannot create onboard: %s", err)
		}
	} else {
		if _, err := d.client.Exec(context.Background(), "UPDATE onboard SET cert = $1, serials = $2 WHERE id = $3", certPem, v, cn); err != nil {
			return fmt.Errorf("cannot update onboard: %s", err)
		}
	}

	return nil
}
