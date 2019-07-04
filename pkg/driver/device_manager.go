package driver

import (
	"crypto/x509"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
)

// DeviceManager interface representing any kind of device manager with any kind of backing store
type DeviceManager interface {
	// Name return unique representative name for this type of device manager, e.g. "file", "memory", "mongo", etc.
	Name() string
	// Database safe-to-print (without credentials) path to database
	Database() string
	// Init initialize the datastore. If the given database URL is invalid for this type of manager, return false. Return error for actual failures
	Init(string) (bool, error)
	// SetCacheTimeout set how long to keep onboard and device certificates in cache before rereading from a backing store. Value of 0 means
	//   not to cache
	SetCacheTimeout(int)
	// OnboardCheck check if a certificate+serial combination are valid to use for registration. Includes checking for duplicates in devices
	OnboardCheck(*x509.Certificate, string) error
	// OnboardRemove remove an onboarding cert
	OnboardRemove(string) error
	// OnboardClear remove all onboarding certs
	OnboardClear() error
	// OnboardGet get the details for an onboarding certificate and its serials by Common Name
	OnboardGet(string) (*x509.Certificate, []string, error)
	// OnboardList list all of the known Common Names for onboard
	OnboardList() ([]string, error)
	// OnboardRegister apply an onboard cert and serials that apply to it. If the onboard cert already exists, will replace the serials and return without error. It is  idempotent.
	OnboardRegister(*x509.Certificate, []string) error
	// DeviceCheckCert check if a certificate is valid to use for a device
	DeviceCheckCert(*x509.Certificate) (*uuid.UUID, error)
	// DeviceRemove remove a device
	DeviceRemove(*uuid.UUID) error
	// DeviceClear remove all devices
	DeviceClear() error
	// DeviceGet get the details for a device based on its UUID
	DeviceGet(*uuid.UUID) (*x509.Certificate, *x509.Certificate, string, error)
	// DeviceList list all of the known UUIDs for devices
	DeviceList() ([]*uuid.UUID, error)
	// DeviceRegister register a new device certificate, including the onboarding certificate used to register it and its serial
	DeviceRegister(*x509.Certificate, *x509.Certificate, string) (*uuid.UUID, error)
	// WriteInfo write an information message
	WriteInfo(*info.ZInfoMsg) error
	// WriteLogs write a LogBundle message
	WriteLogs(*logs.LogBundle) error
	// WriteMetrics write a MetricMsg
	WriteMetrics(*metrics.ZMetricMsg) error
	// GetConfig get the config for a given uuid
	GetConfig(uuid.UUID) (*config.EdgeDevConfig, error)
	// SetConfig set the config for a given uuid
	SetConfig(uuid.UUID, *config.EdgeDevConfig) error
}

// NotFoundError error representing that an item was not found
type NotFoundError struct {
	err string
}

func (n *NotFoundError) Error() string {
	return n.err
}

// InvalidCertError error representing that a certificate is not valid
type InvalidCertError struct {
	err string
}

func (n *InvalidCertError) Error() string {
	return n.err
}

// InvalidSerialError error representing that a serial is not valid
type InvalidSerialError struct {
	err string
}

func (n *InvalidSerialError) Error() string {
	return n.err
}

// UsedSerialError error representing that a serial was used already
type UsedSerialError struct {
	err string
}

func (n *UsedSerialError) Error() string {
	return n.err
}
