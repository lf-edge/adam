package server

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
	// Init initialize the datastore. If the given database URL is invalid for this type of manager, return false. Return error for actual failures
	Init(string) (bool, error)
	// SetCacheTimeout set how long to keep onboard and device certificates in cache before rereading from a backing store. Value of 0 means
	//   not to cache
	SetCacheTimeout(int)
	// CheckOnboardCert check if a certificate+serial combination are valid to use for registration. Includes checking for duplicates in devices
	CheckOnboardCert(*x509.Certificate, string) (bool, error)
	// CheckDeviceCert check if a certificate is valid to use for a device
	CheckDeviceCert(*x509.Certificate) (*uuid.UUID, error)
	// RegisterDeviceCert register a new device certificate, including the onboarding certificate used to register it and its serial
	RegisterDeviceCert(*x509.Certificate, *x509.Certificate, string) (*uuid.UUID, error)
	// WriteInfo write an information message
	WriteInfo(*info.ZInfoMsg) error
	// WriteLogs write a LogBundle message
	WriteLogs(*logs.LogBundle) error
	// WriteMetrics write a MetricMsg
	WriteMetrics(*metrics.ZMetricMsg) error
	// GetConfig get the config for a given uuid
	GetConfig(uuid.UUID) (*config.EdgeDevConfig, error)
}
