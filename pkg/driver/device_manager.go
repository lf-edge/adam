// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"crypto/x509"
	"io"

	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
)

const (
	KB = 1024
	MB = 1024 * KB
	GB = 1024 * MB
	TB = 1024 * GB
)

// DeviceManager interface representing any kind of device manager with any kind of backing store
type DeviceManager interface {
	// Name return unique representative name for this type of device manager, e.g. "file", "memory", "mongo", etc.
	Name() string
	// MaxLogSize return the default maximum log size in bytes for this device manager
	MaxLogSize() int
	// MaxInfoSize return the default maximum info size in bytes for this device manager
	MaxInfoSize() int
	// MaxMetricSize return the default maximum metric size in bytes for this device manager
	MaxMetricSize() int
	// MaxRequestsSize return the default maximum request logs size in bytes for this device manager
	MaxRequestsSize() int
	// Database safe-to-print (without credentials) path to database
	Database() string
	// Init initialize the datastore. If the given database URL is invalid for this type of manager, return false. Return error for actual failures
	Init(string, int, int, int, int) (bool, error)
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
	// WriteRequest record a request that was made, including the remote IP, x-forwarded-for header, and path
	WriteRequest(common.ApiRequest) error
	// GetConfig get the config for a given uuid
	GetConfig(uuid.UUID) (*config.EdgeDevConfig, error)
	// SetConfig set the config for a given uuid
	SetConfig(uuid.UUID, *config.EdgeDevConfig) error
	// GetConfig get the config for a given uuid
	GetConfigResponse(uuid.UUID) (*config.ConfigResponse, error)
	// GetLogsReader get the logs for a given uuid
	GetLogsReader(u uuid.UUID) (io.Reader, error)
	// GetInfoReader get the info for a given uuid
	GetInfoReader(u uuid.UUID) (io.Reader, error)
	// GetRequestsReader get the request logs for a given uuid
	GetRequestsReader(u uuid.UUID) (io.Reader, error)
}
