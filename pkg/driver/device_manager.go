// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"crypto/x509"
	"io"

	"github.com/lf-edge/adam/pkg/driver/common"
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
	// MaxFlowMessageSize return the default maximum FlowMessage logs size in bytes for this device manager
	MaxFlowMessageSize() int
	// MaxAppLogsSize return the default maximum app logs size in bytes for this device manager
	MaxAppLogsSize() int
	// Database safe-to-print (without credentials) path to database
	Database() string
	// Init initialize the datastore. If the given database URL is invalid for this type of manager, return false. Return error for actual failures
	Init(string, common.MaxSizes) (bool, error)
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
	// DeviceCheckCertHash check if a certificate hash is valid to use for a device
	DeviceCheckCertHash([]byte) (*uuid.UUID, error)
	// DeviceRemove remove a device
	DeviceRemove(*uuid.UUID) error
	// DeviceClear remove all devices
	DeviceClear() error
	// DeviceGet get the details for a device based on its UUID
	DeviceGet(*uuid.UUID) (*x509.Certificate, *x509.Certificate, string, error)
	// DeviceList list all of the known UUIDs for devices
	DeviceList() ([]*uuid.UUID, error)
	// DeviceRegister register a new device certificate, including the onboarding certificate used to register it and its serial
	DeviceRegister(uuid.UUID, *x509.Certificate, *x509.Certificate, string, []byte) error
	// WriteCerts write an attestation certs information
	WriteCerts(uuid.UUID, []byte) error
	// WriteStorageKeys write storage keys information
	WriteStorageKeys(uuid.UUID, []byte) error
	// WriteInfo write an information message
	WriteInfo(uuid.UUID, []byte) error
	// WriteLogs write log messages
	WriteLogs(uuid.UUID, []byte) error
	// WriteFlowMessage write FlowMessage
	WriteFlowMessage(uuid.UUID, []byte) error
	// WriteAppInstanceLogs write a AppInstanceLogBundle message for instanceID
	WriteAppInstanceLogs(instanceID uuid.UUID, deviceID uuid.UUID, b []byte) error
	// WriteMetrics write a MetricMsg
	WriteMetrics(uuid.UUID, []byte) error
	// WriteRequest record a request that was made, including the remote IP, x-forwarded-for header, and path
	WriteRequest(uuid.UUID, []byte) error
	// SetDeviceOptions stores device options for a particular device
	SetDeviceOptions(uuid.UUID, []byte) error
	// SetGlobalOptions stores global options
	SetGlobalOptions([]byte) error
	// GetConfig get the config for a given uuid
	// if not found will use handler to populate
	GetConfig(uuid.UUID, common.CreateBaseConfigHandler) ([]byte, error)
	// SetConfig set the config for a given uuid
	SetConfig(uuid.UUID, []byte) error
	// GetUUID get the UuidResponse for a given uuid
	GetUUID(uuid.UUID) ([]byte, error)
	// GetLogsReader get the logs for a given uuid
	GetLogsReader(u uuid.UUID) (io.Reader, error)
	// GetInfoReader get the info for a given uuid
	GetInfoReader(u uuid.UUID) (io.Reader, error)
	// GetRequestsReader get the request logs for a given uuid
	GetRequestsReader(u uuid.UUID) (io.Reader, error)
	// GetCerts retrieve the attest certs for a particular device
	GetCerts(uid uuid.UUID) ([]byte, error)
	// GetStorageKeys retrieve storage keys for a particular device
	GetStorageKeys(uid uuid.UUID) ([]byte, error)
	// GetDeviceOptions retrieve device options for a particular device
	GetDeviceOptions(uuid.UUID) ([]byte, error)
	// GetGlobalOptions retrieve global options
	GetGlobalOptions() ([]byte, error)
}
