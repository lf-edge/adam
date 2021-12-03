// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/lf-edge/eve/api/go/certs"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/logs"

	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	KB = 1024
	MB = 1024 * KB
)

// MaxSizes defines maximum sizes of objects storage
type MaxSizes struct {
	MaxLogSize         int
	MaxInfoSize        int
	MaxMetricSize      int
	MaxRequestsSize    int
	MaxAppLogsSize     int
	MaxFlowMessageSize int
}

type BigData interface {
	Get(index int) ([]byte, error)
	Reader() (io.Reader, error)
	Write(b []byte) (int, error)
}

type DeviceStorage struct {
	Cert        *x509.Certificate
	Info        BigData
	Metrics     BigData
	Logs        BigData
	Requests    BigData
	FlowMessage BigData
	Certs       BigData
	AppLogs     map[uuid.UUID]BigData
	CurrentLog  int
	Config      []byte
	ATtestCerts []byte
	StorageKeys []byte
	Serial      string
	Onboard     *x509.Certificate
}

type FullCertsEntry struct {
	*logs.LogEntry
	Image      string `json:"image,omitempty"`      // SW image the log got emitted from
	EveVersion string `json:"eveVersion,omitempty"` // EVE software version
}

type FullLogEntry struct {
	*logs.LogEntry
	Image      string `json:"image,omitempty"`      // SW image the log got emitted from
	EveVersion string `json:"eveVersion,omitempty"` // EVE software version
}

type Zcerts struct {
	Certs []*certs.ZCert `json:"certs,omitempty"` // EVE device certs
}

// Bytes convenience to convert to json bytes
func (f FullLogEntry) Json() ([]byte, error) {
	return protojson.Marshal(f)
}

func (d *DeviceStorage) AddLogs(b []byte) error {
	// what if the device was not initialized yet?
	if d.Logs == nil {
		return errors.New("AddLog: Logs struct not yet initialized")
	}
	_, err := d.Logs.Write(b)
	return err
}
func (d *DeviceStorage) AddAppLog(instanceID uuid.UUID, b []byte) error {
	// what if the device was not initialized yet?
	if d.AppLogs == nil {
		return fmt.Errorf("AddAppLog: AppLogs struct not yet initialized")
	}
	if _, ok := d.AppLogs[instanceID]; !ok {
		return fmt.Errorf("AddAppLog: AppLogs for instance %s not yet initialized", instanceID)
	}
	_, err := d.AppLogs[instanceID].Write(b)
	return err
}
func (d *DeviceStorage) AddInfo(b []byte) error {
	// what if the device was not initialized yet?
	if d.Info == nil {
		return errors.New("AddInfo: Info struct not yet initialized")
	}
	_, err := d.Info.Write(b)
	return err
}
func (d *DeviceStorage) AddMetrics(b []byte) error {
	// what if the device was not initialized yet?
	if d.Metrics == nil {
		return errors.New("AddMetrics: Metrics struct not yet initialized")
	}
	_, err := d.Metrics.Write(b)
	return err
}

func (d *DeviceStorage) AddRequest(b []byte) error {
	// what if the device was not initialized yet?
	if d.Requests == nil {
		return errors.New("AddRequest: Requests struct not yet initialized")
	}
	_, err := d.Requests.Write(b)
	return err
}

func (d *DeviceStorage) AddFlowRecord(b []byte) error {
	// what if the device was not initialized yet?
	if d.FlowMessage == nil {
		return errors.New("AddFlowRecord: FlowMessage struct not yet initialized")
	}
	_, err := d.FlowMessage.Write(b)
	return err
}

func CreateBaseConfig(u uuid.UUID) []byte {
	conf := &config.EdgeDevConfig{
		Id: &config.UUIDandVersion{
			Uuid:    u.String(),
			Version: "4",
		},
	}
	// we ignore the error because it is tightly controlled
	// we probably should handle it, but then we have to do it with everything downstream
	// eventually
	b, _ := protojson.Marshal(conf)
	return b
}
