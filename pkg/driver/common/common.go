// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"

	"github.com/golang/protobuf/jsonpb"
	uuid "github.com/satori/go.uuid"
)

const (
	KB = 1024
	MB = 1024 * KB
)

type BigData interface {
	Get(index int) ([]byte, error)
	Reader() (io.Reader, error)
	Write(b []byte) (int, error)
}

type ApiRequest struct {
	Timestamp time.Time `json:"timestamp"`
	UUID      uuid.UUID `json:"uuid,omitempty"`
	ClientIP  string    `json:"client-ip"`
	Forwarded string    `json:"forwarded,omitempty"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
}

type DeviceStorage struct {
	Cert       *x509.Certificate
	Info       BigData
	Metrics    BigData
	Logs       BigData
	Requests   BigData
	CurrentLog int
	Config     *config.EdgeDevConfig
	Serial     string
	Onboard    *x509.Certificate
}

func (d *DeviceStorage) AddLog(m *logs.LogBundle) error {
	// convert the message to bytes
	buf := bytes.NewBuffer([]byte{})
	mler := jsonpb.Marshaler{}
	if err := mler.Marshal(buf, m); err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	_, err := d.Logs.Write(buf.Bytes())
	return err
}
func (d *DeviceStorage) AddInfo(m *info.ZInfoMsg) error {
	// convert the message to bytes
	buf := bytes.NewBuffer([]byte{})
	mler := jsonpb.Marshaler{}
	if err := mler.Marshal(buf, m); err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	_, err := d.Info.Write(buf.Bytes())
	return err
}
func (d *DeviceStorage) AddMetrics(m *metrics.ZMetricMsg) error {
	// convert the message to bytes
	buf := bytes.NewBuffer([]byte{})
	mler := jsonpb.Marshaler{}
	if err := mler.Marshal(buf, m); err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	_, err := d.Metrics.Write(buf.Bytes())
	return err
}

func (d *DeviceStorage) AddRequest(m *ApiRequest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshall request struct to json: %v", err)
	}
	_, err = d.Requests.Write(b)
	return err
}

func CreateBaseConfig(u uuid.UUID) *config.EdgeDevConfig {
	return &config.EdgeDevConfig{
		Id: &config.UUIDandVersion{
			Uuid:    u.String(),
			Version: "4",
		},
	}
}
