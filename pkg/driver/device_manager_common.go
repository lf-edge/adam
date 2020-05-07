// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"

	"github.com/golang/protobuf/jsonpb"
	uuid "github.com/satori/go.uuid"
)

type BigData interface {
	Get(index int) ([]byte, error)
	Read(p []byte) (int, error)
	Write(b []byte) (int, error)
}

type deviceStorage struct {
	cert       *x509.Certificate
	info       BigData
	metrics    BigData
	logs       BigData
	currentLog int
	config     *config.EdgeDevConfig
	serial     string
	onboard    *x509.Certificate
}

func (d *deviceStorage) addLog(m *logs.LogBundle) error {
	// convert the message to bytes
	buf := bytes.NewBuffer([]byte{})
	mler := jsonpb.Marshaler{}
	if err := mler.Marshal(buf, m); err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	_, err := d.logs.Write(buf.Bytes())
	return err
}
func (d *deviceStorage) addInfo(m *info.ZInfoMsg) error {
	// convert the message to bytes
	buf := bytes.NewBuffer([]byte{})
	mler := jsonpb.Marshaler{}
	if err := mler.Marshal(buf, m); err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	_, err := d.info.Write(buf.Bytes())
	return err
}
func (d *deviceStorage) addMetrics(m *metrics.ZMetricMsg) error {
	// convert the message to bytes
	buf := bytes.NewBuffer([]byte{})
	mler := jsonpb.Marshaler{}
	if err := mler.Marshal(buf, m); err != nil {
		return fmt.Errorf("failed to marshal protobuf message into json: %v", err)
	}
	_, err := d.metrics.Write(buf.Bytes())
	return err
}

func createBaseConfig(u uuid.UUID) *config.EdgeDevConfig {
	return &config.EdgeDevConfig{
		Id: &config.UUIDandVersion{
			Uuid:    u.String(),
			Version: "4",
		},
	}
}
