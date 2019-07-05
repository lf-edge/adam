// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"crypto/x509"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/satori/go.uuid"
)

type deviceStorage struct {
	cert    *x509.Certificate
	info    []*info.ZInfoMsg
	metrics []*metrics.ZMetricMsg
	logs    []*logs.LogBundle
	config  *config.EdgeDevConfig
	serial  string
	onboard *x509.Certificate
}

func createBaseConfig(u uuid.UUID) *config.EdgeDevConfig {
	return &config.EdgeDevConfig{
		Id: &config.UUIDandVersion{
			Uuid:    u.String(),
			Version: "4",
		},
	}
}
