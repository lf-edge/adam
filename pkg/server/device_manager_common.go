package server

import (
	"crypto/x509"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
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

