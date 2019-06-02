package server

import (
	"crypto/x509"
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
)

type deviceManager interface {
	SetCacheTimeout(int)
	CheckOnboardCert(*x509.Certificate, string) (bool, error)
	CheckDeviceCert(*x509.Certificate) (*uuid.UUID, error)
	RegisterDeviceCert(*x509.Certificate) (*uuid.UUID, error)
	WriteInfo(*info.ZInfoMsg) error
	WriteLogs(*logs.LogBundle) error
	WriteMetrics(*metrics.ZMetricMsg) error
	GetConfig(uuid.UUID) (*config.EdgeDevConfig, error)
}
