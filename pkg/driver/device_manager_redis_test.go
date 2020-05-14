// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"crypto/x509"
	ax "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestURLs(t *testing.T) {
	for _, url := range []string {"redis://localhost:123/0", "redis://username:password@localhost/1", "redis://"} {
		t.Run("redis-url", func(t *testing.T) {
			var mgr DeviceManager
			for _, mgr = range GetDeviceManagers() {
				if ok, _ := mgr.Init(url, 0, 0, 0); ok {
					break
				}
			}

			assert.Equal(t, "redis", mgr.Name())
		})
	}

	for _, url := range []string {"", "foo/bar/baz", "http://google.com", "/etc/hosts", "redis://a.b:1/2/3/4"} {
		t.Run("non-redis-url", func(t *testing.T) {
			var mgr DeviceManager
			for _, mgr = range GetDeviceManagers() {
				if ok, _ := mgr.Init(url, 0, 0,0 ); ok {
					break
				}
			}

			assert.NotEqual(t, "redis", mgr.Name())
		})
	}

    redisDriver := DeviceManagerRedis{}
    redisDriver.Init("redis://localhost:12345/12", 0, 0, 0 )
    assert.Equal(t, "localhost:12345", redisDriver.Database())
}

func TestOnboardRedis(t *testing.T) {
	r := DeviceManagerRedis{}
	r.Init("redis://localhost:6379/0", 0, 0, 0)

	if r.client.FlushAll().Err() != nil {
		t.Skip("you need to run 'docker run redis' before running the rest of the tests")
	}

	// lets see if we can get a bogus cert
	assert.NotEqual(t, nil, r.OnboardCheck(&x509.Certificate{}, "foo"))

	cert := generateCert(t, "foo", "localhost")
	cert2 := generateCert(t, "bar", "vax.kremlin")
	cert3 := generateCert(t, "baz", "vax.kremlin")

	assert.Equal(t, nil, r.OnboardRegister(cert2, []string{"------"}))
	assert.Equal(t, nil, r.OnboardRegister(cert3, []string{"------"}))

	assert.Equal(t, nil, r.OnboardRegister(cert, []string{"123456", "abcdef"}))
	assert.Equal(t, nil, r.OnboardCheck(cert, "123456"))
	assert.Equal(t, nil, r.OnboardCheck(cert, "abcdef"))

	certBack, serials, err := r.OnboardGet("foo")
	assert.Equal(t, nil, err)
	assert.Equal(t, []string{"123456", "abcdef"}, serials)
	assert.Equal(t, cert, certBack)

	cns, err := r.OnboardList()
	assert.Equal(t, nil, err)
	assert.Equal(t, []string{"foo", "bar", "baz"}, cns)

	assert.Equal(t, nil, r.OnboardRemove("bar"))
	cns, err = r.OnboardList()
	assert.Equal(t, nil, err)
	assert.Equal(t, []string{"foo", "baz"}, cns)

	assert.Equal(t, nil, r.OnboardClear())
	cns, err = r.OnboardList()
	assert.Equal(t, nil, err)
	assert.Equal(t, []string{}, cns)
}

func TestDeviceRedis(t *testing.T) {
	r := DeviceManagerRedis{}
	r.Init("redis://localhost:6379/0", 0, 0, 0)

	if r.client.FlushAll().Err() != nil {
		t.Skip("you need to run 'docker run redis' before running the rest of the tests")
	}

	// lets see if we can get a bogus cert
	var nilUUID *uuid.UUID
	c, err := r.DeviceCheckCert(&x509.Certificate{})
	assert.Equal(t, nil, err)
	assert.Equal(t, nilUUID, c)

	cert := generateCert(t, "foo", "localhost")
	cert2 := generateCert(t, "bar", "vax.kremlin")
	cert3 := generateCert(t, "baz", "vax.kremlin")
	certOnboard := generateCert(t, "onboard", "vax.kremlin")

	UUID2, err := r.DeviceRegister(cert2, certOnboard, "------")
	assert.Equal(t, nil, err)
	_, err = r.DeviceRegister(cert3, certOnboard, "------")
	assert.Equal(t, nil, err)

	UUID1, err := r.DeviceRegister(cert, certOnboard, "123456")
	assert.Equal(t, nil, err)
	UUID, err := r.DeviceCheckCert(cert)
	assert.Equal(t, nil, err)
	assert.Equal(t, UUID1, UUID)

	certBack, certOnboardBack, serial, err := r.DeviceGet(UUID)
	assert.Equal(t, nil, err)
	assert.Equal(t, "123456", serial)
	assert.Equal(t, cert, certBack)
	assert.Equal(t, certOnboard, certOnboardBack)

	UUIDs, err := r.DeviceList()
	assert.Equal(t, nil, err)
	assert.Equal(t, 3, len(UUIDs))

	assert.Equal(t, nil, r.DeviceRemove(UUID2))
	UUIDs, err = r.DeviceList()
	assert.Equal(t, nil, err)
	assert.Equal(t, 2, len(UUIDs))

	assert.Equal(t, nil, r.DeviceClear())
	UUIDs, err = r.DeviceList()
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, len(UUIDs))
}

func TestConfigRedis(t *testing.T) {
	r := DeviceManagerRedis{}
	r.Init("redis://localhost:6379/0", 0, 0, 0)

	if r.client.FlushAll().Err() != nil {
		t.Skip("you need to run 'docker run redis' before running the rest of the tests")
	}

	// lets see if we can get a bogus cert
	var nilUUID *uuid.UUID
	c, err := r.DeviceCheckCert(&x509.Certificate{})
	assert.Equal(t, nil, err)
	assert.Equal(t, nilUUID, c)

	cert := generateCert(t, "kgb", "vax.kremlin")
	certOnboard := generateCert(t, "onboard", "vax.kremlin")

	UUID, err := r.DeviceRegister(cert, certOnboard, "123456")
	assert.Equal(t, nil, err)

	conf, err := r.GetConfig(*UUID)
	assert.Equal(t, nil, err)
	assert.Equal(t, UUID.String(), conf.GetId().Uuid)
	assert.Equal(t, "4", conf.GetId().Version)

	conf.Enterprise = "foo"
	assert.Equal(t, nil, r.SetConfig(*UUID, conf))

	conf, err = r.GetConfig(*UUID)
	assert.Equal(t, nil, err)
	assert.Equal(t, UUID.String(), conf.GetId().Uuid)
	assert.Equal(t, "4", conf.GetId().Version)
	assert.Equal(t, "foo", conf.GetEnterprise())
}

func TestStreamsRedis(t *testing.T) {
	r := DeviceManagerRedis{}
	r.Init("redis://localhost:6379/0", 0, 0, 0)

	if r.client.FlushAll().Err() != nil {
		t.Skip("you need to run 'docker run redis' before running the rest of the tests")
	}

	u, err := uuid.NewV4()
	if err != nil {
		return
	}

	var log logs.LogBundle
	var info info.ZInfoMsg
    var metric metrics.ZMetricMsg
	buffer := make([]byte, 1024)

	log.DevID = u.String()
	info.DevId = u.String()
	metric.DevID = u.String()

	assert.Equal(t, nil, r.WriteLogs(&log))
	assert.Equal(t, nil, r.WriteLogs(&log))
	assert.Equal(t, nil, r.WriteMetrics(&metric))
	assert.Equal(t, nil, r.WriteInfo(&info))

	lr, err := r.GetLogsReader(u)
	assert.Equal(t, nil, err)
	for _, i := range []int{103, 1, 103, 1, 0} {
		l, err := lr.Read(buffer)
		assert.Equal(t, nil, err)
		assert.Equal(t, i, l)
	}

	lr, err = r.GetInfoReader(u)
	assert.Equal(t, nil, err)
	l, err := lr.Read(buffer)
	assert.Equal(t, nil, err)
	assert.Equal(t, 96, l)
}

func generateCert(t *testing.T, cn, host string) *x509.Certificate {
	certB, _, err := ax.Generate(cn, host)
	if err != nil {
		t.Fatalf("error generating cert for tests: %v", err)
	}
	cert, err := x509.ParseCertificate(certB)
	if err != nil {
		t.Fatalf("unexpected error parsing certificate: %v", err)
	}
	return cert
}