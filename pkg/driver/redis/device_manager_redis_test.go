// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/adam/pkg/util"
	ax "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve-api/go/config"
	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/metrics"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestInit(t *testing.T) {
	redisDriver := DeviceManager{}
	redisDriver.Init("redis://localhost:12345/12", common.MaxSizes{})
	assert.Equal(t, "localhost:12345", redisDriver.Database())
}

func TestOnboardRedis(t *testing.T) {
	r := DeviceManager{}
	r.Init("redis://localhost:6379/0", common.MaxSizes{})

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
	assert.ElementsMatch(t, []string{"foo", "bar", "baz"}, cns)

	assert.Equal(t, nil, r.OnboardRemove("bar"))
	cns, err = r.OnboardList()
	assert.Equal(t, nil, err)
	assert.ElementsMatch(t, []string{"foo", "baz"}, cns)

	assert.Equal(t, nil, r.OnboardClear())
	cns, err = r.OnboardList()
	assert.Equal(t, nil, err)
	assert.Equal(t, []string{}, cns)
}

func TestDeviceRedis(t *testing.T) {
	r := DeviceManager{}
	r.Init("redis://localhost:6379/0", common.MaxSizes{})

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

	UUID2, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("unable to generate new UUID: %v", err)
	}
	err = r.DeviceRegister(UUID2, cert2, certOnboard, "------", common.CreateBaseConfig(UUID2))
	assert.Equal(t, nil, err)
	UUID3, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("unable to generate new UUID: %v", err)
	}
	err = r.DeviceRegister(UUID3, cert3, certOnboard, "------", common.CreateBaseConfig(UUID3))
	assert.Equal(t, nil, err)

	UUID1, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("unable to generate new UUID: %v", err)
	}
	err = r.DeviceRegister(UUID1, cert, certOnboard, "123456", common.CreateBaseConfig(UUID1))
	assert.Equal(t, nil, err)
	UUID, err := r.DeviceCheckCert(cert)
	assert.Equal(t, nil, err)
	assert.Equal(t, UUID1, *UUID)

	certBack, certOnboardBack, serial, err := r.DeviceGet(UUID)
	assert.Equal(t, nil, err)
	assert.Equal(t, "123456", serial)
	assert.Equal(t, cert, certBack)
	assert.Equal(t, certOnboard, certOnboardBack)

	uuidResponse, err := r.GetUUID(*UUID)
	assert.Equal(t, nil, err)

	var ur eveuuid.UuidResponse
	err = proto.Unmarshal(uuidResponse, &ur)
	assert.Equal(t, nil, err)
	assert.Equal(t, ur.GetUuid(), UUID.String())

	UUIDs, err := r.DeviceList()
	assert.Equal(t, nil, err)
	assert.Equal(t, 3, len(UUIDs))

	assert.Equal(t, nil, r.DeviceRemove(&UUID2))
	UUIDs, err = r.DeviceList()
	assert.Equal(t, nil, err)
	assert.Equal(t, 2, len(UUIDs))

	assert.Equal(t, nil, r.DeviceClear())
	UUIDs, err = r.DeviceList()
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, len(UUIDs))
}

func TestConfigRedis(t *testing.T) {
	r := DeviceManager{}
	r.Init("redis://localhost:6379/0", common.MaxSizes{})

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

	UUID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("unable to generate new UUID: %v", err)
	}
	err = r.DeviceRegister(UUID, cert, certOnboard, "123456", common.CreateBaseConfig(UUID))
	assert.Equal(t, nil, err)

	conf, err := r.GetConfig(UUID)
	assert.Equal(t, nil, err)
	// convert to struct
	var msg config.EdgeDevConfig
	if err := proto.Unmarshal(conf, &msg); err != nil {
		t.Fatalf("error converting device config bytes to struct: %v", err)
	}

	assert.Equal(t, UUID.String(), msg.GetId().Uuid)
	assert.Equal(t, "4", msg.GetId().Version)

	// convert to bytes
	conf, err = protojson.Marshal(&msg)
	if err != nil {
		t.Fatalf("error converting device config struct to bytes: %v", err)
	}

	assert.Equal(t, nil, r.SetConfig(UUID, conf))

	conf, err = r.GetConfig(UUID)
	// convert to struct
	if err := protojson.Unmarshal(conf, &msg); err != nil {
		t.Fatalf("error converting device config bytes to struct: %v", err)
	}

	assert.Equal(t, nil, err)
	assert.Equal(t, UUID.String(), msg.GetId().Uuid)
	assert.Equal(t, "4", msg.GetId().Version)
}

func TestStreamsRedis(t *testing.T) {
	r := DeviceManager{}
	r.Init("redis://localhost:6379/0", common.MaxSizes{})

	if r.client.FlushAll().Err() != nil {
		t.Skip("you need to run 'docker run redis' before running the rest of the tests")
	}

	u, err := uuid.NewV4()
	if err != nil {
		return
	}

	cert := generateCert(t, "cert", "host")
	certOnboard := generateCert(t, "onboard", "host")

	err = r.DeviceRegister(u, cert, certOnboard, "123456", common.CreateBaseConfig(u))
	assert.Equal(t, nil, err)

	var (
		b      []byte
		log    []byte
		infos  []byte
		metric []byte
	)
	buffer := make([]byte, 1024)

	// logs
	b, err = common.FullLogEntry{}.Json()
	if err != nil {
		t.Fatalf("error converting entry to json: %v", err)
	}
	log = append(log, b...)

	// info
	b, err = util.ProtobufToBytes(&info.ZInfoMsg{
		DevId: u.String(),
	})
	if err != nil {
		t.Fatalf("error converting entry to json: %v", err)
	}
	infos = append(infos, b...)

	// metrics
	b, err = util.ProtobufToBytes(&metrics.ZMetricMsg{
		DevID: u.String(),
	})
	if err != nil {
		t.Fatalf("error converting entry to json: %v", err)
	}
	metric = append(metric, b...)

	assert.Equal(t, nil, r.WriteLogs(u, log))
	assert.Equal(t, nil, r.WriteLogs(u, log))
	assert.Equal(t, nil, r.WriteMetrics(u, metric))
	assert.Equal(t, nil, r.WriteInfo(u, infos))

	chunkReader, err := r.GetLogsReader(u)
	assert.Equal(t, nil, err)
	for {
		lr, s, err := chunkReader.Next()
		if lr == nil {
			break
		}
		assert.Equal(t, nil, err)
		l, err := lr.Read(buffer)
		assert.Equal(t, nil, err)
		assert.Equal(t, int64(l), s)
	}

	chunkReader, err = r.GetInfoReader(u)
	assert.Equal(t, nil, err)
	for {
		lr, s, err := chunkReader.Next()
		if lr == nil {
			break
		}
		assert.Equal(t, nil, err)
		l, err := lr.Read(buffer)
		assert.Equal(t, nil, err)
		assert.Equal(t, int64(l), s)
	}

	r.transactionDrop([][]string{
		{deviceInfoStream + u.String()},
		{deviceLogsStream + u.String()},
		{deviceMetricsStream + u.String()},
		{deviceRequestsStream + u.String()},
	})
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

func TestDeviceManagerRedisConcurrency(t *testing.T) {
	setup := func(t *testing.T, n int) (*DeviceManager, []uuid.UUID) {
		t.Helper()
		d := &DeviceManager{}
		if _, err := d.Init("redis://localhost:6379/0", common.MaxSizes{}); err != nil {
			t.Fatalf("Init: %v", err)
		}
		if d.client.FlushAll().Err() != nil {
			t.Skip("you need to run 'docker run redis' before running the rest of the tests")
		}
		uids := make([]uuid.UUID, n)
		for i := range uids {
			uids[i], _ = uuid.NewV4()
			certB, _, err := ax.Generate(fmt.Sprintf("device-%d", i), "")
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			cert, err := x509.ParseCertificate(certB)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if err := d.DeviceRegister(uids[i], cert, nil, "", common.CreateBaseConfig(uids[i])); err != nil {
				t.Fatalf("DeviceRegister: %v", err)
			}
		}
		return d, uids
	}

	t.Run("ConcurrentWritesDifferentDevices", func(t *testing.T) {
		d, uids := setup(t, 3)
		payload := []byte("data")
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteInfo(uids[0], payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteLogs(uids[1], payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteMetrics(uids[2], payload)
			}
		}()
		wg.Wait()
	})

	t.Run("ConcurrentWriteTypesSameDevice", func(t *testing.T) {
		d, uids := setup(t, 1)
		u := uids[0]
		payload := []byte("data")
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteInfo(u, payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteLogs(u, payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteMetrics(u, payload)
			}
		}()
		wg.Wait()
	})

	t.Run("ConcurrentWritesAndDeviceClear", func(t *testing.T) {
		d, uids := setup(t, 1)
		u := uids[0]
		payload := []byte("data")
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteInfo(u, payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteLogs(u, payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				d.DeviceClear()
			}
		}()
		wg.Wait()
	})

	t.Run("ConcurrentDeviceListAndClear", func(t *testing.T) {
		d, _ := setup(t, 3)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.DeviceList()
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.DeviceList()
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				d.DeviceClear()
			}
		}()
		wg.Wait()
	})

	t.Run("ConcurrentOnboardOperations", func(t *testing.T) {
		d, _ := setup(t, 0)
		for i := 0; i < 3; i++ {
			certB, _, err := ax.Generate(fmt.Sprintf("onboard-cn-%d", i), "")
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			cert, err := x509.ParseCertificate(certB)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if err := d.OnboardRegister(cert, []string{"s1", "s2"}); err != nil {
				t.Fatalf("OnboardRegister: %v", err)
			}
		}
		newCertB, _, err := ax.Generate("onboard-new", "")
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		newCert, err := x509.ParseCertificate(newCertB)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				d.OnboardList()
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				d.OnboardRegister(newCert, []string{"s3"})
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				d.OnboardClear()
			}
		}()
		wg.Wait()
	})

	t.Run("ConcurrentWritesAndReaders", func(t *testing.T) {
		d, uids := setup(t, 3)
		payload := []byte("data")
		var wg sync.WaitGroup
		wg.Add(6)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteInfo(uids[0], payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteLogs(uids[1], payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				d.WriteMetrics(uids[2], payload)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				r, err := d.GetInfoReader(uids[0])
				if err != nil {
					t.Errorf("GetInfoReader: %v", err)
					return
				}
				readAllChunks(t, r)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				r, err := d.GetLogsReader(uids[1])
				if err != nil {
					t.Errorf("GetLogsReader: %v", err)
					return
				}
				readAllChunks(t, r)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				r, err := d.GetMetricsReader(uids[2])
				if err != nil {
					t.Errorf("GetMetricsReader: %v", err)
					return
				}
				readAllChunks(t, r)
			}
		}()
		wg.Wait()
	})
}

// readAllChunks drains every chunk from a ChunkReader, discarding the data.
func readAllChunks(t *testing.T, r common.ChunkReader) {
	t.Helper()
	for {
		chunk, _, err := r.Next()
		if chunk == nil || err == io.EOF {
			return
		}
		if err != nil {
			t.Errorf("ChunkReader.Next: %v", err)
			return
		}
		if _, err = io.Copy(io.Discard, chunk); err != nil {
			t.Errorf("io.Copy from chunk: %v", err)
			return
		}
	}
}
