// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"

	"github.com/lf-edge/adam/pkg/driver/common"
	ax "github.com/lf-edge/adam/pkg/x509"
	eveuuid "github.com/lf-edge/eve/api/go/eveuuid"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/metrics"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestDeviceManagerMemory(t *testing.T) {
	fillOnboard := func(dm *DeviceManager) []string {
		dm.onboardCerts = map[string]map[string]bool{}
		cns := []string{"abcd", "efgh", "jklm"}
		for _, cn := range cns {
			certB, _, err := ax.Generate(cn, "")
			if err != nil {
				t.Fatalf("error generating cert for tests: %v", err)
			}
			cert, err := x509.ParseCertificate(certB)
			if err != nil {
				t.Fatalf("unexpected error parsing certificate: %v", err)
			}
			certStr := string(cert.Raw)
			dm.onboardCerts[certStr] = map[string]bool{}
		}
		return cns
	}

	fillDevice := func(dm *DeviceManager) []*uuid.UUID {
		dm.deviceCerts = map[string]uuid.UUID{}
		dm.devices = map[uuid.UUID]common.DeviceStorage{}
		uids := []uuid.UUID{}
		for i := 0; i < 3; i++ {
			u, _ := uuid.NewV4()
			certB, _, err := ax.Generate("abcdefg", "")
			if err != nil {
				t.Fatalf("error generating cert for tests: %v", err)
			}
			cert, err := x509.ParseCertificate(certB)
			if err != nil {
				t.Fatalf("unexpected error parsing certificate: %v", err)
			}
			certStr := string(cert.Raw)
			dm.deviceCerts[certStr] = u
			dm.devices[u] = common.DeviceStorage{}
			uids = append(uids, u)
		}
		puids := make([]*uuid.UUID, 0, len(uids))
		for i := range uids {
			puids = append(puids, &uids[i])
		}
		return puids
	}

	t.Run("TestSetCacheTimeout", func(t *testing.T) {
		d := DeviceManager{}
		d.SetCacheTimeout(10)
	})

	t.Run("TestOnboardCheck", func(t *testing.T) {
		cn := "CN=abcdefg"
		hosts := "localhost,127.0.0.1"

		tests := []struct {
			validCert    bool
			certExists   bool
			serialExists bool
			used         bool
			err          error
		}{
			{false, false, false, false, fmt.Errorf("invalid nil certificate")},
			{true, false, false, false, &common.InvalidCertError{Err: "unknown onboarding certificate"}},
			{true, false, true, false, &common.InvalidCertError{Err: "unknown onboarding certificate"}},
			{true, true, false, false, &common.InvalidSerialError{Err: "unknown serial"}},
			{true, true, true, true, &common.UsedSerialError{Err: "serial already used"}},
			{true, true, true, false, nil},
		}

		for i, tt := range tests {
			// the item we will test
			dm := DeviceManager{}

			// hold the cert and serial
			var (
				cert   *x509.Certificate
				serial string
			)
			// if valid, create the certificate
			if tt.validCert {
				certB, _, err := ax.Generate(cn, hosts)
				if err != nil {
					t.Fatalf("error generating cert for tests: %v", err)
				}
				cert, err = x509.ParseCertificate(certB)
				if err != nil {
					t.Fatalf("%d: unexpected error parsing certificate: %v", i, err)
					continue
				}
			}
			if tt.certExists && cert != nil {
				certStr := string(cert.Raw)
				dm.onboardCerts = map[string]map[string]bool{}
				dm.onboardCerts[certStr] = map[string]bool{}
				// if the serial exists, generate a serial and save it
				if tt.serialExists {
					serial = "abcdefg"
					dm.onboardCerts[certStr][serial] = true
				}
			}
			// is it used?
			if tt.validCert && tt.used {
				dm.devices = map[uuid.UUID]common.DeviceStorage{}
				u, _ := uuid.NewV4()
				dm.devices[u] = common.DeviceStorage{
					Onboard: cert,
					Serial:  serial,
				}
			}
			err := dm.OnboardCheck(cert, serial)
			if (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())) {
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			}
		}
	})

	t.Run("TestOnboardRemove", func(t *testing.T) {
		tests := []struct {
			cn     string
			exists bool
			err    error
		}{
			{"", false, fmt.Errorf("empty cn")},
			{"abcdefg", false, fmt.Errorf("onboard cn not found")},
			{"abcdefg", true, nil},
		}

		for i, tt := range tests {
			// the item we will test
			dm := DeviceManager{}

			// hold the cert and serial
			var (
				cert *x509.Certificate
			)
			var certStr string
			// if valid, create the certificate
			if tt.exists {
				certB, _, err := ax.Generate(tt.cn, "")
				if err != nil {
					t.Fatalf("error generating cert for tests: %v", err)
				}
				cert, err = x509.ParseCertificate(certB)
				if err != nil {
					t.Fatalf("%d: unexpected error parsing certificate: %v", i, err)
				}
				certStr = string(cert.Raw)
				dm.onboardCerts = map[string]map[string]bool{}
				dm.onboardCerts[certStr] = map[string]bool{}
			}
			err := dm.OnboardRemove(tt.cn)
			if (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())) {
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			} else if _, ok := dm.onboardCerts[certStr]; ok {
				t.Errorf("%d: cert still exists after OnboardRemove", i)
			}
		}
	})

	t.Run("TestOnboardClear", func(t *testing.T) {
		// the item we will test
		dm := DeviceManager{}
		fillOnboard(&dm)

		// if valid, create the certificate
		err := dm.OnboardClear()
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case len(dm.onboardCerts) != 0:
			t.Errorf("still have certs after OnboardClear: %d", len(dm.onboardCerts))
		}
	})

	t.Run("TestOnboardGet", func(t *testing.T) {
		tests := []struct {
			cn      string
			serials []string
			exists  bool
			err     error
		}{
			{"", nil, false, fmt.Errorf("empty cn")},
			{"abcdefg", nil, false, fmt.Errorf("onboard cn not found")},
			{"abcdefg", nil, true, nil},
			{"abcdefg", []string{"123"}, true, nil},
			{"abcdefg", []string{"123", "456"}, true, nil},
		}
		for i, tt := range tests {
			d := DeviceManager{
				onboardCerts: map[string]map[string]bool{},
			}
			var (
				validCert *x509.Certificate
				err       error
			)
			if tt.exists {
				validCert, _, err = ax.GenerateCertAndKey(tt.cn, "")
				if err != nil {
					t.Fatalf("Unable to generate certificate: %v", err)
				}
				ser := map[string]bool{}
				for _, k := range tt.serials {
					ser[k] = true
				}
				d.onboardCerts[string(validCert.Raw)] = ser
			}
			cert, serial, err := d.OnboardGet(tt.cn)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && !common.EqualStringSlice(serial, tt.serials):
				t.Errorf("%d: mismatched serials, actual '%v', expected '%v'", i, serial, tt.serials)
			case err == nil && bytes.Compare(validCert.Raw, cert.Raw) != 0:
				t.Errorf("%d: mismatched certs", i)
			}
		}
	})

	t.Run("TestOnboardList", func(t *testing.T) {
		dm := DeviceManager{}
		cns := fillOnboard(&dm)

		// if valid, create the certificate
		got, err := dm.OnboardList()
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case !common.EqualStringSlice(cns, got):
			t.Errorf("mismatched CNs, actual '%v', expected '%v'", got, cns)
		}
	})

	t.Run("TestDeviceCheckCertAndHash", func(t *testing.T) {
		cn := "CN=abcdefg"
		hosts := "localhost,127.0.0.1"
		u, _ := uuid.NewV4()

		tests := []struct {
			validCert  bool
			certExists bool
			u          *uuid.UUID
			err        error
			errHash    error
		}{
			{false, false, nil, fmt.Errorf("invalid nil certificate"), fmt.Errorf("invalid empty hash")},
			{true, false, nil, nil, fmt.Errorf("cert hash not found")},
			{true, true, &u, nil, nil},
		}

		for i, tt := range tests {
			// the item we will test
			dm := DeviceManager{}

			// hold the device cert
			var (
				cert *x509.Certificate
			)
			// if valid, create the certificate
			if tt.validCert {
				certB, _, err := ax.Generate(cn, hosts)
				if err != nil {
					t.Fatalf("error generating cert for tests: %v", err)
				}
				cert, err = x509.ParseCertificate(certB)
				if err != nil {
					t.Fatalf("%d: unexpected error parsing certificate: %v", i, err)
					continue
				}
			}
			if tt.certExists && cert != nil {
				certStr := string(cert.Raw)
				dm.deviceCerts = map[string]uuid.UUID{}
				dm.deviceCerts[certStr] = u
			}
			devu, err := dm.DeviceCheckCert(cert)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case (devu != nil && tt.u == nil) || (devu == nil && tt.u != nil) || (devu != nil && tt.u != nil && tt.u.String() != devu.String()):
				t.Errorf("%d: mismatched uuid, actual %v, expected %v", i, devu, tt.u)
			}
			var hash []byte
			if cert != nil {
				hashArray := sha256.Sum256(cert.Raw)
				hash = hashArray[:]
			}
			devu, err = dm.DeviceCheckCertHash(hash)
			switch {
			case (err != nil && tt.errHash == nil) || (err == nil && tt.errHash != nil) || (err != nil && tt.errHash != nil && !strings.HasPrefix(err.Error(), tt.errHash.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.errHash)
			case (devu != nil && tt.u == nil) || (devu == nil && tt.u != nil) || (devu != nil && tt.u != nil && tt.u.String() != devu.String()):
				t.Errorf("%d: mismatched uuid, actual %v, expected %v", i, devu, tt.u)
			}
		}
	})

	t.Run("TestDeviceRemove", func(t *testing.T) {
		tests := []struct {
			valid  bool
			exists bool
			err    error
		}{
			{false, false, fmt.Errorf("")},
			{true, false, fmt.Errorf("")},
			{true, true, nil},
		}
		for i, tt := range tests {
			dm := DeviceManager{}
			uids := fillDevice(&dm)

			// populate the UUID we will pass
			var u *uuid.UUID
			switch {
			case tt.exists:
				u = uids[0]
			case tt.valid:
				ui, _ := uuid.NewV4()
				u = &ui
			}
			err := dm.DeviceRemove(u)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil:
				// check if the device still exists
				if _, ok := dm.devices[*u]; ok {
					t.Errorf("device still exists")
				}
			}
		}
	})

	t.Run("TestDeviceClear", func(t *testing.T) {
		dm := DeviceManager{}
		fillDevice(&dm)

		err := dm.DeviceClear()
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case len(dm.deviceCerts) != 0:
			t.Errorf("deviceCerts map is not empty")
		case len(dm.devices) != 0:
			t.Errorf("devices map is not empty")
		}
	})

	t.Run("TestDeviceGet", func(t *testing.T) {
		tests := []struct {
			valid  bool
			exists bool
			err    error
		}{
			{false, false, fmt.Errorf("")},
			{true, false, fmt.Errorf("")},
			{true, true, nil},
		}
		for i, tt := range tests {
			dm := DeviceManager{}
			uids := fillDevice(&dm)

			// populate the UUID we will pass
			var u *uuid.UUID
			switch {
			case tt.exists:
				u = uids[0]
			case tt.valid:
				ui, _ := uuid.NewV4()
				u = &ui
			}
			cert, _, _, err := dm.DeviceGet(u)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && dm.devices[*u].Cert != cert:
				t.Errorf("%d: mismatched cert", i)
			}
		}
	})

	t.Run("TestDeviceList", func(t *testing.T) {
		dm := DeviceManager{}
		uids := fillDevice(&dm)

		// if valid, create the certificate
		got, err := dm.DeviceList()
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case !common.EqualUUIDSlice(uids, got):
			t.Errorf("mismatched UUIDs, actual '%v', expected '%v'", got, uids)
		}
	})

	t.Run("TestWriteInfo", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManager{}
		tests := []struct {
			validMsg     bool
			deviceExists bool
			err          error
		}{
			{false, false, nil},
			{true, false, fmt.Errorf("unregistered device UUID")},
			{true, true, nil},
		}
		for i, tt := range tests {
			var msg *info.ZInfoMsg
			if tt.validMsg {
				msg = &info.ZInfoMsg{}
				msg.DevId = u.String()
			}
			// fresh each time
			d.devices = map[uuid.UUID]common.DeviceStorage{}
			if tt.deviceExists {
				d.devices[u] = common.DeviceStorage{
					Info: &ByteSlice{
						maxSize: 500000,
					},
				}
			}

			var (
				outBytes []byte
				err      error
			)
			// get the msg as bytes to compare
			if msg != nil {
				outBytes, err = protojson.Marshal(msg)
				if err != nil {
					t.Fatalf("failed to marshal protobuf message into json: %v", err)
				}
			}

			err = d.WriteInfo(u, outBytes)

			var (
				actual []byte
				geterr error
			)

			if tt.deviceExists {
				actual, geterr = d.devices[u].Info.Get(0)
			}
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && (geterr != nil || !bytes.Equal(actual, outBytes)):
				t.Errorf("%d: did not save message correctly, actual %v expected %v", i, actual, msg)
			}
		}
	})

	t.Run("TestWriteLogs", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManager{}
		tests := []struct {
			validMsg     bool
			deviceExists bool
			err          error
		}{
			{false, false, nil},
			{true, false, fmt.Errorf("unregistered device UUID")},
			{true, true, nil},
		}
		for i, tt := range tests {
			var msg []byte
			if tt.validMsg {
				b, err := common.FullLogEntry{}.Json()
				if err != nil {
					t.Fatalf("%d: %v", i, err)
				}
				msg = append(msg, b...)
			}
			// fresh each time
			d.devices = map[uuid.UUID]common.DeviceStorage{}
			if tt.deviceExists {
				d.devices[u] = common.DeviceStorage{
					Logs: &ByteSlice{
						maxSize: 500000,
					},
				}
			}
			err := d.WriteLogs(u, msg)

			// get the msg as bytes to compare
			var (
				actual []byte
				geterr error
			)
			if tt.deviceExists {
				actual, geterr = d.devices[u].Logs.Get(0)
			}

			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && (geterr != nil || !bytes.Equal(actual, msg)):
				t.Errorf("%d: did not save message correctly, actual %v expected %v", i, d.devices[u].Logs, msg)
			}

			if tt.deviceExists {
				buffer := make([]byte, 1024)
				chunkReader, err := d.GetLogsReader(u)
				assert.Equal(t, nil, err)
				i := 100
				for {
					lr, s, err := chunkReader.Next()
					if lr == nil {
						break
					}
					i--
					if i == 0 {
						t.Fatal(s)
					}
					assert.Equal(t, nil, err)
					l, err := lr.Read(buffer)
					assert.Equal(t, nil, err)
					assert.Equal(t, int64(l), s)
				}
			}
		}
	})

	t.Run("TestWriteMetrics", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManager{}
		tests := []struct {
			validMsg     bool
			deviceExists bool
			err          error
		}{
			{false, false, nil},
			{true, false, fmt.Errorf("unregistered device UUID")},
			{true, true, nil},
		}
		for i, tt := range tests {
			var msg *metrics.ZMetricMsg
			if tt.validMsg {
				msg = &metrics.ZMetricMsg{}
				msg.DevID = u.String()
			}
			// fresh each time
			d.devices = map[uuid.UUID]common.DeviceStorage{}
			if tt.deviceExists {
				d.devices[u] = common.DeviceStorage{
					Metrics: &ByteSlice{
						maxSize: 500000,
					},
				}
			}
			var (
				outBytes []byte
				err      error
			)
			if msg != nil {
				outBytes, err = protojson.Marshal(msg)
				if err != nil {
					t.Fatalf("failed to marshal protobuf message into json: %v", err)
				}
			}
			err = d.WriteMetrics(u, outBytes)
			// get the msg as bytes to compare

			var (
				actual []byte
				geterr error
			)
			if tt.deviceExists {
				actual, geterr = d.devices[u].Metrics.Get(0)
			}

			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && (geterr != nil || !bytes.Equal(actual, outBytes)):
				t.Errorf("%d: did not save message correctly, actual %v expected %v", i, d.devices[u].Metrics, msg)
			}
		}
	})

	t.Run("TestDeviceRegister", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManager{}
		serial := "abcdefgh"
		certB, _, err := ax.Generate("onboard", "")
		if err != nil {
			t.Fatalf("error generating onboard cert for tests: %v", err)
		}
		onboard, err := x509.ParseCertificate(certB)
		if err != nil {
			t.Fatalf("unexpected error parsing onboard certificate: %v", err)
		}

		tests := []struct {
			validDeviceCert bool
			used            bool
			err             error
		}{
			{false, false, fmt.Errorf("invalid nil certificate")},
			{true, true, fmt.Errorf("device already registered")},
			{true, false, nil},
		}
		for i, tt := range tests {
			var (
				deviceCert *x509.Certificate
			)

			// reset with each test
			d.deviceCerts = map[string]uuid.UUID{}

			if tt.validDeviceCert {
				certB, _, err := ax.Generate("device", "")
				if err != nil {
					t.Fatalf("error generating device cert for tests: %v", err)
				}
				deviceCert, err = x509.ParseCertificate(certB)
				if err != nil {
					t.Fatalf("%d: unexpected error parsing device certificate: %v", i, err)
				}
			}
			if tt.used {
				certStr := string(deviceCert.Raw)
				d.deviceCerts[certStr] = u
			}
			u, err := uuid.NewV4()
			if err != nil {
				t.Fatalf("error generating a new device UUID: %v", err)
			}
			err = d.DeviceRegister(u, deviceCert, onboard, serial, common.CreateBaseConfig(u))
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case tt.err == nil && d.devices[u].Serial != serial:
				t.Errorf("%d: mismatched serial stored, actual %s expected %s", i, d.devices[u].Serial, serial)
			case tt.err == nil && d.devices[u].Onboard != onboard:
				t.Errorf("%d: mismatched onboard certificate stored, actual then expected", i)
				t.Errorf("\t%#v", d.devices[u].Onboard)
				t.Errorf("\t%#v", onboard)
			}
		}
	})

	t.Run("TestOnboardRegister", func(t *testing.T) {
		tests := []struct {
			validCert bool
			serial    []string
			used      bool
			err       error
		}{
			{false, nil, false, fmt.Errorf("empty nil certificate")},
			{true, nil, false, nil},
			{true, nil, true, nil},
			{true, []string{}, false, nil},
			{true, []string{}, true, nil},
			{true, []string{"abc", "def"}, false, nil},
			{true, []string{"abc", "def"}, true, nil},
		}
		for i, tt := range tests {
			var (
				cert    *x509.Certificate
				certStr string
			)

			// reset with each test
			d := DeviceManager{
				onboardCerts: map[string]map[string]bool{},
			}

			if tt.validCert {
				certB, _, err := ax.Generate("onboard", "")
				if err != nil {
					t.Fatalf("%d; error generating onboard cert for tests: %v", i, err)
				}
				cert, err = x509.ParseCertificate(certB)
				if err != nil {
					t.Fatalf("%d: unexpected error parsing onboard certificate: %v", i, err)
				}
				certStr = string(certB)
			}
			if tt.used {
				d.onboardCerts[certStr] = map[string]bool{}
			}
			err := d.OnboardRegister(cert, tt.serial)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && d.onboardCerts[certStr] == nil:
				t.Errorf("%d: onboardCerts are nil", i)
			default:
				err := common.CompareStringSliceMap(tt.serial, d.onboardCerts[certStr])
				if err != nil {
					t.Errorf("%d: mismatched serials", i)
					t.Errorf("%v", err)
				}
			}
		}
	})

	t.Run("TestGetUUID", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManager{}

		tests := []struct {
			deviceExists bool
		}{
			{false},
			{true},
		}
		for _, tt := range tests {
			d.devices = map[uuid.UUID]common.DeviceStorage{}
			if tt.deviceExists {
				d.devices[u] = common.DeviceStorage{}
			}
			uuidResponse, err := d.GetUUID(u)
			if tt.deviceExists {
				if err != nil {
					t.Errorf("Error: %v", err)
				}
				if len(uuidResponse) == 0 {
					t.Error("Empty uuidResponse")
				}
				var ur eveuuid.UuidResponse
				err := proto.Unmarshal(uuidResponse, &ur)
				if err != nil {
					t.Errorf("Unmarshal error: %v", err)
				}
				if ur.GetUuid() != u.String() {
					t.Error("uuid mismatch in uuidResponse")
				}
				continue
			}
			if err == nil {
				t.Errorf("empty error for non-exist device")
			}
		}
	})
}
