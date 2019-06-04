package server

import (
	"crypto/x509"
	"fmt"
	"github.com/satori/go.uuid"
	"strings"
	"testing"

	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	ax "github.com/zededa/adam/pkg/x509"
)

func TestDeviceManagerMemory(t *testing.T) {
	t.Run("TestSetCacheTimeout", func(t *testing.T) {
		d := DeviceManagerMemory{}
		d.SetCacheTimeout(10)
	})

	t.Run("TestCheckOnboardCert", func(t *testing.T) {
		cn := "CN=abcdefg"
		hosts := "localhost,127.0.0.1"

		tests := []struct {
			validCert    bool
			certExists   bool
			serialExists bool
			used         bool
			valid        bool
			err          error
		}{
			{false, false, false, false, false, fmt.Errorf("invalid nil certificate")},
			{true, false, false, false, false, nil},
			{true, false, true, false, false, nil},
			{true, true, false, false, false, nil},
			{true, true, true, true, false, nil},
			{true, true, true, false, true, nil},
		}

		for i, tt := range tests {
			// the item we will test
			dm := DeviceManagerMemory{}

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
				dm.devices = map[uuid.UUID]deviceStorage{}
				u, _ := uuid.NewV4()
				dm.devices[u] = deviceStorage{
					onboard: cert,
					serial:  serial,
				}
			}
			valid, err := dm.CheckOnboardCert(cert, serial)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case valid != tt.valid:
				t.Errorf("%d: mismatched valid, actual %v, expected %v", i, valid, tt.valid)
			}
		}
	})

	t.Run("TestCheckDeviceCert", func(t *testing.T) {
		cn := "CN=abcdefg"
		hosts := "localhost,127.0.0.1"
		u, _ := uuid.NewV4()

		tests := []struct {
			validCert  bool
			certExists bool
			u          *uuid.UUID
			err        error
		}{
			{false, false, nil, fmt.Errorf("invalid nil certificate")},
			{true, false, nil, nil},
			{true, true, &u, nil},
		}

		for i, tt := range tests {
			// the item we will test
			dm := DeviceManagerMemory{}

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
			devu, err := dm.CheckDeviceCert(cert)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case (devu != nil && tt.u == nil) || (devu == nil && tt.u != nil) || (devu != nil && tt.u != nil && tt.u.String() != devu.String()):
				t.Errorf("%d: mismatched uuid, actual %v, expected %v", i, devu, tt.u)
			}
		}
	})

	t.Run("TestWriteInfo", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManagerMemory{}
		tests := []struct {
			validMsg     bool
			validUUID    bool
			deviceExists bool
			err          error
		}{
			{false, false, false, fmt.Errorf("invalid nil message")},
			{true, false, false, fmt.Errorf("unable to retrieve valid device UUID")},
			{true, true, false, fmt.Errorf("unregistered device UUID")},
			{true, true, true, nil},
		}
		for i, tt := range tests {
			var msg *info.ZInfoMsg
			if tt.validMsg {
				msg = &info.ZInfoMsg{}
			}
			if tt.validUUID {
				msg.DevId = u.String()
			}
			// fresh each time
			d.devices = map[uuid.UUID]deviceStorage{}
			if tt.deviceExists {
				d.devices[u] = deviceStorage{}
			}
			err := d.WriteInfo(msg)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && (len(d.devices[u].info) != 1 || d.devices[u].info[0] != msg):
				t.Errorf("%d: did not save message correctly, actual %v expected %v", i, d.devices[u].info, msg)
			}
		}
	})

	t.Run("TestWriteLogs", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManagerMemory{}
		tests := []struct {
			validMsg     bool
			validUUID    bool
			deviceExists bool
			err          error
		}{
			{false, false, false, fmt.Errorf("invalid nil message")},
			{true, false, false, fmt.Errorf("unable to retrieve valid device UUID")},
			{true, true, false, fmt.Errorf("unregistered device UUID")},
			{true, true, true, nil},
		}
		for i, tt := range tests {
			var msg *logs.LogBundle
			if tt.validMsg {
				msg = &logs.LogBundle{}
			}
			if tt.validUUID {
				msg.DevID = u.String()
			}
			// fresh each time
			d.devices = map[uuid.UUID]deviceStorage{}
			if tt.deviceExists {
				d.devices[u] = deviceStorage{}
			}
			err := d.WriteLogs(msg)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && (len(d.devices[u].logs) != 1 || d.devices[u].logs[0] != msg):
				t.Errorf("%d: did not save message correctly, actual %v expected %v", i, d.devices[u].logs, msg)
			}
		}
	})

	t.Run("TestWriteMetrics", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManagerMemory{}
		tests := []struct {
			validMsg     bool
			validUUID    bool
			deviceExists bool
			err          error
		}{
			{false, false, false, fmt.Errorf("invalid nil message")},
			{true, false, false, fmt.Errorf("unable to retrieve valid device UUID")},
			{true, true, false, fmt.Errorf("unregistered device UUID")},
			{true, true, true, nil},
		}
		for i, tt := range tests {
			var msg *metrics.ZMetricMsg
			if tt.validMsg {
				msg = &metrics.ZMetricMsg{}
			}
			if tt.validUUID {
				msg.DevID = u.String()
			}
			// fresh each time
			d.devices = map[uuid.UUID]deviceStorage{}
			if tt.deviceExists {
				d.devices[u] = deviceStorage{}
			}
			err := d.WriteMetrics(msg)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && (len(d.devices[u].metrics) != 1 || d.devices[u].metrics[0] != msg):
				t.Errorf("%d: did not save message correctly, actual %v expected %v", i, d.devices[u].metrics, msg)
			}
		}
	})

	t.Run("TestRegisterDeviceCert", func(t *testing.T) {
		u, _ := uuid.NewV4()
		d := DeviceManagerMemory{}
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
			validU          bool
			err             error
		}{
			{false, false, false, fmt.Errorf("invalid nil certificate")},
			{true, true, false, fmt.Errorf("device already registered")},
			{true, false, true, nil},
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
			u, err := d.RegisterDeviceCert(deviceCert, onboard, serial)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case tt.validU && u == nil:
				t.Errorf("%d: received nil uuid when expected valid one", i)
			case !tt.validU && u != nil:
				t.Errorf("%d: received valid uuid when expected nil", i)
			case tt.validU && tt.err == nil && d.devices[*u].serial != serial:
				t.Errorf("%d: mismatched serial stored, actual %s expected %s", i, d.devices[*u].serial, serial)
			case tt.validU && tt.err == nil && d.devices[*u].onboard != onboard:
				t.Errorf("%d: mismatched onboard certificate stored, actual then expected", i)
				t.Errorf("\t%#v", d.devices[*u].onboard)
				t.Errorf("\t%#v", onboard)
			}
		}
	})
}
