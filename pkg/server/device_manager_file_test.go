package server

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/satori/go.uuid"
	ax "github.com/zededa/adam/pkg/x509"
)

func TestDeviceManagerFile(t *testing.T) {
	t.Run("TestSetCacheTimeout", func(t *testing.T) {
		// basics
		cn := "abcdefgh"
		serial := "thisisaserial"
		u, _ := uuid.NewV4()
		timeout := 5

		// make a temporary directory with which to work
		dir, err := ioutil.TempDir("", "adam-test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		d := DeviceManagerFile{
			databasePath: dir,
		}
		d.SetCacheTimeout(timeout)

		// save a device
		devicePath := path.Join(dir, "device", u.String())
		err = os.MkdirAll(devicePath, 0755)
		if err != nil {
			t.Fatalf("error creating a temporary device directory: %v", err)
		}
		deviceCertB, deviceKey, err := ax.Generate(cn, "")
		if err != nil {
			t.Fatalf("unexpected error generating device certificate: %v", err)
		}
		deviceCert, err := x509.ParseCertificate(deviceCertB)
		if err != nil {
			t.Fatalf("error parsing device certificate: %v", err)
		}
		err = ax.WriteCert(deviceCertB, path.Join(devicePath, DeviceCertFilename), false)
		if err != nil {
			t.Fatalf("error writing device certificate: %v", err)
		}
		err = ax.WriteKey(deviceKey, path.Join(devicePath, "device-key.pem"), false)
		if err != nil {
			t.Fatalf("error writing device key: %v", err)
		}
		deviceCertStr := string(deviceCert.Raw)

		// save an onboard with serials
		onboardPath := path.Join(dir, "onboard", cn)
		err = os.MkdirAll(onboardPath, 0755)
		if err != nil {
			t.Fatalf("error creating a temporary onboard directory: %v", err)
		}
		onboardCertB, onboardKey, err := ax.Generate(cn, "")
		if err != nil {
			t.Fatalf("unexpected error generating onboarding certificate: %v", err)
		}
		onboardCert, err := x509.ParseCertificate(onboardCertB)
		if err != nil {
			t.Fatalf("error parsing onboard certificate: %v", err)
		}
		onboardCertStr := string(onboardCert.Raw)
		err = ax.WriteCert(onboardCertB, path.Join(onboardPath, onboardCertFilename), false)
		if err != nil {
			t.Fatalf("error writing onboard certificate: %v", err)
		}
		err = ax.WriteKey(onboardKey, path.Join(onboardPath, "onboard-key.pem"), false)
		if err != nil {
			t.Fatalf("error writing onboard key: %v", err)
		}
		err = ioutil.WriteFile(path.Join(onboardPath, onboardCertSerials), []byte(serial), 0644)
		if err != nil {
			t.Fatalf("error writing onboard serials: %v", err)
		}

		// include the device onboarding cert
		copyFile(path.Join(onboardPath, onboardCertFilename), path.Join(devicePath, DeviceOnboardFilename))
		// write the device serial
		ioutil.WriteFile(path.Join(devicePath, deviceSerialFilename), []byte(serial), 0644)
		// wait for the timeout
		time.Sleep(time.Duration(timeout) * time.Millisecond)
		// force the cache to refresh
		err = d.refreshCache()
		if err != nil {
			t.Fatalf("error refreshing cache: %v", err)
		}

		// check that they were loaded
		switch {
		case d.onboardCerts == nil:
			t.Errorf("onboard certs are nil")
		case d.onboardCerts != nil && d.onboardCerts[onboardCertStr] == nil:
			t.Errorf("onboard cert missing")
		case d.onboardCerts != nil && d.onboardCerts[onboardCertStr] != nil && d.onboardCerts[onboardCertStr][serial] != true:
			t.Errorf("onboard cert serial missing")
		case d.deviceCerts == nil:
			t.Errorf("device certs are nil")
		case d.deviceCerts != nil && d.deviceCerts[deviceCertStr] != u:
			t.Errorf("device cert missing")
		case d.devices == nil:
			t.Errorf("devices are nil")
		case d.devices != nil && d.devices[u].onboard == nil:
			t.Errorf("device missing onboard certificate")
		case d.devices != nil && d.devices[u].onboard != nil && string(d.devices[u].onboard.Raw) != onboardCertStr:
			t.Errorf("mismatched device onboard certificate")
		case d.devices != nil && d.devices[u].serial != serial:
			t.Errorf("device mismatched serial, actual %s expected %s", d.devices[u].serial, serial)
		}
	})

	// CheckOnboardCert for file is identical to Memory, since it just uses the cache, so no testing here
	t.Run("TestCheckOnboardCert", func(t *testing.T) {
	})

	// CheckDeviceCert for file is identical to Memory, since it just uses the cache, so no testing here
	t.Run("TestCheckDeviceCert", func(t *testing.T) {
	})

	writeTester := func(t *testing.T, sectionName string, cmd func(int64, string, bool, bool, DeviceManagerFile) error) {
		u, _ := uuid.NewV4()
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
			ts := int64(1000)
			// make a temporary directory with which to work
			dir, err := ioutil.TempDir("", "adam-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			d := DeviceManagerFile{
				databasePath: dir,
			}
			sectionPath := path.Join(d.getDevicePath(u), sectionName)
			if tt.deviceExists {
				err = os.MkdirAll(sectionPath, 0755)
				if err != nil {
					t.Fatalf("Unable to make dir %s: %v", sectionPath, err)
				}
			}
			err = cmd(ts, u.String(), tt.validMsg, tt.validUUID, d)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && tt.err == nil:
				// check if the correct file exists
				filePath := path.Join(sectionPath, fmt.Sprintf("%d", ts))
				_, err := os.Stat(filePath)
				switch {
				case err != nil && os.IsNotExist(err):
					t.Errorf("%d: missing file at %s", i, filePath)
				case err != nil:
					t.Errorf("%d: unexpected error reading file at %s: %v", i, filePath, err)
				}
			}
		}
	}
	t.Run("TestWriteInfo", func(t *testing.T) {
		writeTester(t, "info", func(ts int64, u string, validMsg, validUUID bool, d DeviceManagerFile) error {
			var msg *info.ZInfoMsg
			if validMsg {
				msg = &info.ZInfoMsg{
					AtTimeStamp: &timestamp.Timestamp{
						Seconds: ts,
					},
				}
			}
			if validUUID {
				msg.DevId = u
			}
			return d.WriteInfo(msg)
		})
	})

	t.Run("TestWriteLogs", func(t *testing.T) {
		writeTester(t, "logs", func(ts int64, u string, validMsg, validUUID bool, d DeviceManagerFile) error {
			var msg *logs.LogBundle
			if validMsg {
				msg = &logs.LogBundle{
					Timestamp: &timestamp.Timestamp{
						Seconds: ts,
					},
				}
			}
			if validUUID {
				msg.DevID = u
			}
			return d.WriteLogs(msg)
		})
	})

	t.Run("TestWriteMetrics", func(t *testing.T) {
		writeTester(t, "metrics", func(ts int64, u string, validMsg, validUUID bool, d DeviceManagerFile) error {
			var msg *metrics.ZMetricMsg
			if validMsg {
				msg = &metrics.ZMetricMsg{
					AtTimeStamp: &timestamp.Timestamp{
						Seconds: ts,
					},
				}
			}
			if validUUID {
				msg.DevID = u
			}
			return d.WriteMetrics(msg)
		})
	})

	t.Run("TestRegisterDeviceCert", func(t *testing.T) {
		u, _ := uuid.NewV4()
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
			//{false, false, false, fmt.Errorf("invalid nil certificate")},
			//{true, true, false, fmt.Errorf("device already registered")},
			{true, false, true, nil},
		}
		for i, tt := range tests {
			var (
				deviceCert *x509.Certificate
			)

			// make a temporary directory with which to work
			dir, err := ioutil.TempDir("", "adam-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			devicePath := path.Join(dir, "device")
			d := DeviceManagerFile{
				databasePath: dir,
			}

			if tt.validDeviceCert {
				certB, _, err = ax.Generate("device", "")
				if err != nil {
					t.Fatalf("error generating device cert for tests: %v", err)
				}
				deviceCert, err = x509.ParseCertificate(certB)
				if err != nil {
					t.Fatalf("%d: unexpected error parsing device certificate: %v", i, err)
				}
			}
			if tt.used {
				deviceUPath := path.Join(devicePath, u.String())
				deviceUCertPath := path.Join(deviceUPath, DeviceCertFilename)
				err = os.MkdirAll(deviceUPath, 0755)
				if err != nil {
					t.Fatalf("%d: error making existing device path %s: %v", i, deviceUPath, err)
				}
				err = ax.WriteCert(certB, deviceUCertPath, true)
				if err != nil {
					t.Fatalf("%d: error writing existing device certificate file %s: %v", i, deviceUCertPath, err)
				}
			}
			unew, err := d.RegisterDeviceCert(deviceCert, onboard, serial)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case tt.validU && unew == nil:
				t.Errorf("%d: received nil uuid when expected valid one", i)
			case !tt.validU && unew != nil:
				t.Errorf("%d: received valid uuid when expected nil", i)
			case unew != nil && tt.validU:
				// check that the device directory exists, that it has the device, cert and serial files, and that their contents are correct
				if err = checkDeviceDirectory(devicePath, *unew, deviceCert, onboard, serial); err != nil {
					t.Errorf("%d: %v", i, err)
				}
			}
		}
	})
}

func copyFile(src, dest string) error {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dest, input, 0644)
	if err != nil {
		return err
	}
	return nil
}

// check the directory for a particular device uuid that it exists, has the necessary files, and the contents are correct
func checkDeviceDirectory(devicePath string, unew uuid.UUID, deviceCert, onboard *x509.Certificate, serial string) error {
	// check that the device directory entry exists
	uPath := path.Join(devicePath, unew.String())
	var (
		b    []byte
		err  error
		cert *x509.Certificate
	)
	if _, err = os.Stat(uPath); err != nil && os.IsNotExist(err) {
		return fmt.Errorf("device directory %s does not exist", uPath)
	}
	// check that the device certificate, onboard certificate, and serial files exist and match
	deviceCertPath := path.Join(uPath, DeviceCertFilename)
	if cert, err = ax.ReadCert(deviceCertPath); err != nil {
		return fmt.Errorf("device cert file read fail: %v", err)
	}
	if string(cert.Raw) != string(deviceCert.Raw) {
		return fmt.Errorf("device cert mismatch")
	}
	deviceOnboardPath := path.Join(uPath, DeviceOnboardFilename)
	if cert, err = ax.ReadCert(deviceOnboardPath); err != nil {
		return fmt.Errorf("device onboard cert file read fail: %v", err)
	}
	if string(cert.Raw) != string(onboard.Raw) {
		return fmt.Errorf("device cert mismatch")
	}
	deviceSerialPath := path.Join(uPath, deviceSerialFilename)
	if _, err := os.Stat(deviceSerialPath); err != nil && os.IsNotExist(err) {
		return fmt.Errorf("device serials file %s does not exist", deviceSerialPath)
	}
	if b, err = ioutil.ReadFile(deviceSerialPath); err != nil {
		return fmt.Errorf("error reading certificate file %s: %v", deviceSerialPath, err)
	}
	if string(b) != serial {
		return fmt.Errorf("mismatched serial: actual '%s' expected '%s'", string(b), serial)
	}

	return nil
}
