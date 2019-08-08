// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"bytes"
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
	ax "github.com/lf-edge/adam/pkg/x509"
)

func TestDeviceManagerFile(t *testing.T) {
	fillOnboard := func(dm *DeviceManagerFile) []string {
		dm.onboardCerts = map[string]map[string]bool{}
		cns := []string{"abcd", "efgh", "jklm"}
		for _, cn := range cns {
			serials := make([]string, 0, 3)
			for i := 0; i < 3; i++ {
				serials = append(serials, randomString(8))
			}
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

			onboardPath := dm.getOnboardPath(cn)
			err = os.MkdirAll(onboardPath, 0755)
			if err != nil {
				t.Fatalf("Unable to make dir %s: %v", onboardPath, err)
			}
			err = ax.WriteCert(cert.Raw, path.Join(onboardPath, onboardCertFilename), true)
			if err != nil {
				t.Fatalf("Unable to write certificate: %v", err)
			}
			ioutil.WriteFile(path.Join(onboardPath, onboardCertSerials), []byte(strings.Join(serials, "\n")), 0644)
			if err != nil {
				t.Fatalf("Unable to write serials: %v", err)
			}
		}
		return cns
	}

	fillDevice := func(dm *DeviceManagerFile) []*uuid.UUID {
		dm.deviceCerts = map[string]uuid.UUID{}
		dm.devices = map[uuid.UUID]deviceStorage{}
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
			devicePath := dm.getDevicePath(u)
			err = os.MkdirAll(devicePath, 0755)
			if err != nil {
				t.Fatalf("error creating a temporary device directory: %v", err)
			}
			err = ax.WriteCert(certB, path.Join(devicePath, DeviceCertFilename), false)
			if err != nil {
				t.Fatalf("error writing device certificate: %v", err)
			}
			dm.deviceCerts[certStr] = u
			dm.devices[u] = deviceStorage{
				cert: cert,
			}
			uids = append(uids, u)
		}
		puids := make([]*uuid.UUID, 0, len(uids))
		for i := range uids {
			puids = append(puids, &uids[i])
		}
		return puids
	}

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
		onboardDir := path.Join(dir, "onboard")
		onboardCert, _, err := ax.GenerateCertAndKey(cn, "")
		if err != nil {
			t.Fatalf("error generating onboard cert and key: %v", err)
		}
		err = saveOnboardCertAndSerials(onboardDir, onboardCert, []string{serial})
		if err != nil {
			t.Fatalf("error saving onboard directory: %v", err)
		}
		onboardCertStr := string(onboardCert.Raw)

		onboardPath := path.Join(onboardDir, cn)
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

	// OnboardCheck for file is identical to Memory, since it just uses the cache, so no testing here
	t.Run("TestOnboardCheck", func(t *testing.T) {
	})

	t.Run("TestOnboardGet", func(t *testing.T) {
		tests := []struct {
			cn        string
			serials   []string
			dirExists bool
			err       error
		}{
			{"", nil, false, fmt.Errorf("empty cn")},
			{"abcdefg", nil, false, fmt.Errorf("onboard directory not found")},
			{"abcdefg", nil, true, nil},
			{"abcdefg", []string{"123"}, true, nil},
			{"abcdefg", []string{"123", "456"}, true, nil},
		}
		for i, tt := range tests {
			// make a temporary directory with which to work
			dir, err := ioutil.TempDir("", "adam-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			d := DeviceManagerFile{
				databasePath: dir,
			}
			var validCert *x509.Certificate
			if tt.dirExists {
				onboardPath := d.getOnboardPath(tt.cn)
				err = os.MkdirAll(onboardPath, 0755)
				if err != nil {
					t.Fatalf("Unable to make dir %s: %v", onboardPath, err)
				}
				validCert, _, err = ax.GenerateCertAndKey(tt.cn, "")
				if err != nil {
					t.Fatalf("Unable to generate certificate: %v", err)
				}
				err = ax.WriteCert(validCert.Raw, path.Join(onboardPath, onboardCertFilename), true)
				if err != nil {
					t.Fatalf("Unable to write certificate: %v", err)
				}
				ioutil.WriteFile(path.Join(onboardPath, onboardCertSerials), []byte(strings.Join(tt.serials, "\n")), 0644)
				if err != nil {
					t.Fatalf("Unable to write serials: %v", err)
				}
			}
			cert, serial, err := d.OnboardGet(tt.cn)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && !equalStringSlice(serial, tt.serials):
				t.Errorf("%d: mismatched serials, actual '%v', expected '%v'", i, serial, tt.serials)
			case err == nil && bytes.Compare(validCert.Raw, cert.Raw) != 0:
				t.Errorf("%d: mismatched certs", i)
			}
		}
	})

	t.Run("TestOnboardList", func(t *testing.T) {
		// make a temporary directory with which to work
		dir, err := ioutil.TempDir("", "adam-test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		dm := DeviceManagerFile{
			databasePath: dir,
		}
		cns := fillOnboard(&dm)

		// if valid, create the certificate
		got, err := dm.OnboardList()
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case !equalStringSlice(cns, got):
			t.Errorf("mismatched CNs, actual '%v', expected '%v'", got, cns)
		}
	})

	t.Run("TestOnboardRemove", func(t *testing.T) {
		tests := []struct {
			valid  bool
			exists bool
			err    error
		}{
			{false, false, fmt.Errorf("empty cn")},
			{true, false, fmt.Errorf("onboard directory not found")},
			{true, true, nil},
		}

		for i, tt := range tests {
			// make a temporary directory with which to work
			dir, err := ioutil.TempDir("", "adam-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			dm := DeviceManagerFile{
				databasePath: dir,
			}

			cns := fillOnboard(&dm)

			// hold the cert and serial
			var (
				cn      string
				certStr string
			)
			// if valid, create the certificate
			switch {
			case tt.valid && !tt.exists:
				cn = randomString(10)
			case tt.exists:
				cn = cns[0]
			}
			err = dm.OnboardRemove(cn)
			if mismatchedErrors(err, tt.err) {
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			} else if _, ok := dm.onboardCerts[certStr]; ok {
				t.Errorf("%d: cert still exists after OnboardRemove", i)
			} else if _, err = os.Stat(dm.getOnboardPath(cn)); cn != "" && !os.IsNotExist(err) {
				t.Errorf("%d: directory for %s still exists", i, cn)
			}
		}
	})

	t.Run("TestOnboardClear", func(t *testing.T) {
		// make a temporary directory with which to work
		dir, err := ioutil.TempDir("", "adam-test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		dm := DeviceManagerFile{
			databasePath: dir,
		}

		fillOnboard(&dm)

		err = dm.OnboardClear()
		// read the dirs
		onboardPath := path.Join(dm.databasePath, onboardDir)
		candidates, err := ioutil.ReadDir(onboardPath)
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case len(candidates) != 0:
			t.Errorf("still have onboard dirs after OnboardClear")
		}
	})

	// DeviceCheckCert for file is identical to Memory, since it just uses the cache, so no testing here
	t.Run("TestDeviceCheckCert", func(t *testing.T) {
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
			// make a temporary directory with which to work
			dir, err := ioutil.TempDir("", "adam-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			dm := DeviceManagerFile{
				databasePath: dir,
			}

			uids := fillDevice(&dm)

			var (
				u      *uuid.UUID
				exists bool
			)
			// populate the UUID we will pass
			switch {
			case tt.exists:
				u = uids[0]
			case tt.valid:
				ui, _ := uuid.NewV4()
				u = &ui
			}
			err = dm.DeviceRemove(u)
			// read the dirs
			if u != nil {
				devicePath := dm.getDevicePath(*u)
				_, e2 := os.Stat(devicePath)
				exists = e2 != nil && !os.IsNotExist(e2)
			}
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && exists:
				t.Errorf("device directory still exists")
			}
		}
	})

	t.Run("TestDeviceClear", func(t *testing.T) {
		// make a temporary directory with which to work
		dir, err := ioutil.TempDir("", "adam-test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		dm := DeviceManagerFile{
			databasePath: dir,
		}

		fillDevice(&dm)

		err = dm.DeviceClear()
		// read the dirs
		devicePath := path.Join(dm.databasePath, deviceDir)
		candidates, err := ioutil.ReadDir(devicePath)
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case len(candidates) != 0:
			t.Errorf("still have device dirs after OnboardClear")
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
			// make a temporary directory with which to work
			dir, err := ioutil.TempDir("", "adam-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			dm := DeviceManagerFile{
				databasePath: dir,
			}

			uids := fillDevice(&dm)

			var (
				u        *uuid.UUID
				fileCert *x509.Certificate
			)
			// populate the UUID we will pass
			switch {
			case tt.exists:
				u = uids[0]
			case tt.valid:
				ui, _ := uuid.NewV4()
				u = &ui
			}
			cert, _, _, err := dm.DeviceGet(u)
			if u != nil && tt.exists {
				devicePath := dm.getDevicePath(*u)
				fileCert, _ = ax.ReadCert(path.Join(devicePath, DeviceCertFilename))
			}
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && cert != nil && fileCert != nil && bytes.Compare(fileCert.Raw, cert.Raw) != 0:
				t.Errorf("%d: mismatched cert", i)
			}
		}
	})

	t.Run("TestDeviceList", func(t *testing.T) {
		// make a temporary directory with which to work
		dir, err := ioutil.TempDir("", "adam-test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		dm := DeviceManagerFile{
			databasePath: dir,
		}

		uids := fillDevice(&dm)

		// if valid, create the certificate
		got, err := dm.DeviceList()
		switch {
		case err != nil:
			t.Errorf("unexpected error: %v", err)
		case !equalUUIDSlice(uids, got):
			t.Errorf("mismatched UUIDs, actual '%v', expected '%v'", got, uids)
		}
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

	t.Run("TestDeviceRegister", func(t *testing.T) {
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
			unew, err := d.DeviceRegister(deviceCert, onboard, serial)
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
				err     error
			)

			// reset with each test
			// make a temporary directory with which to work
			dir, err := ioutil.TempDir("", "adam-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			d := DeviceManagerFile{
				databasePath: dir,
			}

			if tt.validCert {
				cert, _, err = ax.GenerateCertAndKey("onboard", "")
				if err != nil {
					t.Fatalf("%d: error generating onboard cert and key: %v", i, err)
				}
				certStr = string(cert.Raw)
			}
			if tt.used {
				// store in cache and on disk
				if d.onboardCerts == nil {
					d.onboardCerts = map[string]map[string]bool{}
				}
				d.onboardCerts[certStr] = map[string]bool{}

				onboardDir := path.Join(dir, "onboard")
				err := saveOnboardCertAndSerials(onboardDir, cert, tt.serial)
				if err != nil {
					t.Fatalf("%d: error saving onboard directory: %v", i, err)
				}
			}
			err = d.OnboardRegister(cert, tt.serial)
			switch {
			case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
				t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
			case err == nil && d.onboardCerts[certStr] == nil:
				t.Errorf("%d: onboardCerts are nil", i)
			default:
				err := compareStringSliceMap(tt.serial, d.onboardCerts[certStr])
				if err != nil {
					t.Errorf("%d: mismatched serials", i)
					t.Errorf("%v", err)
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

func saveOnboardCertAndSerials(onboardDir string, cert *x509.Certificate, serials []string) error {
	var err error
	// save an onboard with serials
	onboardPath := path.Join(onboardDir, cert.Subject.CommonName)
	err = os.MkdirAll(onboardPath, 0755)
	if err != nil {
		return fmt.Errorf("error creating a temporary onboard directory: %v", err)
	}
	err = ax.WriteCert(cert.Raw, path.Join(onboardPath, onboardCertFilename), true)
	if err != nil {
		return fmt.Errorf("error writing onboard certificate: %v", err)
	}

	err = ioutil.WriteFile(path.Join(onboardPath, onboardCertSerials), []byte(strings.Join(serials, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("error writing onboard serials: %v", err)
	}
	return nil
}
