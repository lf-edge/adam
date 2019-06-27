// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package x509_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"crypto/x509"
	ax "github.com/zededa/adam/pkg/x509"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		cn    string
		hosts string
		err   error
	}{
		{"", "", fmt.Errorf("must specify at least one hostname/IP or CN")},
		{"CN=abcdefg", "", nil},
		{"", "localhost", nil},
		{"", "localhost,127.0.0.1", nil},
		{"CN=ancdefg", "localhost,127.0.0.1", nil},
	}
	for i, tt := range tests {
		certB, _, err := ax.Generate(tt.cn, tt.hosts)
		switch {
		case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())):
			t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
		case err != nil:
			continue
		default:
			// check that the certs are valid and the right kind
			cert, err := x509.ParseCertificate(certB)
			if err != nil {
				t.Errorf("%d: unexpected error parsing certificate: %v", i, err)
				continue
			}
			// check that the CN matches
			if cert.Subject.CommonName != tt.cn {
				t.Errorf("%d: mismatched CN, actual %s expected %s", i, cert.Subject.CommonName, tt.cn)
			}
			// check that the SAN match
			sans := strings.Split(tt.hosts, ",")
			ips := make([]string, 0)
			hosts := make([]string, 0)
			re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
			for _, s := range sans {
				if re.MatchString(s) {
					ips = append(ips, s)
				} else {
					hosts = append(hosts, s)
				}
			}
			// easiest way to compare is sort and join
			sort.Strings(ips)
			sort.Strings(hosts)
			certHosts := cert.DNSNames
			sort.Strings(certHosts)
			certIPs := make([]string, 0)
			for _, i := range cert.IPAddresses {
				certIPs = append(certIPs, i.String())
			}
			sort.Strings(certIPs)
			ipsJoin := strings.Join(ips, ",")
			hostsJoin := strings.Join(hosts, ",")
			certIpsJoin := strings.Join(certIPs, ",")
			certHostsJoin := strings.Join(certHosts, ",")

			if ipsJoin != certIpsJoin {
				t.Errorf("%d: mismatched SAN IPs, actual %s expected %s", i, certIpsJoin, ipsJoin)
			}
			if hostsJoin != certHostsJoin {
				t.Errorf("%d: mismatched SAN Hosts, actual %s expected %s", i, certHostsJoin, hostsJoin)
			}
		}
	}
}

func TestGenerateAndWrite(t *testing.T) {
	dir, err := ioutil.TempDir("", "adam-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	certFilename := "cert.pem"
	keyFilename := "key.pem"
	cn := "CN=abcdefg"
	hosts := "localhost,127.0.0.1"

	tests := []struct {
		certPath   string
		keyPath    string
		certExists bool
		keyExists  bool
		force      bool
		err        error
	}{
		{"", "", false, false, false, fmt.Errorf("certPath must not be empty")},
		{"CERT", "", false, false, false, fmt.Errorf("keyPath must not be empty")},
		{"", "KEY", false, false, false, fmt.Errorf("certPath must not be empty")},
		{"CERT", "KEY", true, false, false, fmt.Errorf("file already exists")},
		{"CERT", "KEY", false, true, false, fmt.Errorf("file already exists")},
		{"CERT", "KEY", true, false, true, nil},
		{"CERT", "KEY", false, true, true, nil},
	}
	for i, tt := range tests {
		certPath := tt.certPath
		if certPath != "" {
			certPath = path.Join(dir, certFilename)
		}
		keyPath := tt.keyPath
		if keyPath != "" {
			keyPath = path.Join(dir, keyFilename)
		}
		if tt.certExists {
			ioutil.WriteFile(certPath, []byte{1, 2, 3}, 0644)
		} else {
			os.Remove(certPath)
		}
		if tt.keyExists {
			ioutil.WriteFile(keyPath, []byte{1, 2, 3}, 0644)
		} else {
			os.Remove(keyPath)
		}
		err := ax.GenerateAndWrite(cn, hosts, certPath, keyPath, tt.force)
		if (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && !strings.HasPrefix(err.Error(), tt.err.Error())) {
			t.Errorf("%d: mismatched errors, actual %v expected %v", i, err, tt.err)
		}
	}
}
