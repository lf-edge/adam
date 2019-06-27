// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// WriteCert write cert bytes to a path, after pem encoding them. Do not overwrite unless force is true.
func WriteCert(cert []byte, certPath string, force bool) error {
	// make sure we have the paths we need, and that they are not already taken, unless we were told to force
	if certPath == "" {
		return fmt.Errorf("certPath must not be empty")
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) && !force {
		return fmt.Errorf("file already exists at certPath %s", certPath)
	}
	certPem := PemEncodeCert(cert)
	err := ioutil.WriteFile(certPath, certPem, 0644)
	if err != nil {
		return fmt.Errorf("failed to write certificate to %s: %v", certPath, err)
	}

	return nil
}

// WriteKey write RSA private key to a path, after pem encoding it. Do not overwrite unless force is true.
func WriteKey(key *rsa.PrivateKey, keyPath string, force bool) error {
	// make sure we have the paths we need, and that they are not already taken, unless we were told to force
	if keyPath == "" {
		return fmt.Errorf("keyPath must not be empty")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) && !force {
		return fmt.Errorf("file already exists at keyPath %s", keyPath)
	}
	keyPem := PemEncodeKey(key)
	err := ioutil.WriteFile(keyPath, keyPem, 0600)
	if err != nil {
		return fmt.Errorf("failed to write key to %s: %v", keyPath, err)
	}

	return nil
}

// ReadCert read a cert file
func ReadCert(p string) (*x509.Certificate, error) {
	var (
		b   []byte
		err error
	)
	if _, err = os.Stat(p); err != nil && os.IsNotExist(err) {
		return nil, err
	}
	if b, err = ioutil.ReadFile(p); err != nil {
		return nil, fmt.Errorf("error reading certificate file %s: %v", p, err)
	}
	return ParseCert(b)
}

// ParseCert parse a cert from a PEM-encoded byte slice
func ParseCert(b []byte) (*x509.Certificate, error) {
	var (
		err     error
		certPem *pem.Block
		cert    *x509.Certificate
	)
	certPem, _ = pem.Decode(b)
	cert, err = x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to convert data to certificate: %v", err)
	}
	return cert, nil
}
