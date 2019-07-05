// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	rsaBits = 2048
	oneYear = 365 * 24 * time.Hour
)

// Generate a key and cert
func Generate(cn, hosts string) ([]byte, *rsa.PrivateKey, error) {
	if hosts == "" && cn == "" {
		return nil, nil, fmt.Errorf("must specify at least one hostname/IP or CN")
	}
	// simple RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	notBefore := time.Now()
	notAfter := notBefore.Add(oneYear)

	subject := pkix.Name{
		Organization: []string{"Zededa"},
	}
	if cn != "" {
		subject.CommonName = cn
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	hostnames := strings.Split(hosts, ",")
	for _, h := range hostnames {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	return derBytes, privKey, nil
}

// GenerateCertAndKey generate a certificate and a key, and return as x509.Certificate and rsa.PrivateKey
func GenerateCertAndKey(cn, hosts string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certB, key, err := Generate(cn, hosts)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certB)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// GenerateAndWrite generate a certificate and key and save to the given paths. Do not overwrite unless force is true.
func GenerateAndWrite(cn, hosts, certPath, keyPath string, force bool) error {
	certB, keyB, err := Generate(cn, hosts)
	if err != nil {
		return err
	}
	err = WriteCert(certB, certPath, force)
	if err != nil {
		return err
	}
	err = WriteKey(keyB, keyPath, force)
	if err != nil {
		return err
	}
	return nil
}
