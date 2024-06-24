// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package x509

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// PemEncodeCert take certificate DER bytes and PEM encode them
func PemEncodeCert(cert []byte) []byte {
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	b := make([]byte, out.Len())
	copy(b, out.Bytes())
	return b
}

// PemEncodeKey take an RSA private key and PEM encode it
func PemEncodeKey(key *rsa.PrivateKey) []byte {
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	b := make([]byte, out.Len())
	copy(b, out.Bytes())
	return b
}

// ParseCertFromBlock process pem certificates
func ParseCertFromBlock(b []byte) ([]*x509.Certificate, error) {
	var certsSlice []*x509.Certificate
	for block, rest := pem.Decode(b); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			c, e := x509.ParseCertificates(block.Bytes)
			if e != nil {
				continue
			}
			certsSlice = append(certsSlice, c...)
		}
	}

	return certsSlice, nil
}
