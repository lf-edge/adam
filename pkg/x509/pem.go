package x509

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func PemEncodeCert(cert []byte) []byte {
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	b := make([]byte, out.Len())
	copy(b, out.Bytes())
	return b
}

func PemEncodeKey(key *rsa.PrivateKey) []byte {
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	b := make([]byte, out.Len())
	copy(b, out.Bytes())
	return b
}
