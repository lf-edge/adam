package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

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

// read a cert file
func ReadCert(p string) (*x509.Certificate, error) {
	var (
		b       []byte
		err     error
		certPem *pem.Block
		cert    *x509.Certificate
	)
	if _, err = os.Stat(p); err != nil && os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file %s does not exist", p)
	}
	if b, err = ioutil.ReadFile(p); err != nil {
		return nil, fmt.Errorf("error reading certificate file %s: %v", p, err)
	}
	certPem, _ = pem.Decode(b)
	cert, err = x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to convert data from file %s to certificate: %v", p, err)
	}
	return cert, nil
}
