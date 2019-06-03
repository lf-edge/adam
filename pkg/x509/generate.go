package x509

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const (
	rsaBits = 2048
	oneYear = 365 * 24 * time.Hour
)

// generate a key and cert
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

func GenerateAndWrite(cn, hosts, certPath, keyPath string, force bool) error {
	// make sure we have the paths we need, and that they are not already taken, unless we were told to force
	if keyPath == "" {
		return fmt.Errorf("keyPath must not be empty")
	}
	if certPath == "" {
		return fmt.Errorf("certPath must not be empty")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) && !force {
		return fmt.Errorf("file already exists at keyPath %s", keyPath)
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) && !force {
		return fmt.Errorf("file already exists at certPath %s", certPath)
	}
	certB, keyB, err := Generate(cn, hosts)
	cert := PemEncodeCert(certB)
	key := PemEncodeKey(keyB)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certPath, cert, 0644)
	if err != nil {
		return fmt.Errorf("failed to write certificate to %s: %v", certPath, err)
	}
	err = ioutil.WriteFile(keyPath, key, 0600)
	if err != nil {
		return fmt.Errorf("failed to write key to %s: %v", keyPath, err)
	}

	return nil
}
