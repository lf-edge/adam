// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultServerURL = "https://localhost:8080"
)

var (
	serverURL   string
	serverCA    string
	insecureTLS bool
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage a running Adam server",
	Long:  `Managed devices and onboard configuration in a running Adam server over https.`,
}

func adminInit() {
	adminCmd.PersistentFlags().StringVar(&serverURL, "server", defaultServerURL, "full URL to running Adam server")
	adminCmd.MarkFlagRequired("server")
	adminCmd.PersistentFlags().StringVar(&serverCA, "server-ca", path.Join(defaultDatabaseURL, serverCertFilename), "path to CA certificate for trusting server; set to blank if using a certificate signed by a CA already on your system")
	adminCmd.PersistentFlags().BoolVar(&insecureTLS, "insecure", false, "accept invalid, expired or mismatched hostname errors for adam server certificate")
	// onboard
	adminCmd.AddCommand(onboardCmd)
	onboardInit()
	// device
	adminCmd.AddCommand(deviceCmd)
	deviceInit()
}

func getClient() *http.Client {
	return getClientStreamingOption(false)
}
func getStreamingClient() *http.Client {
	return getClientStreamingOption(true)
}

// http client with correct config
func getClientStreamingOption(stream bool) *http.Client {
	tlsConfig := &tls.Config{}
	if serverCA != "" {
		caCert, err := ioutil.ReadFile(serverCA)
		if err != nil {
			log.Fatalf("unable to read server CA file at %s: %v", serverCA, err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}
	if insecureTLS {
		tlsConfig.InsecureSkipVerify = true
	}

	// if we are streaming, then wait forever, but at least put a timeout
	// on the handshake and the response headers
	timeout := time.Second * 10
	if stream {
		timeout = timeout * 0
	}
	var client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	return client
}
func resolveURL(b, p string) (string, error) {
	u, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	base, err := url.Parse(b)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}
