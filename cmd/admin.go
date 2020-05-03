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
	"github.com/spf13/viper"
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
	Long: `Managed devices and onboard configuration in a running Adam server over https. Common configuration
	options for all admin commands are listed below, as well as their defaults. These also can be set
	via environment variables. Note that environment variables always override defaults, and that CLI flags
	always override both defaults and environment variables.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		serverURL = viper.GetString("server")
		serverCA = viper.GetString("server-ca")
		insecureTLS = viper.GetBool("insecure")
	},
}

func adminInit() {
	adminCmd.PersistentFlags().String("server", defaultServerURL, "full URL to running Adam server, can also be set via env var ADAM_SERVER")
	adminCmd.MarkFlagRequired("server")
	viper.BindPFlag("server", adminCmd.PersistentFlags().Lookup("server"))
	adminCmd.PersistentFlags().String("server-ca", path.Join(defaultDatabaseURL, serverCertFilename), "path to CA certificate for trusting server; set to blank if using a certificate signed by a CA already on your system; can also be set via env var ADAM_SERVER_CA")
	viper.BindPFlag("server-ca", adminCmd.PersistentFlags().Lookup("server-ca"))
	adminCmd.PersistentFlags().Bool("insecure", false, "accept invalid, expired or mismatched hostname errors for adam server certificate, can also be set via env var ADAM_INSECURE")
	viper.BindPFlag("insecure", adminCmd.PersistentFlags().Lookup("insecure"))

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
