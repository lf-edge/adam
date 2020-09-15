// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/lf-edge/adam/pkg/driver/common"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/server"
	ax509 "github.com/lf-edge/adam/pkg/x509"
	"github.com/spf13/cobra"
)

const (
	defaultPort        = "8080"
	defaultIP          = "0.0.0.0"
	defaultCertRefresh = 60
)

var (
	serverCert      string
	serverKey       string
	certCN          string
	certHosts       string
	port            string
	hostIP          string
	clientCertPath  string
	certRefresh     int
	maxLogSize      int
	maxInfoSize     int
	maxMetricSize   int
	maxRequestsSize int
	maxAppLogsSize  int
	autoCert        bool
	deviceManagers  = driver.GetDeviceManagers()
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Adam server",
	Long:  `Adam is an LF-Edge API compliant Controller. Complete API documentation is available at https://github.com/lf-edge/eve/api/API.md`,
	Run: func(cmd *cobra.Command, args []string) {
		// create a handler based on where our device database is
		// in the future, we may support other device manager types
		var mgr driver.DeviceManager
		maxSizes := common.MaxSizes{
			MaxLogSize:      maxLogSize,
			MaxInfoSize:     maxInfoSize,
			MaxMetricSize:   maxMetricSize,
			MaxRequestsSize: maxRequestsSize,
			MaxAppLogsSize:  maxAppLogsSize,
		}
		for _, m := range deviceManagers {
			name := m.Name()
			valid, err := m.Init(databaseURL, maxSizes)
			if err != nil {
				log.Fatalf("error initializing the %s device manager: %v", name, err)
			}
			if valid {
				mgr = m
				break
			}
		}
		if mgr == nil {
			log.Fatalf("could not find valid device manager")
		}

		// we use MkdirAll, since we are willing to continue if the directory already exists; we only error if we cannot make it,
		//   or if the _files_ already exist
		err := os.MkdirAll(configDir, 0755)
		if err != nil {
			log.Fatalf("failed to make directory %s: %v", configDir, err)
		}

		// if we were asked to autoCert, then we do it
		if autoCert {
			if certCN == certHosts && certCN == "" {
				log.Fatalf("must specify at least one hostname/IP or CN")
			}
			// get the directory
			certDir := path.Dir(serverCert)
			keyDir := path.Dir(serverKey)
			// only do it if the files do not exist
			certForce := false
			// make the directories or fail
			if err := os.MkdirAll(certDir, 0755); err != nil {
				log.Fatalf("failed to make cert directory %s: %v", certDir, err)
			}
			if err := os.MkdirAll(keyDir, 0755); err != nil {
				log.Fatalf("failed to make key directory %s: %v", keyDir, err)
			}
			if err := ax509.GenerateAndWrite(certCN, certHosts, serverCert, serverKey, certForce); err != nil {
				log.Printf("auto-generation: key %s and/or cert %s already in place, skipping", serverKey, serverCert)
			} else {
				log.Printf("saved new server certificate to %s", serverCert)
				log.Printf("saved new server key to %s", serverKey)
			}
		}

		catls, err := tls.LoadX509KeyPair(serverCert, serverKey)
		if err != nil {
			log.Fatalf("error loading server cert %s and server key %s: %v", serverCert, serverKey, err)
		}
		ca, err := x509.ParseCertificate(catls.Certificate[0])
		if err != nil {
			log.Fatalf("error parsing server cert: %v", err)
		}

		err = ioutil.WriteFile(path.Join(configDir, "server"), []byte(ca.Subject.CommonName+":"+port), 0644)
		if err != nil {
			log.Fatalf("error writing to server file: %v", err)
		}

		err = ioutil.WriteFile(path.Join(configDir, "hosts"), []byte(hostIP+" "+ca.Subject.CommonName), 0644)
		if err != nil {
			log.Fatalf("error writing hosts file: %v", err)
		}

		rootCert, err := ioutil.ReadFile(serverCert)
		if err != nil {
			log.Fatalf("error reading %s file: %v", serverCert, err)
		}
		err = ioutil.WriteFile(path.Join(configDir, "root-certificate.pem"), rootCert, 0644)
		if err != nil {
			log.Fatalf("error writing root-certificate.pem file: %v", err)
		}

		// FIXME: this is going away as part of fixing https://github.com/lf-edge/adam/issues/16
		err = ioutil.WriteFile(path.Join(configDir, "Force-API-V1"), []byte{}, 0644)
		if err != nil {
			log.Fatalf("error writing Force-API-V1 file: %v", err)
		}
		log.Printf("EVE-compatible configuration directory output to %s", configDir)

		s := &server.Server{
			Port:          port,
			Address:       hostIP,
			CertPath:      serverCert,
			KeyPath:       serverKey,
			DeviceManager: mgr,
			CertRefresh:   certRefresh,
		}
		s.Start()
	},
}

func serverInit() {
	// get the default max log sizes
	defaultLogSizes := []string{}
	defaultInfoSizes := []string{}
	defaultMetricSizes := []string{}
	defaultRequestsSizes := []string{}
	defaultAppLogsSizes := []string{}
	for _, m := range deviceManagers {
		defaultLogSizes = append(defaultLogSizes, fmt.Sprintf("%s:%d", m.Name(), m.MaxLogSize()))
		defaultInfoSizes = append(defaultInfoSizes, fmt.Sprintf("%s:%d", m.Name(), m.MaxInfoSize()))
		defaultMetricSizes = append(defaultMetricSizes, fmt.Sprintf("%s:%d", m.Name(), m.MaxMetricSize()))
		defaultRequestsSizes = append(defaultRequestsSizes, fmt.Sprintf("%s:%d", m.Name(), m.MaxRequestsSize()))
		defaultAppLogsSizes = append(defaultAppLogsSizes, fmt.Sprintf("%s:%d", m.Name(), m.MaxAppLogsSize()))
	}
	serverCmd.Flags().StringVar(&port, "port", defaultPort, "port on which to listen")
	serverCmd.Flags().StringVar(&hostIP, "ip", defaultIP, "IP address on which to listen")
	serverCmd.Flags().StringVar(&serverCert, "server-cert", path.Join(defaultDatabaseURL, serverCertFilename), "path to server certificate")
	serverCmd.Flags().StringVar(&serverKey, "server-key", path.Join(defaultDatabaseURL, serverKeyFilename), "path to server key")
	serverCmd.Flags().StringVar(&databaseURL, "db-url", defaultDatabaseURL, "path to directory where we will store and find device information, including onboarding certificates, device certificates, config, logs and metrics. See the readme for more details.")
	serverCmd.Flags().StringVar(&configDir, "conf-dir", defaultConfigDir, "path to directory where running server will output runtime configuration files that can be fed into EVE")
	serverCmd.Flags().BoolVar(&autoCert, "auto-cert", false, "whether to automatically generate certs, if they do not exist; if they do exist, this will be ignored")
	serverCmd.Flags().StringVar(&certCN, "cert-cn", "localhost", "CN for automatically generating of certs, if they do not exist; if they do exist, this will be ignored")
	serverCmd.Flags().StringVar(&certHosts, "cert-hosts", "127.0.0.1,localhost,localhost.localdomain", "hosts for automatically generating of certs, if they do not exist; if they do exist, this will be ignored")
	serverCmd.Flags().IntVar(&certRefresh, "cert-refresh", defaultCertRefresh, "how often, in seconds, to refresh the onboarding and device certs from the filesystem; 0 means not to cache at all.")
	serverCmd.Flags().IntVar(&maxLogSize, "max-log-size", 0, fmt.Sprintf("the maximum size of the logs before rotating. A setting of 0 means to use the default for the particular driver. Those are: %v", defaultLogSizes))
	serverCmd.Flags().IntVar(&maxInfoSize, "max-info-size", 0, fmt.Sprintf("the maximum size of the info before rotating. A setting of 0 means to use the default for the particular driver. Those are: %v", defaultInfoSizes))
	serverCmd.Flags().IntVar(&maxMetricSize, "max-metric-size", 0, fmt.Sprintf("the maximum size of the metrics before rotating. A setting of 0 means to use the default for the particular driver. Those are: %v", defaultMetricSizes))
	serverCmd.Flags().IntVar(&maxRequestsSize, "max-requests-size", 0, fmt.Sprintf("the maximum size of the request logs before rotating. A setting of 0 means to use the default for the particular driver. Those are: %v", defaultRequestsSizes))
	serverCmd.Flags().IntVar(&maxAppLogsSize, "max-app-logs-size", 0, fmt.Sprintf("the maximum size of the app logs before rotating. A setting of 0 means to use the default for the particular driver. Those are: %v", defaultAppLogsSizes))
}
