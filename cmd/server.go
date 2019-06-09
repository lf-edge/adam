package cmd

import (
	"log"
	"path"

	"github.com/spf13/cobra"
	"github.com/zededa/adam/pkg/driver"
	"github.com/zededa/adam/pkg/server"
)

const (
	defaultPort        = "8080"
	defaultCertRefresh = 60
)

var (
	serverCert     string
	serverKey      string
	port           string
	clientCertPath string
	certRefresh    int
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Adam server",
	Long:  `Adam is an LF-Edge API compliant Controller. Complete API documentation is available at https://github.com/lf-edge/eve/api/API.md`,
	Run: func(cmd *cobra.Command, args []string) {
		// create a handler based on where our device database is
		// in the future, we may support other device manager types
		var mgr driver.DeviceManager
		for _, m := range driver.GetDeviceManagers() {
			name := m.Name()
			valid, err := m.Init(databaseURL)
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

		s := &server.Server{
			Port:          port,
			CertPath:      serverCert,
			KeyPath:       serverKey,
			DeviceManager: mgr,
			CertRefresh:   certRefresh,
		}
		s.Start()
	},
}

func serverInit() {
	serverCmd.Flags().StringVar(&port, "port", defaultPort, "port on which to listen")
	serverCmd.Flags().StringVar(&serverCert, "server-cert", path.Join(defaultDatabaseURL, serverCertFilename), "path to server certificate")
	serverCmd.Flags().StringVar(&serverKey, "server-key", path.Join(defaultDatabaseURL, serverKeyFilename), "path to server key")
	serverCmd.Flags().StringVar(&databaseURL, "db-url", defaultDatabaseURL, "path to directory where we will store and find device information, including onboarding certificates, device certificates, config, logs and metrics. See the readme for more details.")
	serverCmd.Flags().IntVar(&certRefresh, "cert-refresh", defaultCertRefresh, "how often, in seconds, to refresh the onboarding and device certs from the filesystem; 0 means not to cache at all.")
}
