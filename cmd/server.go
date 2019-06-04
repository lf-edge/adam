package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zededa/adam/pkg/server"
)

const (
	defaultPort        = "8080"
	defaultCertRefresh = 60
)

var (
	port           string
	clientCertPath string
	certRefresh    int
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Adam server",
	Long:  `Adam is an LF-Edge API compliant Controller. Complete API documentation is available at https://github.com/lf-edge/eve/api/API.md`,
	Run: func(cmd *cobra.Command, args []string) {
		s := &server.Server{
			Port:        port,
			CertPath:    certPath,
			KeyPath:     keyPath,
			DatabaseURL: databaseURL,
			CertRefresh: certRefresh,
		}
		s.Start()
	},
}

func serverInit() {
	serverCmd.Flags().StringVar(&port, "port", defaultPort, "port on which to listen")
	serverCmd.Flags().StringVar(&certPath, "server-cert", defaultCertPath, "path to server certificate")
	serverCmd.Flags().StringVar(&keyPath, "server-key", defaultKeyPath, "path to server key")
	serverCmd.Flags().StringVar(&databaseURL, "db-url", defaultDatabaseURL, "path to directory where we will store and find device information, including onboarding certificates, device certificates, config, logs and metrics. See the readme for more details.")
	serverCmd.Flags().IntVar(&certRefresh, "cert-refresh", defaultCertRefresh, "how often, in seconds, to refresh the onboarding and device certs from the filesystem; 0 means not to cache at all.")
}
