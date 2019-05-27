package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zededa/adam/pkg/server"
)

const (
	defaultPort           = "8080"
	defaultCertRefresh    = 60
	defaultClientCertPath = "./run/client-ca.pem"
)

var (
	port           string
	clientCertPath string
	certRefresh    int
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run an adam server",
	Long:  `Adam is an LF-Edge API compliant Controller. Complete API documentation is available at https://github.com/lf-edge/eve/api/API.md`,
	Run: func(cmd *cobra.Command, args []string) {
		s := &server.Server{
			Port:                   port,
			CertPath:               certPath,
			KeyPath:                keyPath,
			ClientCertPath:         clientCertPath,
			DeviceDatabasePath:     deviceDatabasePath,
			OnboardingDatabasePath: onboardingDatabasePath,
			CertRefresh:            certRefresh,
		}
		s.Start()
	},
}

func serverInit() {
	serverCmd.Flags().StringVar(&port, "port", defaultPort, "port on which to listen")
	serverCmd.Flags().StringVar(&certPath, "certfile", defaultCertPath, "path to server certificate")
	serverCmd.Flags().StringVar(&keyPath, "keyfile", defaultKeyPath, "path to server key")
	serverCmd.Flags().StringVar(&clientCertPath, "client-ca", defaultClientCertPath, "path to CA file that signs client certificates")
	serverCmd.Flags().StringVar(&deviceDatabasePath, "device-db", defaultDeviceDatabasePath, "path to directory where we will store and find device information, including device certificates, config, logs and metrics. See the readme for more details.")
	serverCmd.Flags().StringVar(&onboardingDatabasePath, "onboard-db", defaultOnboardingDatabasePath, "path to directory where we will find onboarding certificates")
	serverCmd.Flags().IntVar(&certRefresh, "cert-refresh", defaultCertRefresh, "how often, in seconds, to refresh the onboarding and device certs from the filesystem; 0 means not to cache at all.")
}
