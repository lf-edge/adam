package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zededa/adam/pkg/server"
)

const (
	defaultPort           = "8080"
	defaultClientCertPath = "./run/client-ca.pem"
)

var (
	port           string
	clientCertPath string
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
		}
		s.Start()
	},
}

func serverInit() {
	serverCmd.Flags().StringVar(&port, "port", defaultPort, "port on which to listen")
	serverCmd.Flags().StringVar(&certPath, "certfile", defaultCertPath, "path to server certificate")
	serverCmd.Flags().StringVar(&keyPath, "keyfile", defaultKeyPath, "path to server key")
	serverCmd.Flags().StringVar(&clientCertPath, "client-ca", defaultClientCertPath, "path to CA file that signs client certificates")
	serverCmd.Flags().StringVar(&deviceDatabasePath, "device-db", "", "path to directory where we will store and find device certificates; defaults to in-memory")
	serverCmd.Flags().StringVar(&onboardingDatabasePath, "onboard-db", "", "path to directory where we will find onboarding certificates")
	serverCmd.MarkFlagRequired("onboard-db")
}
