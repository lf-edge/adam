package cmd

const (
	defaultCertPath = "./run/server.pem"
	defaultKeyPath  = "./run/server-key.pem"
)

var (
	certPath               string
	keyPath                string
	hosts                  string
	force                  bool
	onboardingDatabasePath string
	deviceDatabasePath     string
)
