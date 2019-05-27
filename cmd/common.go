package cmd

const (
	defaultCertPath               = "./run/server.pem"
	defaultKeyPath                = "./run/server-key.pem"
	defaultDeviceDatabasePath     = "./run/device"
	defaultOnboardingDatabasePath = "./run/onboard"
)

var (
	certPath               string
	keyPath                string
	hosts                  string
	force                  bool
	onboardingDatabasePath string
	deviceDatabasePath     string
)
