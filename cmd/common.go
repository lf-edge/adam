package cmd

import (
	"path"
	"regexp"
)

const (
	defaultCertPath               = "./run/server.pem"
	defaultKeyPath                = "./run/server-key.pem"
	defaultDeviceDatabasePath     = "./run/device"
	defaultOnboardingDatabasePath = "./run/onboard"
)

var (
	cn                     string
	certPath               string
	keyPath                string
	hosts                  string
	force                  bool
	onboardingDatabasePath string
	deviceDatabasePath     string
)

func getOnboardCertName(cn string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9\\.\\-]`)
	return re.ReplaceAllString(cn, "_")
}

func getOnboardCertPath(cn string) string {
	return path.Join(onboardingDatabasePath, getOnboardCertName(cn))
}
