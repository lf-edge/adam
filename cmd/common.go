package cmd

import (
	"path"
	"regexp"
)

const (
	defaultCertPath               = "./run/adam/server.pem"
	defaultKeyPath                = "./run/adam/server-key.pem"
	defaultDeviceDatabasePath     = "./run/adam/device"
	defaultOnboardingDatabasePath = "./run/adam/onboard"
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
