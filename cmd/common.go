package cmd

import (
	"path"
	"regexp"
)

const (
	defaultCertPath    = "./run/adam/server.pem"
	defaultKeyPath     = "./run/adam/server-key.pem"
	defaultDatabaseURL = "./run/adam"
)

var (
	cn          string
	certPath    string
	keyPath     string
	hosts       string
	force       bool
	databaseURL string
)

func getOnboardCertName(cn string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9\\.\\-]`)
	return re.ReplaceAllString(cn, "_")
}

func getOnboardCertPath(cn string) string {
	return path.Join(getOnboardCertBase(), getOnboardCertName(cn))
}
func getOnboardCertBase() string {
	return path.Join(databaseURL, "onboard")
}
func getDeviceBase() string {
	return path.Join(databaseURL, "device")
}
