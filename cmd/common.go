package cmd

import (
	"net/http"
	"path"
	"regexp"
	"time"
)

const (
	serverCertFilename = "server.pem"
	serverKeyFilename  = "server-key.pem"
	defaultDatabaseURL = "./run/adam"
	defaultServerURL   = "https://localhost:8080"
	jsonContentType    = "application/json"
	textContentType    = "text/plain"
)

var (
	cn          string
	certPath    string
	keyPath     string
	hosts       string
	force       bool
	databaseURL string
	serverURL   string
)

func getFriendlyCN(cn string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9\\.\\-]`)
	return re.ReplaceAllString(cn, "_")
}

func getOnboardCertPath(cn string) string {
	return path.Join(getOnboardCertBase(), getFriendlyCN(cn))
}
func getOnboardCertBase() string {
	return path.Join(databaseURL, "onboard")
}
func getDeviceBase() string {
	return path.Join(databaseURL, "device")
}

// http client with correct config
func getClient() *http.Client {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	return client
}
