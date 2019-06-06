package cmd

import (
	"net/http"
	"net/url"
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

// http client with correct config
func getClient() *http.Client {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	return client
}
func resolveURL(b, p string) (string, error) {
	u, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	base, err := url.Parse(b)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}
