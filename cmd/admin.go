package cmd

import (
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage a running Adam server",
	Long:  `Managed devices and onboard configuration in a running Adam server over https.`,
}

func adminInit() {
	adminCmd.PersistentFlags().StringVar(&serverURL, "server", defaultServerURL, "full URL to running Adam server")
	adminCmd.MarkFlagRequired("server")
	// onboard
	adminCmd.AddCommand(onboardCmd)
	onboardInit()
	// device
	adminCmd.AddCommand(deviceCmd)
	deviceInit()
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
