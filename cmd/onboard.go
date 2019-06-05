package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
	ax "github.com/zededa/adam/pkg/x509"
)

var (
	serials string
)

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Manage onboarding certificates in a running Adam server",
	Long:  `Add, list, remove, clear onboarding certificates`,
}

var onboardListCmd = &cobra.Command{
	Use:   "list",
	Short: "list onboarding certificates and their valid serials",
	Long:  `List the current registered onboarding certificates and their serials`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := resolveUrl(serverURL, "/admin/onboard")
		if err != nil {
			log.Fatalf("error constructing URL: %v", err)
		}
		client := getClient()
		response, err := client.Get(u)
		if err != nil {
			log.Fatalf("error reading URL %s: %v", u, err)
		}
		buf, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalf("unable to read data from URL %s: %v", u, err)
		}
		log.Printf(string(buf))
	},
}

var onboardAddCmd = &cobra.Command{
	Use:   "add",
	Short: "add new onboarding certificate",
	Long:  `Add new onboarding certificate, as well as the valid serials. If the certificate already exists, its serials are replaced by the provided list`,
	Run: func(cmd *cobra.Command, args []string) {
		b, err := ioutil.ReadFile(certPath)
		switch {
		case err != nil && os.IsNotExist(err):
			log.Fatalf("cert file %s does not exist", certPath)
		case err != nil:
			log.Fatalf("error reading cert file %s: %v", certPath, err)
		}
		body := fmt.Sprintf(`{"cert":"%s", "serials":"%s"}`, string(b), serials)
		u, err := resolveUrl(serverURL, "/admin/onboard")
		if err != nil {
			log.Fatalf("error constructing URL: %v", err)
		}
		client := getClient()
		_, err = client.Post(u, jsonContentType, strings.NewReader(body))
		if err != nil {
			log.Fatalf("unable to post data to URL %s: %v", u, err)
		}
	},
}

var onboardRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "remove existing onboard certificate",
	Long:  `Remove an existing onboard certificate. Must specify exactly one of either --cn or --path <cert>.`,
	Run: func(cmd *cobra.Command, args []string) {
		// ensure we specified exactly one of cn or path
		if (cn == "" && certPath == "") || (cn != "" && certPath != "") {
			log.Fatalf("must specify exactly one of --cn or --certPath <path>")
		}
		if certPath != "" {
			cert, err := ax.ReadCert(certPath)
			if err != nil {
				log.Fatalf("error reading cert file %s: %v", certPath, err)
			}
			cn = cert.Subject.CommonName
		}
		u, err := resolveUrl(serverURL, path.Join("/admin/onboard", getFriendlyCN(cn)))
		if err != nil {
			log.Fatalf("error constructing URL: %v", err)
		}
		client := getClient()

		req, err := http.NewRequest("DELETE", u, nil)
		if err != nil {
			log.Fatalf("%s", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("%s", err)
		}
		defer resp.Body.Close()
	},
}

var onboardClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "clear all onboard certificates",
	Long:  `Clear all of the existing onboard certificates. This command is idempotent.`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := resolveUrl(serverURL, "/admin/onboard")
		if err != nil {
			log.Fatalf("error constructing URL: %v", err)
		}
		client := getClient()

		req, err := http.NewRequest("DELETE", u, nil)
		if err != nil {
			log.Fatalf("%s", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("%s", err)
		}
		defer resp.Body.Close()
	},
}

func onboardInit() {
	onboardCmd.PersistentFlags().StringVar(&serverURL, "server", defaultServerURL, "full URL to running Adam server")
	onboardCmd.MarkFlagRequired("server")
	// onboardList
	onboardCmd.AddCommand(onboardListCmd)
	// onboardAdd
	onboardCmd.AddCommand(onboardAddCmd)
	onboardAddCmd.PersistentFlags().StringVar(&serials, "serial", "", "serials to include with the certificate")
	onboardAddCmd.PersistentFlags().StringVar(&certPath, "path", "", "path to certificate to add")
	onboardAddCmd.MarkFlagRequired("path")
	// onboardRemove
	onboardCmd.AddCommand(onboardRemoveCmd)
	onboardRemoveCmd.Flags().StringVar(&cn, "cn", "", "cn of certificate to remove")
	onboardRemoveCmd.Flags().StringVar(&certPath, "path", "", "path to certificate to remove; will read the Common Name from the certificate.")
	// onboardClear
	onboardCmd.AddCommand(onboardClearCmd)
}
