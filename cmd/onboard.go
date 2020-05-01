// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/lf-edge/adam/pkg/server"
	ax "github.com/lf-edge/adam/pkg/x509"
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
		u, err := resolveURL(serverURL, "/admin/onboard")
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
		fmt.Printf("\n%s\n", string(buf))
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
		body, err := json.Marshal(server.OnboardCert{
			Cert:   b,
			Serial: serials,
		})
		if err != nil {
			log.Fatalf("error encoding json: %v", err)
		}
		u, err := resolveURL(serverURL, "/admin/onboard")
		if err != nil {
			log.Fatalf("error constructing URL: %v", err)
		}
		client := getClient()
		_, err = client.Post(u, jsonContentType, bytes.NewBuffer(body))
		if err != nil {
			log.Fatalf("unable to post data to URL %s: %v", u, err)
		}
	},
}

var onboardGetCmd = &cobra.Command{
	Use:   "get",
	Short: "get an individual onboard certificate and serials by Common Name",
	Long:  `Get the details of an onboard certificate by supplying its Common Name. If it exists, will return the certificate and its valid serials.`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := resolveURL(serverURL, path.Join("/admin/onboard", getFriendlyCN(cn)))
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
		var t server.OnboardCert
		err = json.Unmarshal(buf, &t)
		fmt.Printf("\nCommon Name: %s\n%s\nserials: %s\n", cn, string(t.Cert), string(t.Serial))
	},
}

var onboardRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "remove existing onboard certificate",
	Long:  `Remove an existing onboard certificate. Must specify exactly one of either --cn or --path <cert>.`,
	Run: func(cmd *cobra.Command, args []string) {
		// ensure we specified exactly one of cn or path
		if (cn == "" && certPath == "") || (cn != "" && certPath != "") {
			log.Fatalf("must specify exactly one of --cn or --path <path>")
		}
		if certPath != "" {
			cert, err := ax.ReadCert(certPath)
			if err != nil {
				log.Fatalf("error reading cert file %s: %v", certPath, err)
			}
			cn = cert.Subject.CommonName
		}
		u, err := resolveURL(serverURL, path.Join("/admin/onboard", getFriendlyCN(cn)))
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
		u, err := resolveURL(serverURL, "/admin/onboard")
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
	// onboardList
	onboardCmd.AddCommand(onboardListCmd)
	// onboardGet
	onboardCmd.AddCommand(onboardGetCmd)
	onboardGetCmd.Flags().StringVar(&cn, "cn", "", "cn of certificate to get details")
	onboardGetCmd.MarkFlagRequired("cn")
	// onboardAdd
	onboardCmd.AddCommand(onboardAddCmd)
	onboardAddCmd.Flags().StringVar(&serials, "serial", "", "serials to include with the certificate")
	onboardAddCmd.Flags().StringVar(&certPath, "path", "", "path to certificate to add")
	onboardAddCmd.MarkFlagRequired("path")
	// onboardRemove
	onboardCmd.AddCommand(onboardRemoveCmd)
	onboardRemoveCmd.Flags().StringVar(&cn, "cn", "", "cn of certificate to remove")
	onboardRemoveCmd.Flags().StringVar(&certPath, "path", "", "path to certificate to remove; will read the Common Name from the certificate.")
	// onboardClear
	onboardCmd.AddCommand(onboardClearCmd)
}
