package cmd

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/spf13/cobra"
)

var (
	devUUID string
)

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Manage registered devices in a running Adam server",
	Long:  `Add, list, remove, clear devices`,
}

var deviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "list UUIDs of known devices",
	Long:  `List the current registered UUIDs`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := resolveURL(serverURL, "/admin/device")
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

var deviceAddCmd = &cobra.Command{
	Use:   "add",
	Short: "add new device",
	Long:  `Add new device and retrieve the UUID`,
	Run: func(cmd *cobra.Command, args []string) {
		b, err := ioutil.ReadFile(certPath)
		switch {
		case err != nil && os.IsNotExist(err):
			log.Fatalf("cert file %s does not exist", certPath)
		case err != nil:
			log.Fatalf("error reading cert file %s: %v", certPath, err)
		}
		u, err := resolveURL(serverURL, "/admin/device")
		if err != nil {
			log.Fatalf("error constructing URL: %v", err)
		}
		client := getClient()
		_, err = client.Post(u, textContentType, bytes.NewReader(b))
		if err != nil {
			log.Fatalf("unable to post data to URL %s: %v", u, err)
		}
	},
}

var deviceRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "remove registered device",
	Long:  `Remove a registered device`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := resolveURL(serverURL, path.Join("/admin/device", devUUID))
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

var deviceClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "clear all registered devices",
	Long:  `Clear all of the registered devices. This command is idempotent.`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := resolveURL(serverURL, "/admin/device")
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

func deviceInit() {
	deviceCmd.PersistentFlags().StringVar(&serverURL, "server", defaultServerURL, "full URL to running Adam server")
	deviceCmd.MarkFlagRequired("server")
	// deviceList
	deviceCmd.AddCommand(deviceListCmd)
	// deviceAdd
	deviceCmd.AddCommand(deviceAddCmd)
	deviceAddCmd.Flags().StringVar(&certPath, "path", "", "path to certificate to add")
	deviceAddCmd.MarkFlagRequired("path")
	// deviceRemove
	deviceCmd.AddCommand(deviceRemoveCmd)
	deviceRemoveCmd.Flags().StringVar(&devUUID, "uuid", "", "uuid of device to remove")
	// deviceClear
	deviceCmd.AddCommand(deviceClearCmd)
}
