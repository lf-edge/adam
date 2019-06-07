package cmd

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/zededa/adam/pkg/server"
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

var deviceGetCmd = &cobra.Command{
	Use:   "get",
	Short: "get an individual device certificate, its onboard certificate, and its onboard serial by UUID",
	Long:  `Get the details of a device, specifically its actual certificate, its onboard certificate (if any), and its onboard serial (if any) by supplying its UUID.`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := resolveURL(serverURL, path.Join("/admin/device", devUUID))
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
		var t server.DeviceCert
		err = json.Unmarshal(buf, &t)
		log.Printf("\nUUID: %s\nDevice Cert:\n%s\nOnboard Cert:\n%s\nOnboard Serial: %s", devUUID, string(t.Cert), string(t.Onboard), string(t.Serial))
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
		body, err := json.Marshal(server.DeviceCert{
			Cert: b,
		})
		if err != nil {
			log.Fatalf("error encoding json: %v", err)
		}
		client := getClient()
		_, err = client.Post(u, jsonContentType, bytes.NewBuffer(body))
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
	// deviceList
	deviceCmd.AddCommand(deviceListCmd)
	// deviceGet
	deviceCmd.AddCommand(deviceGetCmd)
	deviceGetCmd.Flags().StringVar(&devUUID, "uuid", "", "uuid of device to get")
	deviceGetCmd.MarkFlagRequired("uuid")
	// deviceAdd
	deviceCmd.AddCommand(deviceAddCmd)
	deviceAddCmd.Flags().StringVar(&certPath, "path", "", "path to certificate to add")
	deviceAddCmd.MarkFlagRequired("path")
	// deviceRemove
	deviceCmd.AddCommand(deviceRemoveCmd)
	deviceRemoveCmd.Flags().StringVar(&devUUID, "uuid", "", "uuid of device to remove")
	deviceRemoveCmd.MarkFlagRequired("uuid")
	// deviceClear
	deviceCmd.AddCommand(deviceClearCmd)
}
