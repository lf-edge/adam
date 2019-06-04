package cmd

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/satori/go.uuid"
	"github.com/spf13/cobra"
	"github.com/zededa/adam/pkg/server"
	"github.com/zededa/adam/pkg/x509"
)

const (
	defaultPrivateKeyPath = "./run/private"
)

var (
	privatePath string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate certs for the Adam server and clients",
	Long:  `Generate the necessary certs for the Adam server and clients`,
}

var generateServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Generate server certs",
	Long:  `Generate the necessary server certs`,
	Run: func(cmd *cobra.Command, args []string) {
		// create dir if it does not exist
		var err error
		err = os.MkdirAll(filepath.Dir(certPath), 0755)
		if err != nil {
			log.Fatalf("error creating cert directory: %v", err)
		}
		err = os.MkdirAll(filepath.Dir(keyPath), 0755)
		if err != nil {
			log.Fatalf("error creating key directory: %v", err)
		}
		err = x509.GenerateAndWrite("", hosts, certPath, keyPath, force)
		if err != nil {
			log.Fatalf("error generating key/cert: %v", err)
		}
		log.Printf("saved new server certificate to %s", certPath)
		log.Printf("saved new server key to %s", keyPath)
	},
}

var generateOnboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Generate onboarding certs",
	Long:  `Generate an onboarding cert. The cert will be saved in the provided path, named by the CN, e.g. onboard/company-a/certificate.pem and onboard/company-a/key.pem.`,
	Run: func(cmd *cobra.Command, args []string) {
		onboardingDatabasePath := getOnboardCertBase()
		fi, err := os.Stat(onboardingDatabasePath)
		if err == nil && !fi.IsDir() {
			log.Fatalf("onboarding database path %s exists but is not a directory", onboardingDatabasePath)
		}
		onboardPath := getOnboardCertPath(cn)
		// we use MkdirAll, since we are willing to continue if the directory already exists; we only error if we cannot make it,
		//   or if the _files_ already exist
		err = os.MkdirAll(onboardPath, 0755)
		if err != nil {
			log.Fatalf("could not create onboarding certificate path %s: %v", onboardPath, err)
		}
		err = os.MkdirAll(privatePath, 0700)
		if err != nil {
			log.Fatalf("could not create private path %s: %v", privatePath, err)
		}
		certFile := path.Join(onboardPath, server.DeviceOnboardFilename)
		keyFile := path.Join(privatePath, fmt.Sprintf("onboard-%s-key.pem", getOnboardCertName(cn)))
		err = x509.GenerateAndWrite(cn, "", certFile, keyFile, force)
		if err != nil {
			log.Fatalf("error generating key/cert: %v", err)
		}
		log.Printf("saved new onboard certificate to %s", certFile)
		log.Printf("saved new onboard key to %s", keyFile)
	},
}

var generateDeviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Generate individual device certs",
	Long:  `Generate a device cert. The cert will be saved in the provided path with a newly generated UUID`,
	Run: func(cmd *cobra.Command, args []string) {
		deviceDatabasePath := getDeviceBase()
		fi, err := os.Stat(deviceDatabasePath)
		if err == nil && !fi.IsDir() {
			log.Fatalf("device database path %s exists but is not a directory", deviceDatabasePath)
		}
		// generate a new uuid
		unew, err := uuid.NewV4()
		if err != nil {
			log.Fatalf("error generating uuid for device: %v", err)
		}

		devicePath := server.GetDevicePath(databaseURL, unew)
		err = os.MkdirAll(devicePath, 0755)
		if err != nil {
			log.Fatalf("error creating new device tree %s: %v", devicePath, err)
		}
		err = os.MkdirAll(privatePath, 0700)
		if err != nil {
			log.Fatalf("could not create private path %s: %v", privatePath, err)
		}
		// generate the certificate
		certFile := path.Join(devicePath, server.DeviceCertFilename)
		keyFile := path.Join(privatePath, fmt.Sprintf("device-%s-key.pem", unew.String()))
		err = x509.GenerateAndWrite(cn, "", certFile, keyFile, false)
		if err != nil {
			log.Fatalf("error generating key/cert: %v", err)
		}
		log.Printf("saved new device certificate to %s", certFile)
		log.Printf("saved new device key to %s", keyFile)
	},
}

func generateInit() {
	generateCmd.PersistentFlags().StringVar(&databaseURL, "db-url", defaultDatabaseURL, "path to directory where the device database is stored; we will store the generated onboarding certificates in the appropriate subdirectory")
	// generate server
	generateCmd.AddCommand(generateServerCmd)
	generateServerCmd.Flags().StringVar(&certPath, "certfile", defaultCertPath, "path to server certificate")
	generateServerCmd.Flags().StringVar(&keyPath, "keyfile", defaultKeyPath, "path to server key")
	generateServerCmd.Flags().StringVar(&hosts, "hosts", "", "hostnames and/or IPs to use in the certificate, separated by ',', output to the certfile and keyfile; will not replace if they exist")
	generateServerCmd.MarkFlagRequired("hosts")
	generateServerCmd.Flags().BoolVar(&force, "force", false, "replace existing files")

	// generate onboarding certs
	generateCmd.AddCommand(generateOnboardCmd)
	generateOnboardCmd.Flags().StringVar(&cn, "cn", "", "CN to use in the certificate; will not replace if one with the same CN exists")
	generateOnboardCmd.MarkFlagRequired("cn")
	generateOnboardCmd.Flags().StringVar(&privatePath, "keypath", defaultPrivateKeyPath, "path to directory where we will store the generated onboarding key")
	generateOnboardCmd.Flags().BoolVar(&force, "force", false, "replace existing files")

	// generate device certs
	generateCmd.AddCommand(generateDeviceCmd)
	generateDeviceCmd.Flags().StringVar(&cn, "cn", "", "CN to use in the certificate; will not replace if one with the same CN exists")
	generateDeviceCmd.MarkFlagRequired("cn")
	generateDeviceCmd.Flags().StringVar(&privatePath, "keypath", defaultPrivateKeyPath, "path to directory where we will store the generated device key")
	generateDeviceCmd.Flags().BoolVar(&force, "force", false, "replace existing files")
}
