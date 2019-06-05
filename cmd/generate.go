package cmd

import (
	"fmt"
	"log"
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/zededa/adam/pkg/x509"
)

const (
	defaultPrivateKeyPath = "./run/private"
)

var (
	outpath      string
	isServerCert bool
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate keys and certs",
	Long:  `Generate keys and certs. The keys and certs will be saved in the provided output path named by CN, e.g. run/private/company-a.pem and run/private/company-a-key.pem. If the --server option is provided, then they will be saved in the appropriate database for the server with the appropriate names.`,
	Run: func(cmd *cobra.Command, args []string) {
		outputDir := outpath
		cnFriendly := getFriendlyCN(cn)
		certFilename := fmt.Sprintf("%s.pem", cnFriendly)
		keyFilename := fmt.Sprintf("%s-key.pem", cnFriendly)
		certType := "generic"
		if isServerCert {
			outputDir = databaseURL
			certFilename = serverCertFilename
			keyFilename = serverKeyFilename
			certType = "server"
		}
		// we use MkdirAll, since we are willing to continue if the directory already exists; we only error if we cannot make it,
		//   or if the _files_ already exist
		err := os.MkdirAll(outputDir, 0755)
		if err != nil {
			log.Fatalf("failed to make directory %s: %v", outputDir, err)
		}
		certFile := path.Join(outputDir, certFilename)
		keyFile := path.Join(outputDir, keyFilename)
		err = x509.GenerateAndWrite(cn, hosts, certFile, keyFile, force)
		if err != nil {
			log.Fatalf("error generating key/cert: %v", err)
		}
		log.Printf("saved new %s certificate to %s", certType, certFile)
		log.Printf("saved new %s key to %s", certType, keyFile)
	},
}

func generateInit() {
	generateCmd.Flags().StringVar(&databaseURL, "db-url", defaultDatabaseURL, "path to directory where the device database is stored; we will store the generated onboarding certificates in the appropriate subdirectory")
	// generate server
	generateCmd.Flags().StringVar(&hosts, "hosts", "", "hostnames and/or IPs to use in the certificate, separated by ',', output to the certfile and keyfile; will not replace if they exist")
	generateCmd.MarkFlagRequired("hosts")
	generateCmd.Flags().StringVar(&cn, "cn", "", "CN to use in the certificate")
	generateCmd.MarkFlagRequired("cn")
	generateCmd.Flags().StringVar(&outpath, "out", defaultPrivateKeyPath, "path to directory where we will store the keys and certificates. If --server provided, this is ignored.")
	generateCmd.Flags().BoolVar(&isServerCert, "server", false, "save key and cert in server database directory with appropriate filenames")
	generateCmd.Flags().BoolVar(&force, "force", false, "replace existing files")
}
