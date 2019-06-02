package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

var (
	newSerial string
)

var serialsCmd = &cobra.Command{
	Use:   "serials",
	Short: "manage serials for onboarding certificates",
	Long:  `Add, list, remove, clear serials for use with an onboarding certificate`,
}

var serialsListCmd = &cobra.Command{
	Use:   "list",
	Short: "list current serials",
	Long:  `List the current serials for a given cn cert`,
	Run: func(cmd *cobra.Command, args []string) {
		if onboardingDatabasePath == "" {
			log.Fatalf("onboarding path must be set")
		}
		fi, err := os.Stat(onboardingDatabasePath)
		if err != nil {
			log.Fatalf("onboarding database path %s does not exist", onboardingDatabasePath)
		}
		if !fi.IsDir() {
			log.Fatalf("onboarding database path %s is not a directory", onboardingDatabasePath)
		}
		serials, err := loadCurrentSerials(cn)
		if err != nil {
			log.Fatalf("error loading current serials: %v", err)
		}
		fmt.Println(strings.Join(serials, "\n"))
	},
}

var serialsAddCmd = &cobra.Command{
	Use:   "add",
	Short: "add new serial",
	Long:  `Add new serial, to the current serials for a given cn cert`,
	Run: func(cmd *cobra.Command, args []string) {
		if onboardingDatabasePath == "" {
			log.Fatalf("onboarding path must be set")
		}
		fi, err := os.Stat(onboardingDatabasePath)
		if err != nil {
			log.Fatalf("onboarding database path %s does not exist", onboardingDatabasePath)
		}
		if !fi.IsDir() {
			log.Fatalf("onboarding database path %s is not a directory", onboardingDatabasePath)
		}
		serials, err := loadCurrentSerials(cn)
		if err != nil {
			log.Fatalf("error loading current serials: %v", err)
		}
		// go through the existing strings and add if needed
		for _, ser := range serials {
			// if it already is there, nothing to do
			if ser == newSerial {
				return
			}
		}
		serials = append(serials, newSerial)
		err = saveCurrentSerials(cn, serials)
		if err != nil {
			log.Fatalf("error saving current serials: %v", err)
		}
	},
}

var serialsRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "remove existing serial",
	Long:  `Remove an existing serial from the list`,
	Run: func(cmd *cobra.Command, args []string) {
		if onboardingDatabasePath == "" {
			log.Fatalf("onboarding path must be set")
		}
		fi, err := os.Stat(onboardingDatabasePath)
		if err != nil {
			log.Fatalf("onboarding database path %s does not exist", onboardingDatabasePath)
		}
		if !fi.IsDir() {
			log.Fatalf("onboarding database path %s is not a directory", onboardingDatabasePath)
		}
		serials, err := loadCurrentSerials(cn)
		if err != nil {
			log.Fatalf("error loading current serials: %v", err)
		}
		// go through the existing strings and remove if needed
		newSerials := make([]string, 0)
		for _, ser := range serials {
			// if it already is there, nothing to do
			if ser != newSerial {
				newSerials = append(newSerials, newSerial)
			}
		}
		err = saveCurrentSerials(cn, newSerials)
		if err != nil {
			log.Fatalf("error saving current serials: %v", err)
		}
	},
}

var serialsClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "clear current serials",
	Long:  `Clear all of the serials for a given cn cert`,
	Run: func(cmd *cobra.Command, args []string) {
		if onboardingDatabasePath == "" {
			log.Fatalf("onboarding path must be set")
		}
		fi, err := os.Stat(onboardingDatabasePath)
		if err != nil {
			log.Fatalf("onboarding database path %s does not exist", onboardingDatabasePath)
		}
		if !fi.IsDir() {
			log.Fatalf("onboarding database path %s is not a directory", onboardingDatabasePath)
		}
		// we could just do os.Open and then f.Truncate, but trying to be consistent
		_, err = loadCurrentSerials(cn)
		if err != nil {
			log.Fatalf("error loading current serials: %v", err)
		}
		err = saveCurrentSerials(cn, []string{})
		if err != nil {
			log.Fatalf("error saving current serials: %v", err)
		}
	},
}

func serialsInit() {
	serialsCmd.PersistentFlags().StringVar(&onboardingDatabasePath, "onboard-db", defaultOnboardingDatabasePath, "path to directory where we will store the serials")
	serialsCmd.PersistentFlags().StringVar(&cn, "cn", "", "CN whose certificate will match the serials")
	serialsCmd.MarkFlagRequired("cn")
	// serialsList
	serialsCmd.AddCommand(serialsListCmd)
	// serialsAdd
	serialsCmd.AddCommand(serialsAddCmd)
	serialsAddCmd.PersistentFlags().StringVar(&newSerial, "serial", "", "serial to add to the certificate as valid")
	serialsAddCmd.MarkFlagRequired("serial")
	// serialsRemove
	serialsCmd.AddCommand(serialsRemoveCmd)
	serialsRemoveCmd.PersistentFlags().StringVar(&newSerial, "serial", "", "serial to remove from the certificate as valid")
	serialsRemoveCmd.MarkFlagRequired("serial")
	// serialsClear
	serialsCmd.AddCommand(serialsClearCmd)
}

func loadCurrentSerials(cn string) ([]string, error) {
	serialsPath := getOnboardSerialsPath(cn)
	b, err := ioutil.ReadFile(serialsPath)
	switch {
	case err != nil && os.IsNotExist(err):
		return []string{}, nil
	case err != nil:
		return nil, fmt.Errorf("error opening serials file %s to read: %v", serialsPath, err)
	default:
		return strings.Fields(string(b)), nil
	}
}

func saveCurrentSerials(cn string, serials []string) error {
	serialsPath := getOnboardSerialsPath(cn)
	err := ioutil.WriteFile(serialsPath, []byte(strings.Join(serials, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("error writing new serials file %s: %v", serialsPath, err)
	}
	return nil
}

func getOnboardSerialsPath(cn string) string {
	return path.Join(getOnboardCertPath(cn), "serials.txt")
}
