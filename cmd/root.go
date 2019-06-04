package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "adam"}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverInit()
	rootCmd.AddCommand(generateCmd)
	generateInit()
	rootCmd.AddCommand(serialsCmd)
	serialsInit()
}

// Execute primary function for cobra
func Execute() {
	rootCmd.Execute()
}
