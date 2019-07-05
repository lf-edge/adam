// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

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
	rootCmd.AddCommand(adminCmd)
	adminInit()
}

// Execute primary function for cobra
func Execute() {
	rootCmd.Execute()
}
