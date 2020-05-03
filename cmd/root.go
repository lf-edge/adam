// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{Use: "adam"}

func init() {
	viper.SetEnvPrefix("adam")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

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
