// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"regexp"
)

const (
	serverCertFilename  = "server.pem"
	serverKeyFilename   = "server-key.pem"
	signingCertFilename = "signing.pem"
	signingKeyFilename  = "signing-key.pem"
	encryptCertFilename = "encrypt.pem"
	encryptKeyFilename  = "encrypt-key.pem"
	defaultDatabaseURL  = "./run/adam"
	defaultConfigDir    = "./run/config"
	jsonContentType     = "application/json"
)

var (
	cn          string
	certPath    string
	hosts       string
	force       bool
	databaseURL string
	configDir   string
)

func getFriendlyCN(cn string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9\\.\\-]`)
	return re.ReplaceAllString(cn, "_")
}
