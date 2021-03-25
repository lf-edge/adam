// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"embed"
)

// Embed the static directory
//go:embed static
var StaticFiles embed.FS
