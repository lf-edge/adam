// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"time"

	"github.com/lf-edge/adam/pkg/driver"
	uuid "github.com/satori/go.uuid"
)

type ApiRequestv2 struct {
	Timestamp time.Time `json:"timestamp"`
	UUID      uuid.UUID `json:"uuid,omitempty"`
	ClientIP  string    `json:"client-ip"`
	Forwarded string    `json:"forwarded,omitempty"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
}

type apiHandlerv2 struct {
	manager     driver.DeviceManager
	logChannel  chan []byte
	infoChannel chan []byte
}
