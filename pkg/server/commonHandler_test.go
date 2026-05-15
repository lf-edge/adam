// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/adam/pkg/driver/memory"
	ax "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve-api/go/register"
)

// TestRegisterProcessForbiddenForUnknownCert verifies that when the
// auth-container signature has already verified upstream but the (cert,
// serial) tuple is not in the controller's pre-registration set,
// registerProcess returns 403 Forbidden — per APIv2.md /register:
// "Valid credentials without authorization: 403".
//
// Prior to this fix the same condition mapped to 401 Unauthorized, which
// confused "missing/invalid credentials" with "valid credentials, not
// pre-registered" and prevented EVE's cmd/client from raising
// LedBlinkOnboardingFailureNotFound (which is keyed off 403).
func TestRegisterProcessForbiddenForUnknownCert(t *testing.T) {
	dm := &memory.DeviceManager{}

	certB, _, err := ax.Generate("CN=test-onboard", "")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certB)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	msg := &register.ZRegisterMsg{Serial: "test-serial"}
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal register message: %v", err)
	}

	status, err := registerProcess(dm, msgBytes, cert)
	if status != http.StatusForbidden {
		t.Errorf("status: got %d, want %d (%s)", status, http.StatusForbidden, http.StatusText(http.StatusForbidden))
	}
	if err == nil {
		t.Error("err: got nil, want non-nil (failure should carry context)")
	}
}
