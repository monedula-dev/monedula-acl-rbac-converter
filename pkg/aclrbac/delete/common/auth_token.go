// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package common

import (
	"crypto/rand"
	"encoding/hex"
)

// NewAuthToken returns a 64-hex-char random token used as RUNTIME_AUTH_TOKEN
// for delete-deny-one invocation. Generated fresh per `delete-deny-acls` run.
func NewAuthToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
