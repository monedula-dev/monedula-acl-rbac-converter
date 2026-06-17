// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds

import (
	"net/http"
	"testing"
	"time"
)

// respWithRetryAfter builds a bare *http.Response carrying the given
// Retry-After header value, for testing parseRetryAfter directly. The
// integer-seconds path is covered end-to-end by the public retry tests;
// this pins the RFC 7231 HTTP-date branch and the malformed/past cases,
// which the integer path can't reach.
func respWithRetryAfter(v string) *http.Response {
	h := http.Header{}
	if v != "" {
		h.Set("Retry-After", v)
	}
	return &http.Response{Header: h}
}

func TestParseRetryAfter_HTTPDateFuture(t *testing.T) {
	future := time.Now().Add(45 * time.Second).UTC().Format(http.TimeFormat)
	got := parseRetryAfter(respWithRetryAfter(future))
	// Allow a generous window: the call computes time.Until(t), so the
	// observed delay is a little under 45s and never above it.
	if got <= 30*time.Second || got > 46*time.Second {
		t.Errorf("HTTP-date Retry-After ~45s away: got %v, want roughly 45s", got)
	}
}

func TestParseRetryAfter_HTTPDatePastIsZero(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(respWithRetryAfter(past)); got != 0 {
		t.Errorf("a past HTTP-date must yield 0 (don't sleep / sleep negative); got %v", got)
	}
}

func TestParseRetryAfter_Malformed(t *testing.T) {
	for _, v := range []string{"soon", "-5", "not-a-date", "12.5"} {
		if got := parseRetryAfter(respWithRetryAfter(v)); got != 0 {
			t.Errorf("malformed Retry-After %q must yield 0; got %v", v, got)
		}
	}
}

func TestParseRetryAfter_Absent(t *testing.T) {
	if got := parseRetryAfter(respWithRetryAfter("")); got != 0 {
		t.Errorf("absent Retry-After must yield 0; got %v", got)
	}
}

func TestParseRetryAfter_IntegerSeconds(t *testing.T) {
	if got := parseRetryAfter(respWithRetryAfter("7")); got != 7*time.Second {
		t.Errorf("integer Retry-After 7 must yield 7s; got %v", got)
	}
	// Zero is a valid delta-seconds value (retry immediately).
	if got := parseRetryAfter(respWithRetryAfter("0")); got != 0 {
		t.Errorf("Retry-After 0 must yield 0; got %v", got)
	}
}
