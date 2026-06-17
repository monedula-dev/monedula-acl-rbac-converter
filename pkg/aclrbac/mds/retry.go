// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Default retry tuning. Field-overridable on Config so tests can run fast.
// Note: there is no defaultMaxRetries — the CLI sets the flag default
// (currently 3) so library callers must pick a value explicitly. A
// zero MaxRetries literally means "no retries".
const (
	defaultRetryBase     = 100 * time.Millisecond
	defaultRetryCap      = 5 * time.Second
	defaultRetryAfterCap = 60 * time.Second
)

// shouldRetry classifies an error / response status as transient.
// Returns (retry?, delay-hint-from-server-or-zero).
func shouldRetry(resp *http.Response, err error) (bool, time.Duration) {
	if err != nil {
		// Network-class errors. We retry on:
		//   - io.EOF (server closed connection mid-request)
		//   - net.ErrClosed (we closed; usually a transient pool issue)
		//   - *net.OpError with Op == "dial" / "read" / "write"
		// We do NOT retry on context cancellation (operator intent).
		if errors.Is(err, io.EOF) {
			return true, 0
		}
		if errors.Is(err, net.ErrClosed) {
			return true, 0
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			switch opErr.Op {
			case "dial", "read", "write":
				return true, 0
			}
		}
		return false, 0
	}

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return true, parseRetryAfter(resp)
	case http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true, 0
	}
	return false, 0
}

// parseRetryAfter reads the Retry-After response header per RFC 7231.
// Accepts either a delta-seconds integer or an HTTP-date.
func parseRetryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

// backoffDelay computes the delay before the n-th retry attempt
// (n=1 first retry, n=2 second, etc.). base * 2^(n-1) with +/-25%
// jitter, capped at maxDelay. n must be >= 1.
func backoffDelay(n int, base, maxDelay time.Duration) time.Duration {
	if n < 1 {
		n = 1
	}
	d := base << (n - 1)
	if d <= 0 || d > maxDelay {
		d = maxDelay
	}
	// rand.Int64N panics on a non-positive argument. With a sub-2ns
	// RetryBase (or maxDelay), int64(d)/2 truncates to 0; clamp the jitter
	// span to at least 1 so a tiny RetryBase never panics.
	half := int64(d) / 2
	if half <= 0 {
		half = 1
	}
	jitter := time.Duration(rand.Int64N(half)) // 0..d/2
	d = d - d/4 + jitter                       // [0.75d, 1.25d)
	return d
}
