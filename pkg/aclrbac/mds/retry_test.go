// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

// flakyServer returns a server that fails the first N requests with the
// given status code, then returns 204 ok thereafter.
func flakyServer(failures int, status int) (*httptest.Server, *int64) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt64(&calls, 1)
		if c <= int64(failures) {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return srv, &calls
}

func TestRetry_500_RecoversWithRetries(t *testing.T) {
	srv, calls := flakyServer(2, http.StatusInternalServerError)
	defer srv.Close()

	cl, err := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get("/security/1.0/something")
	if err != nil {
		t.Fatalf("Get: %v (call count %d)", err, atomic.LoadInt64(calls))
	}
	resp.Body.Close()
	if got := atomic.LoadInt64(calls); got != 3 {
		t.Errorf("expected 3 calls (2 retries + 1 success), got %d", got)
	}
}

func TestRetry_503_AbortsAfterMaxRetries(t *testing.T) {
	srv, calls := flakyServer(99, http.StatusServiceUnavailable)
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", MaxRetries: 2})
	if _, err := cl.Get("/x"); err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	if got := atomic.LoadInt64(calls); got != 3 {
		t.Errorf("expected 3 calls, got %d", got)
	}
}

func TestRetry_4xx_DoesNotRetry(t *testing.T) {
	srv, calls := flakyServer(99, http.StatusBadRequest)
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", MaxRetries: 5})
	if _, err := cl.Get("/x"); err == nil {
		t.Fatal("expected error on 400")
	}
	if got := atomic.LoadInt64(calls); got != 1 {
		t.Errorf("4xx should not retry; got %d calls", got)
	}
}

func TestRetry_401_DoesNotRetry(t *testing.T) {
	srv, calls := flakyServer(99, http.StatusUnauthorized)
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", MaxRetries: 5})
	_, err := cl.Get("/x")
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !mds.IsAuthError(err) {
		t.Errorf("401 response should be IsAuthError; got %v", err)
	}
	if got := atomic.LoadInt64(calls); got != 1 {
		t.Errorf("401 should not retry; got %d calls", got)
	}
}

func TestRetry_429_HonoursRetryAfter(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt64(&calls, 1)
		if c == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", MaxRetries: 3})
	start := time.Now()
	resp, err := cl.Get("/x")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if elapsed < 900*time.Millisecond {
		t.Errorf("Retry-After should delay >= 1s; got %v", elapsed)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("expected 2 calls; got %d", got)
	}
}

func TestRetry_ZeroMaxRetries_NoRetries(t *testing.T) {
	// Library callers using mds.NewClient directly with the zero value
	// for MaxRetries get exactly one attempt (no retries). The CLI
	// flag default of 3 lives in the cobra registration, not here.
	srv, calls := flakyServer(99, http.StatusInternalServerError)
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t"})
	if _, err := cl.Get("/x"); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt64(calls); got != 1 {
		t.Errorf("MaxRetries=0 should produce exactly 1 call; got %d", got)
	}
}

// TestRetry_TinyRetryBase_NoPanic is the B15 regression guard: a sub-2ns
// RetryBase makes int64(d)/2 truncate to 0, which would panic rand.Int64N.
// Drive the public retry loop with a 1ns base against a flaky server and
// assert it recovers (no panic, retries happen).
func TestRetry_TinyRetryBase_NoPanic(t *testing.T) {
	srv, calls := flakyServer(2, http.StatusInternalServerError)
	defer srv.Close()

	cl, err := mds.NewClient(mds.Config{
		URL:        srv.URL,
		Token:      "t",
		MaxRetries: 3,
		RetryBase:  1 * time.Nanosecond,
		RetryCap:   1 * time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get("/security/1.0/something")
	if err != nil {
		t.Fatalf("Get with tiny RetryBase: %v (call count %d)", err, atomic.LoadInt64(calls))
	}
	resp.Body.Close()
	if got := atomic.LoadInt64(calls); got != 3 {
		t.Errorf("expected 3 calls (2 retries + 1 success), got %d", got)
	}
}

func TestRetry_RetryAfter_Cap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", strconv.Itoa(99999))
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	cl, _ := mds.NewClient(mds.Config{URL: srv.URL, Token: "t", MaxRetries: 1, RetryAfterCap: 100 * time.Millisecond})
	start := time.Now()
	if _, err := cl.Get("/x"); err == nil {
		t.Fatal("expected exhaustion error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Retry-After cap not honoured; elapsed %v", elapsed)
	}
}
