// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package live (this file) — package-private helpers for parsing Kafka
// client.properties files and the limited subset of JAAS configuration
// the live adapter recognises. The exported surface lives in live.go.
package live

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// parseProperties reads a Java client.properties file. It supports
// '#' and '!' comments, leading/trailing whitespace stripping,
// '=' and ':' key/value separators, and '\' line continuations.
// Keys are case-sensitive; later assignments override earlier ones.
//
// Per the Java Properties spec, line continuations strip leading
// whitespace from each continuation line so that indenting the
// continued lines is purely cosmetic.
func parseProperties(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("properties: open %s: %w", path, err)
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var pending string
	inContinuation := false
	// lineno tracks the physical source line that begins the current
	// (possibly continuation-joined) logical line, so the malformed-line
	// error can name a precise location without echoing the line content.
	// Echoing the content would leak credentials when the malformed line
	// is a misformatted sasl.jaas.config — its value typically contains
	// username="..." password="..." pairs.
	lineno := 0
	startLine := 0
	for sc.Scan() {
		lineno++
		line := sc.Text()
		// On a continuation, drop the leading whitespace introduced by
		// indenting the wrapped value in the source file. Java's
		// Properties.load behaves the same way.
		if inContinuation {
			line = strings.TrimLeft(line, " \t")
		} else {
			startLine = lineno
		}
		// Strip trailing whitespace before checking for a continuation
		// marker; spaces preceding the backslash should not survive.
		trimmedRight := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmedRight, "\\") {
			pending += strings.TrimSuffix(trimmedRight, "\\")
			inContinuation = true
			continue
		}
		joined := pending + trimmedRight
		pending = ""
		inContinuation = false

		stripped := strings.TrimSpace(joined)
		if stripped == "" || strings.HasPrefix(stripped, "#") || strings.HasPrefix(stripped, "!") {
			continue
		}
		idx := strings.IndexAny(stripped, "=:")
		if idx < 0 {
			return nil, fmt.Errorf("properties: malformed line %d (no '=' or ':' separator)", startLine)
		}
		k := strings.TrimSpace(stripped[:idx])
		v := strings.TrimSpace(stripped[idx+1:])
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("properties: scan: %w", err)
	}
	// Flush a logical line left pending by a trailing '\' continuation at EOF
	// (no further physical line followed). Without this the last property —
	// often a wrapped sasl.jaas.config — would be silently dropped.
	if stripped := strings.TrimSpace(pending); stripped != "" {
		idx := strings.IndexAny(stripped, "=:")
		if idx < 0 {
			return nil, fmt.Errorf("properties: malformed line %d (no '=' or ':' separator)", startLine)
		}
		if !strings.HasPrefix(stripped, "#") && !strings.HasPrefix(stripped, "!") {
			out[strings.TrimSpace(stripped[:idx])] = strings.TrimSpace(stripped[idx+1:])
		}
	}
	return out, nil
}

var (
	jaasPlainModule = regexp.MustCompile(`(?i)org\.apache\.kafka\.common\.security\.plain\.PlainLoginModule`)
	jaasScramModule = regexp.MustCompile(`(?i)org\.apache\.kafka\.common\.security\.scram\.ScramLoginModule`)
	jaasUserRe      = regexp.MustCompile(`username\s*=\s*"([^"]*)"`)
	jaasPassRe      = regexp.MustCompile(`password\s*=\s*"([^"]*)"`)
)

// parseJAASUserPass extracts the username and password from a JAAS
// config string. Recognizes PlainLoginModule and ScramLoginModule;
// other modules return an error so the caller can surface a useful
// "not supported" message rather than silently dropping credentials.
func parseJAASUserPass(cfg string) (user, pass string, err error) {
	switch {
	case jaasPlainModule.MatchString(cfg), jaasScramModule.MatchString(cfg):
		// recognized; fall through to extraction
	default:
		return "", "", errors.New("jaas: only PlainLoginModule and ScramLoginModule are recognized")
	}
	um := jaasUserRe.FindStringSubmatch(cfg)
	pm := jaasPassRe.FindStringSubmatch(cfg)
	if um == nil || pm == nil {
		return "", "", errors.New("jaas: missing username= or password= in config")
	}
	return um[1], pm[1], nil
}
