// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package authlogin implements `monedula-acl-rbac auth login`.
package authlogin

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

// Options bundles inputs.
type Options struct {
	URL                string
	Stdin              io.Reader
	Stdout             io.Writer
	PasswordReader     func() (string, error)
	CACertPath         string
	ClientCertPath     string
	ClientKeyPath      string
	InsecureSkipVerify bool
}

// Run prompts for user + password, exchanges with MDS, and writes the
// cache file. Returns the resolved token.
func Run(opts Options) error {
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}

	r := bufio.NewReader(opts.Stdin)
	fmt.Fprint(opts.Stdout, "MDS user: ")
	userLine, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	username := strings.TrimSpace(userLine)
	if username == "" {
		return fmt.Errorf("auth login: empty username")
	}

	var password string
	if opts.PasswordReader != nil {
		password, err = opts.PasswordReader()
	} else {
		fmt.Fprint(opts.Stdout, "Password: ")
		pw, perr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(opts.Stdout)
		password = string(pw)
		err = perr
	}
	if err != nil {
		return err
	}

	// Pass the password in-memory rather than writing it to a temp file.
	// On Windows `os.CreateTemp` + `f.Chmod(0o600)` leaves the file
	// world-readable in the system temp dir until the deferred Remove
	// fires — a window where another local user can read it. AuthConfig's
	// in-memory Password takes precedence over PasswordFile in exchange().
	tok, err := mds.ResolveToken(mds.AuthConfig{
		URL:                opts.URL,
		User:               username,
		Password:           password,
		CACertPath:         opts.CACertPath,
		ClientCertPath:     opts.ClientCertPath,
		ClientKeyPath:      opts.ClientKeyPath,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	})
	if err != nil {
		return err
	}
	// Key the cache file on (URL, current OS user) per spec §10.4 so that
	// subsequent invocations on the same host find the cache via --mds-url
	// alone (spec §10.5). The MDS user is still recorded in the file's
	// JSON content (Token.User) for human readability.
	if err := mds.WriteTokenCacheForOSUser(tok); err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "Cached token for %s @ %s (expires %s)\n", username, opts.URL, tok.ExpiresAt.Format(time.RFC3339))
	return nil
}
