// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

// MDSAuthFlags holds the values parsed from <mds-auth> common flags.
type MDSAuthFlags struct {
	URL                string
	User               string
	PasswordFile       string
	TokenFile          string
	CacheToken         bool
	CACertPath         string
	ClientCertPath     string
	ClientKeyPath      string
	InsecureSkipVerify bool
	MaxRetries         int
}

// AddMDSConnFlags wires only the MDS connection flags (URL + TLS) — the
// subset a command needs when it resolves its own token interactively (e.g.
// `auth login`). Registering the full auth set there would expose flags like
// --mds-user / --mds-token-file that the command silently ignores.
func (f *MDSAuthFlags) AddMDSConnFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.URL, "mds-url", envOr("MONEDULA_ACL_RBAC_MDS_URL", ""), "MDS base URL (required)")
	cmd.Flags().StringVar(&f.CACertPath, "mds-ca-cert", envOr("MONEDULA_ACL_RBAC_MDS_CA_CERT", ""), "Path to a PEM CA bundle for MDS TLS")
	cmd.Flags().StringVar(&f.ClientCertPath, "mds-client-cert", envOr("MONEDULA_ACL_RBAC_MDS_CLIENT_CERT", ""), "Path to a PEM client certificate for mTLS to MDS")
	cmd.Flags().StringVar(&f.ClientKeyPath, "mds-client-key", envOr("MONEDULA_ACL_RBAC_MDS_CLIENT_KEY", ""), "Path to a PEM client key for mTLS to MDS")
	cmd.Flags().BoolVar(&f.InsecureSkipVerify, "mds-insecure-skip-verify", envBool("MONEDULA_ACL_RBAC_MDS_INSECURE_SKIP_VERIFY"), "Skip TLS certificate verification")
}

// AddMDSAuthFlags wires the full <mds-auth> flag set (connection + token
// resolution + retries) onto cmd.
func (f *MDSAuthFlags) AddMDSAuthFlags(cmd *cobra.Command) {
	f.AddMDSConnFlags(cmd)
	cmd.Flags().StringVar(&f.User, "mds-user", envOr("MONEDULA_ACL_RBAC_MDS_USER", ""), "MDS username")
	cmd.Flags().StringVar(&f.PasswordFile, "mds-password-file", envOr("MONEDULA_ACL_RBAC_MDS_PASSWORD_FILE", ""), "Path to a file containing the MDS password")
	cmd.Flags().StringVar(&f.TokenFile, "mds-token-file", envOr("MONEDULA_ACL_RBAC_MDS_TOKEN_FILE", ""), "Path to a pre-fetched MDS bearer token file")
	cmd.Flags().BoolVar(&f.CacheToken, "cache-token", false, "Persist the resolved token to the user config dir")
	cmd.Flags().IntVar(&f.MaxRetries, "mds-max-retries", envOrInt("MONEDULA_ACL_RBAC_MDS_MAX_RETRIES", 3), "Retry transient MDS failures (5xx, 429, connection reset) up to N additional times after the initial call; pass 0 to disable retries")
}

// ResolveClient assembles an MDS Client from the parsed flags.
func (f *MDSAuthFlags) ResolveClient() (*mds.Client, error) {
	if f.URL == "" {
		return nil, NewUsageError("--mds-url is required (or set MONEDULA_ACL_RBAC_MDS_URL)")
	}
	tok, err := mds.ResolveToken(mds.AuthConfig{
		URL:                f.URL,
		User:               f.User,
		PasswordFile:       f.PasswordFile,
		TokenFilePath:      f.TokenFile,
		CACertPath:         f.CACertPath,
		ClientCertPath:     f.ClientCertPath,
		ClientKeyPath:      f.ClientKeyPath,
		InsecureSkipVerify: f.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}
	if f.CacheToken {
		// Cache keyed on (URL, OS user) — the same scheme `auth login` uses —
		// so a later `--mds-url X` (without --mds-user) discovers it. Keying
		// on the MDS user instead would make --cache-token tokens invisible
		// to URL-only invocations, contradicting spec §10.
		if err := mds.WriteTokenCacheForOSUser(tok); err != nil {
			// Best-effort: a failed cache write must never fail the command.
			// Log at debug so "why isn't my token cached?" is diagnosable.
			log.Debug("could not cache MDS token for reuse (continuing)", "err", err)
		}
	}
	authCfg := mds.AuthConfig{
		URL:                f.URL,
		User:               f.User,
		PasswordFile:       f.PasswordFile,
		TokenFilePath:      f.TokenFile,
		CACertPath:         f.CACertPath,
		ClientCertPath:     f.ClientCertPath,
		ClientKeyPath:      f.ClientKeyPath,
		InsecureSkipVerify: f.InsecureSkipVerify,
	}
	return mds.NewClient(mds.Config{
		URL:                f.URL,
		Token:              tok.Token,
		CACertPath:         f.CACertPath,
		ClientCertPath:     f.ClientCertPath,
		ClientKeyPath:      f.ClientKeyPath,
		InsecureSkipVerify: f.InsecureSkipVerify,
		MaxRetries:         f.MaxRetries,
		// Re-resolve the token on a mid-run 401 (token file refreshed
		// out-of-band, or a password exchange that can be repeated).
		TokenSource: func() (string, error) {
			t, terr := mds.ResolveToken(authCfg)
			if terr != nil {
				return "", terr
			}
			return t.Token, nil
		},
	})
}
