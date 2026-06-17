// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// WriteChecksum computes SHA-256 of `path` and writes the hex digest to
// `path` + ".sha256". The file is overwritten if present.
func WriteChecksum(path string) error {
	sum, err := hashFile(path)
	if err != nil {
		return err
	}
	out := path + ".sha256"
	if err := WriteAtomic(out, []byte(sum+"  "+path+"\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	return nil
}

// ErrChecksumMismatch is returned by VerifyChecksum when the recorded
// digest no longer matches the file's content. Callers map this error to
// exit code 5.
var ErrChecksumMismatch = errors.New("checksum mismatch")

// VerifyChecksum reads `path` + ".sha256" and compares it against a fresh
// hash of `path`. Returns an error if the checksum file is missing,
// malformed, or does not match.
func VerifyChecksum(path string) error {
	sumFile := path + ".sha256"
	data, err := os.ReadFile(sumFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", sumFile, err)
	}
	if len(data) < 64 {
		return fmt.Errorf("checksum file %s too short", sumFile)
	}
	recorded := string(data[:64])

	got, err := hashFile(path)
	if err != nil {
		return err
	}
	if got != recorded {
		return fmt.Errorf("%w: %s: recorded=%s actual=%s", ErrChecksumMismatch, path, recorded, got)
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
