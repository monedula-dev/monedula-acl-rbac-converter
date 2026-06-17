// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeTmp(t *testing.T, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "admin.properties")
	if err := os.WriteFile(p, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseProperties_BasicAndComments(t *testing.T) {
	p := writeTmp(t, `
# This is a comment.
! And so is this.
security.protocol=SASL_SSL
sasl.mechanism = PLAIN
sasl.jaas.config = org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="hunter2";
`)
	got, err := parseProperties(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"security.protocol": "SASL_SSL",
		"sasl.mechanism":    "PLAIN",
		"sasl.jaas.config":  `org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="hunter2";`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseProperties: got %v want %v", got, want)
	}
}

func TestParseProperties_LineContinuation(t *testing.T) {
	p := writeTmp(t, "key = first \\\n  second \\\n  third\n")
	got, err := parseProperties(p)
	if err != nil {
		t.Fatal(err)
	}
	if got["key"] != "first second third" {
		t.Errorf("continuation join: got %q", got["key"])
	}
}

// TestParseProperties_TrailingContinuationFlushed pins that a logical line
// whose final physical line ends with a '\' continuation (with no following
// line before EOF) is still emitted. The old loop accumulated it into the
// pending buffer and never flushed it after the scanner reached EOF, silently
// dropping the property.
func TestParseProperties_TrailingContinuationFlushed(t *testing.T) {
	p := writeTmp(t, "first=1\nkey=val \\")
	got, err := parseProperties(p)
	if err != nil {
		t.Fatal(err)
	}
	if got["key"] != "val" {
		t.Errorf("trailing-continuation property dropped; got key=%q (map=%v)", got["key"], got)
	}
}

// TestParseProperties_MalformedLineDoesNotEchoContent is the S2 regression
// guard: the malformed-line error must NOT echo the raw line content. The
// previous error format was `properties: malformed line %q` which would
// happily reflect any raw token, password, or credential the operator
// pasted into the file by mistake. The fixed error names only the line
// number — operators can inspect their own file at that location.
//
// Note: a real-world `sasl.jaas.config=...` line contains `=` and so
// always parses (separator detection finds the first `=`); the malformed
// case is rarer — typically a stray bare token from a broken paste, or
// a leftover authentication header the operator dropped into the wrong
// file. The defensive principle: never echo content we don't recognise.
func TestParseProperties_MalformedLineDoesNotEchoContent(t *testing.T) {
	const secret = "hunter2-do-not-leak"
	// A line with no '=' or ':' separator that nonetheless contains a
	// sensitive-looking token. Common real-world cause: an operator
	// pastes a bearer-token line into client.properties without the
	// `auth.token=` prefix.
	body := "Bearer-" + secret + "\n"
	p := writeTmp(t, body)
	_, err := parseProperties(p)
	if err == nil {
		t.Fatal("expected malformed-line error")
	}
	msg := err.Error()
	if strings.Contains(msg, secret) {
		t.Errorf("malformed-line error must not echo raw line content; got: %s", msg)
	}
	if !strings.Contains(msg, "line 1") {
		t.Errorf("expected line number in error; got: %s", msg)
	}
}

func TestParseJAAS_PlainLogin(t *testing.T) {
	cfg := `org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="hunter2";`
	user, pass, err := parseJAASUserPass(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" || pass != "hunter2" {
		t.Errorf("got %q/%q want alice/hunter2", user, pass)
	}
}

func TestParseJAAS_RejectsUnrecognizedModule(t *testing.T) {
	_, _, err := parseJAASUserPass(`com.example.Custom required token="x";`)
	if err == nil {
		t.Fatal("expected error for unrecognized JAAS module")
	}
}
