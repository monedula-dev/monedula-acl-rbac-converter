// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package text

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
)

// TestParseText_DNPrincipalWithCommas pins that an SSL/DN principal containing
// commas (e.g. User:CN=alice,OU=eng,O=Acme) is parsed. The old regex captured
// the principal with [^,]+, so it stopped at the first comma and the whole
// line fell through to UNPARSED, silently dropping the ACL.
func TestParseText_DNPrincipalWithCommas(t *testing.T) {
	body := "Current ACLs for resource `ResourcePattern(resourceType=TOPIC, name=orders, patternType=LITERAL)`:\n" +
		"\t(principal=User:CN=alice,OU=eng,O=Acme, host=*, operation=READ, permissionType=ALLOW)\n"
	rows, err := parseText(body, extract.NewLogger())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (DN principal must parse)", len(rows))
	}
	if rows[0].Principal != "User:CN=alice,OU=eng,O=Acme" {
		t.Errorf("principal: got %q", rows[0].Principal)
	}
	if rows[0].Host != "*" {
		t.Errorf("host: got %q, want *", rows[0].Host)
	}
}

// TestParseText_UnrecognizedHeaderResetsResource pins that an unparseable
// resource-header line resets the current-resource context, so following ACL
// lines are not silently misattributed to the PREVIOUS resource block.
func TestParseText_UnrecognizedHeaderResetsResource(t *testing.T) {
	body := "Current ACLs for resource `ResourcePattern(resourceType=TOPIC, name=orders, patternType=LITERAL)`:\n" +
		"\t(principal=User:alice, host=*, operation=READ, permissionType=ALLOW)\n" +
		"Current ACLs for resource `ResourcePattern(resourceType=TOPIC, name=BADFORMAT\n" + // header drift: no patternType
		"\t(principal=User:bob, host=*, operation=WRITE, permissionType=ALLOW)\n"
	rows, err := parseText(body, extract.NewLogger())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, r := range rows {
		if r.Principal == "User:bob" && r.ResourceName == "orders" {
			t.Errorf("bob's ACL was misattributed to the previous resource 'orders' after an unparseable header")
		}
	}
}
