// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Acknowledgement is one entry in ack.yaml. Each is a per-DENY operator
// sign-off used to override WOULD_GRANT_ACCESS during DENY removal
// (spec §4.4).
type Acknowledgement struct {
	ACLID        string `yaml:"acl_id"        json:"acl_id"`
	GrantingRule string `yaml:"granting_rule" json:"granting_rule"`
	Operator     string `yaml:"operator"      json:"operator"`
	Reason       string `yaml:"reason"        json:"reason"`
}

// ParseAcknowledgements parses ack.yaml. Empty input yields an empty slice.
// Every entry must populate acl_id, operator, and reason.
func ParseAcknowledgements(data []byte) ([]Acknowledgement, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var raw struct {
		Acknowledgements []Acknowledgement `yaml:"acknowledgements"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse ack.yaml: %w", err)
	}
	for i, e := range raw.Acknowledgements {
		if e.ACLID == "" {
			return nil, fmt.Errorf("ack.yaml entry %d: missing acl_id", i)
		}
		if e.Operator == "" {
			return nil, fmt.Errorf("ack.yaml entry %d (acl_id=%s): missing operator", i, e.ACLID)
		}
		if e.Reason == "" {
			return nil, fmt.Errorf("ack.yaml entry %d (acl_id=%s): missing reason", i, e.ACLID)
		}
	}
	return raw.Acknowledgements, nil
}
