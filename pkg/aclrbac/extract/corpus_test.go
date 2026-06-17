// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package extract_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/csv"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/text"
)

// -update regenerates the .expected.json files from current parser
// output. Run after intentional parser changes:
//
//	go test ./pkg/aclrbac/extract/ -run Corpus -update
var updateGolden = flag.Bool("update", false, "update golden corpus expected files")

// canonicalize re-marshals JSON with stable key ordering so diffs are
// signal, not noise. encoding/json's default already sorts map keys,
// but we round-trip through interface{} to also drop the optional
// source.generated_at field, which varies per run.
func canonicalize(t *testing.T, raw []byte) []byte {
	t.Helper()
	var v map[string]interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if src, ok := v["source"].(map[string]interface{}); ok {
		delete(src, "generated_at")
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}

func runCorpusCase(t *testing.T, name string, extract func() ([]byte, error)) {
	t.Helper()
	gotRaw, err := extract()
	if err != nil {
		t.Fatalf("%s extract: %v", name, err)
	}
	got := canonicalize(t, gotRaw)

	goldenPath := filepath.Join("testdata", "corpus", name+".expected.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	want = canonicalize(t, want)
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\nwant:\n%s\ngot:\n%s\nRerun with -update if change is intentional.", goldenPath, want, got)
	}
}

func TestCorpus_Text(t *testing.T) {
	runCorpusCase(t, "text-realistic", func() ([]byte, error) {
		a, err := text.New("testdata/corpus/text-realistic.txt")
		if err != nil {
			return nil, err
		}
		set, _, _, _, err := a.Extract()
		if err != nil {
			return nil, err
		}
		return json.MarshalIndent(set, "", "  ")
	})
}

func TestCorpus_CSV(t *testing.T) {
	runCorpusCase(t, "csv-realistic", func() ([]byte, error) {
		a, err := csv.New("testdata/corpus/csv-realistic.csv")
		if err != nil {
			return nil, err
		}
		set, _, _, _, err := a.Extract()
		if err != nil {
			return nil, err
		}
		return json.MarshalIndent(set, "", "  ")
	})
}
