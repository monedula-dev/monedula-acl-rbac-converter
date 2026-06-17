// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
)

func TestBuildKgoOpts_PlaintextNoConfig(t *testing.T) {
	log := extract.NewLogger()
	opts, err := buildKgoOpts([]string{"broker:9092"}, "", log)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) == 0 {
		t.Fatal("expected at least SeedBrokers opt")
	}
	// Confirm the opts make a valid client (no dial happens here).
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	cl.Close()
}

func TestBuildKgoOpts_SASLPlaintextPLAIN(t *testing.T) {
	p := writeTmp(t, `
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="hunter2";
`)
	log := extract.NewLogger()
	opts, err := buildKgoOpts([]string{"broker:9092"}, p, log)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		t.Fatalf("NewClient with SASL opts: %v", err)
	}
	cl.Close()
	// extract.log should record the three USED keys.
	logged := string(log.Bytes())
	for _, want := range []string{
		"USED config key=security.protocol",
		"USED config key=sasl.mechanism",
		"USED config key=sasl.jaas.config",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("extract.log missing %q; got:\n%s", want, logged)
		}
	}
}

func TestBuildKgoOpts_SASLPlaintextSCRAM256(t *testing.T) {
	p := writeTmp(t, `
security.protocol=SASL_PLAINTEXT
sasl.mechanism=SCRAM-SHA-256
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="alice" password="hunter2";
`)
	log := extract.NewLogger()
	opts, err := buildKgoOpts([]string{"broker:9092"}, p, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) == 0 {
		t.Fatal("expected at least one kgo opt")
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		t.Fatalf("NewClient with SCRAM-SHA-256 opts: %v", err)
	}
	cl.Close()
	logged := string(log.Bytes())
	for _, want := range []string{
		"USED config key=security.protocol",
		"USED config key=sasl.mechanism",
		"USED config key=sasl.jaas.config",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("extract.log missing %q; got:\n%s", want, logged)
		}
	}
}

func TestBuildKgoOpts_SASLPlaintextSCRAM512(t *testing.T) {
	p := writeTmp(t, `
security.protocol=SASL_PLAINTEXT
sasl.mechanism=SCRAM-SHA-512
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="alice" password="hunter2";
`)
	log := extract.NewLogger()
	opts, err := buildKgoOpts([]string{"broker:9092"}, p, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) == 0 {
		t.Fatal("expected at least one kgo opt")
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		t.Fatalf("NewClient with SCRAM-SHA-512 opts: %v", err)
	}
	cl.Close()
	logged := string(log.Bytes())
	for _, want := range []string{
		"USED config key=security.protocol",
		"USED config key=sasl.mechanism",
		"USED config key=sasl.jaas.config",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("extract.log missing %q; got:\n%s", want, logged)
		}
	}
}

func TestBuildKgoOpts_AcceptsJKSTruststore(t *testing.T) {
	// JKS truststores are loaded in-process. Build one in a TempDir,
	// point client.properties at it, and assert buildKgoOpts returns
	// a usable opts slice (no error, opts include a TLS dialer).
	cert, _ := genCert(t, "ca-buildopts-jks")
	jksPath := writeJKSTruststore(t, cert, "changeit")
	p := writeTmp(t, `
security.protocol=SSL
ssl.truststore.location=`+jksPath+`
ssl.truststore.password=changeit
`)
	log := extract.NewLogger()
	opts, err := buildKgoOpts([]string{"broker:9093"}, p, log)
	if err != nil {
		t.Fatalf("expected JKS truststore to load; got error: %v", err)
	}
	if len(opts) == 0 {
		t.Fatal("expected at least SeedBrokers + DialTLSConfig opts")
	}
	logged := string(log.Bytes())
	for _, want := range []string{
		"USED config key=security.protocol",
		"USED config key=ssl.truststore.location",
		"USED config key=ssl.truststore.password",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("extract.log missing %q; got:\n%s", want, logged)
		}
	}
}

func TestBuildKgoOpts_SkippedUnknownKey(t *testing.T) {
	p := writeTmp(t, `
security.protocol=PLAINTEXT
client.id=my-client
`)
	log := extract.NewLogger()
	if _, err := buildKgoOpts([]string{"broker:9092"}, p, log); err != nil {
		t.Fatal(err)
	}
	logged := string(log.Bytes())
	if !strings.Contains(logged, "SKIPPED config key=client.id") {
		t.Errorf("expected SKIPPED line for client.id; got:\n%s", logged)
	}
}
