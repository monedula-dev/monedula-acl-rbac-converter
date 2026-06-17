// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package discover implements `monedula-acl-rbac discover`.
package discover

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

// Run queries MDS for available clusters and writes a scopes.yaml stub.
func Run(w io.Writer, cl *mds.Client) error {
	clusters, err := fetchClusters(cl)
	if err != nil {
		return err
	}
	return writeStub(w, clusters)
}

type clusterList struct {
	Kafka   []string
	SR      []string
	KSQL    []string
	Connect []string
}

func fetchClusters(cl *mds.Client) (clusterList, error) {
	resp, err := cl.Get("/security/1.0/registry/clusters")
	if err != nil {
		return clusterList{}, err
	}
	defer resp.Body.Close()

	var raw struct {
		KafkaClusters []struct {
			ID string `json:"id"`
		} `json:"kafka_clusters"`
		SchemaRegistryClusters []struct {
			ID string `json:"id"`
		} `json:"schema_registry_clusters"`
		KSQLClusters []struct {
			ID string `json:"id"`
		} `json:"ksql_clusters"`
		ConnectClusters []struct {
			ID string `json:"id"`
		} `json:"connect_clusters"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return clusterList{}, fmt.Errorf("discover: decode: %w", err)
	}
	out := clusterList{}
	for _, c := range raw.KafkaClusters {
		out.Kafka = append(out.Kafka, c.ID)
	}
	for _, c := range raw.SchemaRegistryClusters {
		out.SR = append(out.SR, c.ID)
	}
	for _, c := range raw.KSQLClusters {
		out.KSQL = append(out.KSQL, c.ID)
	}
	for _, c := range raw.ConnectClusters {
		out.Connect = append(out.Connect, c.ID)
	}
	return out, nil
}

func writeStub(w io.Writer, c clusterList) error {
	fmt.Fprintln(w, "# monedula-acl-rbac discover-generated scopes.yaml stub")
	fmt.Fprintln(w, "# Fill in any required org/environment IDs by hand; clusters below are pre-populated.")
	fmt.Fprintln(w, "")
	// Cluster IDs are emitted as double-quoted YAML scalars so MDS payloads
	// containing YAML-special characters (`:`, leading `*`/`&`/`#`, etc.)
	// don't break the generated stub. Confluent IDs (`lkc-...`, `lsrc-...`)
	// are typically alphanumeric and would be valid bare too, but quoting
	// costs nothing and is the more defensive default.
	if len(c.Kafka) > 0 {
		fmt.Fprintf(w, "kafka_cluster: %q  # required\n", c.Kafka[0])
		if len(c.Kafka) > 1 {
			fmt.Fprintf(w, "# Other Kafka clusters seen: %v\n", c.Kafka[1:])
		}
	} else {
		fmt.Fprintln(w, `kafka_cluster: ""  # TODO required - no kafka clusters returned by MDS`)
	}
	if len(c.SR) > 0 {
		fmt.Fprintf(w, "schema_registry_cluster: %q  # only if input ACLs reference Subject resources\n", c.SR[0])
	} else {
		fmt.Fprintln(w, `schema_registry_cluster: ""  # optional`)
	}
	if len(c.KSQL) > 0 {
		fmt.Fprintf(w, "ksql_cluster: %q  # only if input ACLs reference ksqlDB resources\n", c.KSQL[0])
	} else {
		fmt.Fprintln(w, `ksql_cluster: ""  # optional`)
	}
	if len(c.Connect) > 0 {
		fmt.Fprintf(w, "connect_cluster: %q  # only if input ACLs reference Connect resources\n", c.Connect[0])
	} else {
		fmt.Fprintln(w, `connect_cluster: ""  # optional`)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "# organization: TODO if any binding targets org scope")
	fmt.Fprintln(w, "# environment:  TODO if any binding targets environment scope")
	return nil
}
