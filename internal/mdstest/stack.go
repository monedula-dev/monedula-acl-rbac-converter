// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build integration || e2e

package mdstest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobynet "github.com/moby/moby/api/types/network"
	tcgo "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// CPSpec is a Confluent Platform version under test.
type CPSpec struct {
	Name    string
	Version string
	KRaft   bool // true => KRaft (CP 8.x), false => ZooKeeper (CP 7.x)
}

// CPSpecs is the version matrix the real-MDS tests run against.
var CPSpecs = []CPSpec{
	{Name: "cp7.9-zookeeper", Version: "7.9.7", KRaft: false},
	{Name: "cp8.2-kraft", Version: "8.2.1", KRaft: true},
}

// Stack is a running MDS (and its backing cp-server broker) under one version.
type Stack struct {
	URL       string // MDS base URL, reachable from the host
	ClusterID string // kafka cluster id (the MDS scope)
	PWFile    string // file holding the mds super-user password
	// Brokers is the host-reachable SASL_PLAINTEXT bootstrap server(s) for the
	// same cp-server broker that backs MDS. A client must authenticate as the
	// kafka superuser (PLAIN) to manage ACLs — ConfluentServerAuthorizer rejects
	// the ANONYMOUS principal on the Kafka-native ACL APIs.
	Brokers []string
	// CommandConfig is a host path to a Kafka client.properties file carrying the
	// SASL_PLAINTEXT/PLAIN kafka-superuser credentials for Brokers. Pass it to the
	// CLI via --command-config and to a kgo client via KafkaSASL.
	CommandConfig string
	// Kafka is the cp-server container, exposed so tests can dump logs / exec for
	// diagnostics.
	Kafka tcgo.Container
}

// KafkaUser / KafkaPass are the SASL/PLAIN superuser credentials for the host
// CLIENT listener, exposed so a kgo client can authenticate without parsing the
// command-config file.
const (
	KafkaUser = "kafka"
	KafkaPass = "kafka-secret"
)

// clientCommandConfig is the client.properties content authenticating as the
// kafka superuser over SASL_PLAINTEXT/PLAIN against the CLIENT listener.
const clientCommandConfig = `security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="kafka" password="kafka-secret";
`

func genTokenKeypair(t *testing.T, dir string) (keyPath, pubPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "keypair.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPath = filepath.Join(dir, "public.pem")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return keyPath, pubPath
}

const ldapBootstrap = `dn: ou=users,dc=confluent,dc=io
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=confluent,dc=io
objectClass: organizationalUnit
ou: groups

dn: uid=mds,ou=users,dc=confluent,dc=io
objectClass: inetOrgPerson
uid: mds
cn: mds
sn: mds
userPassword: mds-secret
`

// commonMDSEnv holds the LDAP + token + MDS + SASL listener config shared by
// the ZooKeeper and KRaft bring-ups.
func commonMDSEnv() map[string]string {
	return map[string]string{
		"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR":            "1",
		"KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR":    "1",
		"KAFKA_TRANSACTION_STATE_LOG_MIN_ISR":               "1",
		"KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS":            "0",
		"KAFKA_CONFLUENT_LICENSE_TOPIC_REPLICATION_FACTOR":  "1",
		"KAFKA_CONFLUENT_BALANCER_TOPIC_REPLICATION_FACTOR": "1",
		"KAFKA_CONFLUENT_TIER_METADATA_REPLICATION_FACTOR":  "1",

		// User:ANONYMOUS must stay a superuser: in the KRaft line the CONTROLLER
		// listener is PLAINTEXT, so broker↔controller ClusterAction traffic
		// authenticates as ANONYMOUS and the node fails to start without it. The
		// host-reachable CLIENT listener is SASL, so no anonymous client traffic
		// rides on this.
		"KAFKA_SUPER_USERS":           "User:kafka;User:mds;User:ANONYMOUS",
		"KAFKA_AUTHORIZER_CLASS_NAME": "io.confluent.kafka.security.authorizer.ConfluentServerAuthorizer",

		"KAFKA_SASL_MECHANISM_INTER_BROKER_PROTOCOL":           "PLAIN",
		"KAFKA_LISTENER_NAME_INTERNAL_SASL_ENABLED_MECHANISMS": "PLAIN",
		"KAFKA_LISTENER_NAME_INTERNAL_PLAIN_SASL_JAAS_CONFIG":  `org.apache.kafka.common.security.plain.PlainLoginModule required username="kafka" password="kafka-secret" user_kafka="kafka-secret";`,
		// CLIENT is the host-reachable listener. ConfluentServerAuthorizer hard-
		// closes the Kafka-native ACL APIs (DescribeAcls/CreateAcls) for the
		// ANONYMOUS principal, so a plain PLAINTEXT listener cannot manage ACLs.
		// Authenticate as the kafka superuser over SASL_PLAINTEXT/PLAIN instead.
		"KAFKA_LISTENER_NAME_CLIENT_SASL_ENABLED_MECHANISMS":                       "PLAIN",
		"KAFKA_LISTENER_NAME_CLIENT_PLAIN_SASL_JAAS_CONFIG":                        `org.apache.kafka.common.security.plain.PlainLoginModule required username="kafka" password="kafka-secret" user_kafka="kafka-secret";`,
		"KAFKA_LISTENER_NAME_TOKEN_SASL_ENABLED_MECHANISMS":                        "OAUTHBEARER",
		"KAFKA_LISTENER_NAME_TOKEN_OAUTHBEARER_SASL_SERVER_CALLBACK_HANDLER_CLASS": "io.confluent.kafka.server.plugins.auth.token.TokenBearerValidatorCallbackHandler",
		"KAFKA_LISTENER_NAME_TOKEN_OAUTHBEARER_SASL_LOGIN_CALLBACK_HANDLER_CLASS":  "io.confluent.kafka.server.plugins.auth.token.TokenBearerServerLoginCallbackHandler",
		"KAFKA_LISTENER_NAME_TOKEN_OAUTHBEARER_SASL_JAAS_CONFIG":                   `org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required publicKeyPath="/tmp/conf/public.pem";`,

		"KAFKA_CONFLUENT_METADATA_TOPIC_REPLICATION_FACTOR":     "1",
		"KAFKA_CONFLUENT_METADATA_SERVER_AUTHENTICATION_METHOD": "BEARER",
		"KAFKA_CONFLUENT_METADATA_SERVER_LISTENERS":             "http://0.0.0.0:8090",
		"KAFKA_CONFLUENT_METADATA_SERVER_ADVERTISED_LISTENERS":  "http://kafka:8090",
		"KAFKA_CONFLUENT_METADATA_SERVER_TOKEN_MAX_LIFETIME_MS": "3600000",
		"KAFKA_CONFLUENT_METADATA_SERVER_TOKEN_KEY_PATH":        "/tmp/conf/keypair.pem",

		"KAFKA_LDAP_JAVA_NAMING_FACTORY_INITIAL":         "com.sun.jndi.ldap.LdapCtxFactory",
		"KAFKA_LDAP_COM_SUN_JNDI_LDAP_READ_TIMEOUT":      "3000",
		"KAFKA_LDAP_JAVA_NAMING_PROVIDER_URL":            "ldap://openldap:389",
		"KAFKA_LDAP_JAVA_NAMING_SECURITY_PRINCIPAL":      "cn=admin,dc=confluent,dc=io",
		"KAFKA_LDAP_JAVA_NAMING_SECURITY_CREDENTIALS":    "admin",
		"KAFKA_LDAP_JAVA_NAMING_SECURITY_AUTHENTICATION": "simple",
		"KAFKA_LDAP_USER_SEARCH_BASE":                    "ou=users,dc=confluent,dc=io",
		"KAFKA_LDAP_GROUP_SEARCH_BASE":                   "ou=groups,dc=confluent,dc=io",
		"KAFKA_LDAP_USER_NAME_ATTRIBUTE":                 "uid",
		"KAFKA_LDAP_USER_OBJECT_CLASS":                   "inetOrgPerson",
		"KAFKA_LDAP_GROUP_NAME_ATTRIBUTE":                "cn",
		"KAFKA_LDAP_GROUP_OBJECT_CLASS":                  "groupOfNames",
		"KAFKA_LDAP_GROUP_MEMBER_ATTRIBUTE":              "member",
		"KAFKA_LDAP_GROUP_MEMBER_ATTRIBUTE_PATTERN":      "cn=(.*),ou=users,dc=confluent,dc=io",
		"KAFKA_LOG4J_ROOT_LOGLEVEL":                      "WARN",
	}
}

func newClusterID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// freeHostPort reserves an ephemeral TCP port on the loopback interface and
// returns it. There is an unavoidable TOCTOU window between closing the
// listener here and Docker binding the port; it is small enough for tests and
// the alternative (a dynamic mapped port) can't be advertised pre-start.
func freeHostPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// StartMDSStack brings up openldap (+ zookeeper for the ZK line) and cp-server
// with MDS/RBAC for the given version, publishes a host-reachable PLAINTEXT
// broker listener, and returns the host MDS base URL plus broker bootstrap. It
// t.Skip()s when Docker is unavailable.
func StartMDSStack(ctx context.Context, t *testing.T, spec CPSpec) (Stack, func()) {
	t.Helper()
	tmp := t.TempDir()
	keyPath, pubPath := genTokenKeypair(t, tmp)
	ldifPath := filepath.Join(tmp, "bootstrap.ldif")
	if err := os.WriteFile(ldifPath, []byte(ldapBootstrap), 0o644); err != nil {
		t.Fatal(err)
	}
	pwFile := filepath.Join(tmp, "mds.pw")
	if err := os.WriteFile(pwFile, []byte("mds-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmdCfgFile := filepath.Join(tmp, "client.properties")
	if err := os.WriteFile(cmdCfgFile, []byte(clientCommandConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	// Reserve the host port the broker's PLAINTEXT listener will advertise. It
	// must be known before the container starts so it can be baked into
	// KAFKA_ADVERTISED_LISTENERS — a dynamic mapped port can't be advertised.
	brokerHostPort := freeHostPort(t)

	net, err := network.New(ctx)
	if err != nil {
		t.Skipf("Docker / network unavailable: %v", err)
	}
	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
		_ = net.Remove(ctx)
	}
	start := func(req tcgo.ContainerRequest) tcgo.Container {
		c, err := tcgo.GenericContainer(ctx, tcgo.GenericContainerRequest{ContainerRequest: req, Started: true})
		if err != nil {
			// A container that came up but failed its readiness probe (e.g. a
			// broker that exited on a config error) is returned non-nil; dump
			// its tail so the skip names the actual cause instead of a generic
			// "container exited with code 1".
			if c != nil {
				if rc, lerr := c.Logs(ctx); lerr == nil {
					b, _ := io.ReadAll(rc)
					rc.Close()
					s := string(b)
					if len(s) > 3000 {
						s = s[len(s)-3000:]
					}
					t.Logf("container %q log tail:\n%s", req.Image, s)
				}
			}
			cleanup()
			t.Skipf("Docker / container %q unavailable: %v", req.Image, err)
		}
		cleanups = append(cleanups, func() { _ = c.Terminate(ctx) })
		return c
	}

	start(tcgo.ContainerRequest{
		Image:          "osixia/openldap:1.5.0",
		Cmd:            []string{"--copy-service"},
		Networks:       []string{net.Name},
		NetworkAliases: map[string][]string{net.Name: {"openldap"}},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "Confluent",
			"LDAP_DOMAIN":         "confluent.io",
			"LDAP_ADMIN_PASSWORD": "admin",
		},
		Files: []tcgo.ContainerFile{{
			HostFilePath:      ldifPath,
			ContainerFilePath: "/container/service/slapd/assets/config/bootstrap/ldif/custom/bootstrap.ldif",
			FileMode:          0o644,
		}},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(90 * time.Second),
	})

	// The CLIENT listener is advertised at localhost:<brokerHostPort> so a host
	// kadm/CLI client reconnects to the mapped port. INTERNAL/TOKEN stay on the
	// container network name (kafka:...) for inter-broker and MDS traffic.
	clientAdvertised := fmt.Sprintf("CLIENT://localhost:%d", brokerHostPort)

	env := commonMDSEnv()
	clusterID := ""
	if spec.KRaft {
		clusterID = newClusterID(t)
		env["CLUSTER_ID"] = clusterID
		env["KAFKA_NODE_ID"] = "1"
		env["KAFKA_PROCESS_ROLES"] = "broker,controller"
		env["KAFKA_CONTROLLER_QUORUM_VOTERS"] = "1@kafka:9091"
		env["KAFKA_CONTROLLER_LISTENER_NAMES"] = "CONTROLLER"
		env["KAFKA_LISTENER_SECURITY_PROTOCOL_MAP"] = "CONTROLLER:PLAINTEXT,INTERNAL:SASL_PLAINTEXT,TOKEN:SASL_PLAINTEXT,CLIENT:SASL_PLAINTEXT"
		env["KAFKA_LISTENERS"] = "CONTROLLER://0.0.0.0:9091,INTERNAL://0.0.0.0:9092,TOKEN://0.0.0.0:9093,CLIENT://0.0.0.0:9094"
		env["KAFKA_ADVERTISED_LISTENERS"] = "INTERNAL://kafka:9092,TOKEN://kafka:9093," + clientAdvertised
		env["KAFKA_INTER_BROKER_LISTENER_NAME"] = "INTERNAL"
		env["KAFKA_CONFLUENT_AUTHORIZER_ACCESS_RULE_PROVIDERS"] = "CONFLUENT"
	} else {
		start(tcgo.ContainerRequest{
			Image:          "confluentinc/cp-zookeeper:" + spec.Version,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"zookeeper"}},
			Env:            map[string]string{"ZOOKEEPER_CLIENT_PORT": "2181", "ZOOKEEPER_TICK_TIME": "2000"},
			WaitingFor:     wait.ForLog("binding to port").WithStartupTimeout(90 * time.Second),
		})
		env["KAFKA_BROKER_ID"] = "1"
		env["KAFKA_ZOOKEEPER_CONNECT"] = "zookeeper:2181"
		env["KAFKA_LISTENER_SECURITY_PROTOCOL_MAP"] = "INTERNAL:SASL_PLAINTEXT,TOKEN:SASL_PLAINTEXT,CLIENT:SASL_PLAINTEXT"
		env["KAFKA_LISTENERS"] = "INTERNAL://0.0.0.0:9092,TOKEN://0.0.0.0:9093,CLIENT://0.0.0.0:9094"
		env["KAFKA_ADVERTISED_LISTENERS"] = "INTERNAL://kafka:9092,TOKEN://kafka:9093," + clientAdvertised
		env["KAFKA_INTER_BROKER_LISTENER_NAME"] = "INTERNAL"
		env["KAFKA_CONFLUENT_AUTHORIZER_ACCESS_RULE_PROVIDERS"] = "CONFLUENT,ZK_ACL"
	}

	kafka := start(tcgo.ContainerRequest{
		Image:          "confluentinc/cp-server:" + spec.Version,
		Networks:       []string{net.Name},
		NetworkAliases: map[string][]string{net.Name: {"kafka"}},
		ExposedPorts:   []string{"8090/tcp", "9094/tcp"},
		// Pin container :9094 to the pre-reserved host port so the advertised
		// PLAINTEXT listener (localhost:<brokerHostPort>) is reachable.
		HostConfigModifier: func(hc *mobycontainer.HostConfig) {
			hc.PortBindings = mobynet.PortMap{
				mobynet.MustParsePort("9094/tcp"): []mobynet.PortBinding{
					{HostPort: strconv.Itoa(brokerHostPort)},
				},
			}
		},
		Files: []tcgo.ContainerFile{
			{HostFilePath: keyPath, ContainerFilePath: "/tmp/conf/keypair.pem", FileMode: 0o644},
			{HostFilePath: pubPath, ContainerFilePath: "/tmp/conf/public.pem", FileMode: 0o644},
		},
		Env: env,
		WaitingFor: wait.ForHTTP("/security/1.0/features").WithPort("8090/tcp").
			WithStatusCodeMatcher(func(s int) bool { return s == 200 }).
			WithStartupTimeout(240 * time.Second),
	})

	host, err := kafka.Host(ctx)
	if err != nil {
		cleanup()
		t.Fatalf("kafka host: %v", err)
	}
	port, err := kafka.MappedPort(ctx, "8090/tcp")
	if err != nil {
		cleanup()
		t.Fatalf("mds port: %v", err)
	}
	url := fmt.Sprintf("http://%s:%s", host, port.Port())

	// Confirm the CLIENT broker port pin actually landed on container 9094.
	if mp, mperr := kafka.MappedPort(ctx, "9094/tcp"); mperr == nil {
		t.Logf("port map: 9094/tcp -> host %s (pinned %d); 8090/tcp -> host %s", mp.Port(), brokerHostPort, port.Port())
	} else {
		t.Logf("port map: MappedPort(9094/tcp) err: %v (pinned %d)", mperr, brokerHostPort)
	}

	return Stack{
		URL:           url,
		ClusterID:     kafkaClusterID(t, url),
		PWFile:        pwFile,
		Brokers:       []string{fmt.Sprintf("localhost:%d", brokerHostPort)},
		CommandConfig: cmdCfgFile,
		Kafka:         kafka,
	}, cleanup
}

// kafkaClusterID reads the MDS metadata id (unauthenticated endpoint).
func kafkaClusterID(t *testing.T, mdsURL string) string {
	t.Helper()
	resp, err := http.Get(mdsURL + "/v1/metadata/id")
	if err != nil {
		t.Fatalf("metadata id: %v", err)
	}
	defer resp.Body.Close()
	var raw struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode metadata id: %v", err)
	}
	if raw.ID == "" {
		t.Fatal("empty kafka cluster id from MDS")
	}
	return raw.ID
}
