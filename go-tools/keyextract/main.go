// keyextract: offline decryptor for a self-hosted Omni etcd data store.
//
// It connects to the SAME etcd Omni uses, reads the key-slot record, unwraps
// the AES-256 master key using the OpenPGP private key WE (the operator) hold,
// rebuilds Omni's exact COSI cipher, and lists/decrypts every resource -
// dumping Talos cluster secrets (CA private keys), kubeconfig, talosconfig.
//
// This demonstrates that for a self-hosted Omni the encryption keys are fully
// recoverable by whoever controls --private-key-source, despite the claim that
// the keys "cannot be extracted".
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cosi-project/runtime/pkg/keystorage"
	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/state/impl/store"
	"github.com/cosi-project/runtime/pkg/state/impl/store/compression"
	"github.com/cosi-project/runtime/pkg/state/impl/store/encryption"
	etcdstate "github.com/cosi-project/state-etcd/pkg/state/impl/etcd"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	yaml "go.yaml.in/yaml/v3"

	"github.com/siderolabs/omni/internal/backend/runtime/keyprovider"
	"github.com/siderolabs/omni/client/pkg/omni/resources/registry"

	// Blank imports register every Omni resource type in the protobuf registry,
	// so the ProtobufMarshaler can decode typed specs.
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/auth"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/infra"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/k8s"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/oidc"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/omni"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/siderolink"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/system"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/virtual"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		accountID  = env("ACCOUNT_ID", "287cfd52-735b-4dbf-bfc8-c47593e09c3b")
		etcdEP     = env("ETCD_ENDPOINT", "https://127.0.0.1:2379")
		caFile     = env("ETCD_CA", "etcd-certs/ca.crt")
		certFile   = env("ETCD_CERT", "etcd-certs/client.crt")
		keyFile    = env("ETCD_KEY", "etcd-certs/client.key")
		privKeyAsc = env("OMNI_PRIVATE_KEY", "keys/omni.asc")
		outDir     = env("OUT_DIR", "extracted")
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = os.MkdirAll(outDir, 0o755)

	// --- 1. Connect to the same etcd Omni uses ---
	tlsInfo := transport.TLSInfo{CertFile: certFile, KeyFile: keyFile, TrustedCAFile: caFile}
	tlsCfg, err := tlsInfo.ClientConfig()
	if err != nil {
		return fmt.Errorf("etcd tls: %w", err)
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{etcdEP},
		TLS:         tlsCfg,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("etcd connect: %w", err)
	}
	defer cli.Close()

	// --- 2. Read the key-slot record and unwrap the master key with OUR private key ---
	privArmored, err := os.ReadFile(privKeyAsc)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}

	hexHash := fmt.Sprintf("%x", sha256.Sum256([]byte(accountID)))
	ksKey := "keystore-omni/record-store/" + hexHash

	resp, err := cli.Get(ctx, ksKey)
	if err != nil {
		return fmt.Errorf("get keystore: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return fmt.Errorf("keystore record %q not found", ksKey)
	}

	ks := &keystorage.KeyStorage{}
	if err := ks.UnmarshalBinary(resp.Kvs[0].Value); err != nil {
		return fmt.Errorf("unmarshal keystore: %w", err)
	}

	slot, err := keyprovider.GetIdentityString(string(privArmored))
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	masterKey, err := ks.GetMasterKey(slot, string(privArmored))
	if err != nil {
		return fmt.Errorf("unwrap master key (slot %q): %w", slot, err)
	}

	fmt.Println("==================================================================")
	fmt.Println(" Omni etcd data-store key extraction")
	fmt.Println("==================================================================")
	fmt.Printf(" etcd endpoint   : %s\n", etcdEP)
	fmt.Printf(" account id      : %s\n", accountID)
	fmt.Printf(" keystore record : %s\n", ksKey)
	fmt.Printf(" PGP key slot    : %s\n", slot)
	fmt.Printf(" >>> RECOVERED AES-256-GCM MASTER KEY: %x\n", masterKey)
	fmt.Println("==================================================================")

	// --- 3. Rebuild Omni's EXACT cipher + marshaler (see internal/.../state_etcd.go) ---
	prefix := fmt.Sprintf("/omni/%s", url.PathEscape(accountID))
	salt := sha256.Sum256([]byte(accountID))

	cipher := encryption.NewCipher(encryption.KeyProviderFunc(func() ([]byte, error) {
		return masterKey, nil
	}))
	marshaler := encryption.NewMarshaler(
		compression.NewMarshaler(store.ProtobufMarshaler{}, compression.ZStd(), 2048),
		cipher,
	)
	st := etcdstate.NewState(cli, marshaler,
		etcdstate.WithKeyPrefix(prefix),
		etcdstate.WithSalt(salt[:]),
	)

	// --- 4. Raw-read every etcd value under the account prefix and decrypt it ---
	// Using the marshaler directly (decrypt -> decompress -> protobuf) sidesteps
	// any namespace guessing: we just decrypt whatever Omni actually stored.
	_ = st // the marshaler is the real workhorse; st proves the full wiring matches Omni

	debug := os.Getenv("DEBUG") != ""
	fmt.Printf("%d Omni resource types registered for typed decoding\n\n", len(registry.Resources))

	listResp, err := cli.Get(ctx, prefix+"/", clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("list etcd keys: %w", err)
	}

	counts := map[string]int{}
	failures := 0
	total := 0
	var secretDump []resource.Resource

	for _, kv := range listResp.Kvs {
		res, err := marshaler.UnmarshalResource(kv.Value)
		if err != nil {
			failures++
			if debug && failures <= 10 {
				fmt.Printf("  decode fail %s: %v\n", string(kv.Key), err)
			}
			continue
		}
		typ := res.Metadata().Type()
		counts[typ]++
		total++
		if isSecretType(typ) {
			secretDump = append(secretDump, res)
		}
	}

	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)

	fmt.Printf("Decrypted %d resources across %d types (%d undecodable non-resource keys):\n\n", total, len(types), failures)
	for _, t := range types {
		marker := ""
		if isSecretType(t) {
			marker = "   <-- SECRETS"
		}
		fmt.Printf("  %5d  %-48s%s\n", counts[t], t, marker)
	}

	fmt.Printf("\n--- Dumping %d secret-bearing resources to %s ---\n", len(secretDump), outDir)
	for _, r := range secretDump {
		dumpSecret(outDir, r)
	}

	return nil
}

func isSecretType(typ string) bool {
	switch typ {
	case "ClusterSecrets.omni.sidero.dev",
		"ImportedClusterSecrets.omni.sidero.dev",
		"RedactedClusterMachineConfigs.omni.sidero.dev",
		"ClusterMachineConfigs.omni.sidero.dev",
		"TalosConfigs.omni.sidero.dev",
		"KubernetesUsernames.omni.sidero.dev":
		return true
	}
	return strings.Contains(typ, "Secret")
}

func dumpSecret(outDir string, r resource.Resource) {
	out, err := yaml.Marshal(r.Spec())
	if err != nil {
		return
	}
	safe := strings.NewReplacer("/", "_", " ", "_").Replace(r.Metadata().Type() + "__" + r.Metadata().ID())
	path := outDir + "/" + safe + ".yaml"
	_ = os.WriteFile(path, out, 0o600)
	fmt.Printf("    [secret] %s  ->  %s\n", r.Metadata(), path)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
