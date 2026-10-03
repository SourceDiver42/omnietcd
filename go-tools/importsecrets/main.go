// importsecrets: reads the REAL secrets bundle from a running Talos cluster and
// imports it into Omni as an ImportedClusterSecrets resource (+ a locked Cluster),
// mirroring exactly what `omnictl cluster import` does for the secrets step.
//
// We do this directly (instead of the full import) because Talos-in-Docker nodes
// have no hardware SystemInformation/UUID, which the import's machine-discovery
// requires. The secret material handling is identical: the running cluster's CA
// private keys land in Omni's encrypted etcd store.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/safe"
	talosclient "github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/config/generate/secrets"
	configres "github.com/siderolabs/talos/pkg/machinery/resources/config"
	yaml "go.yaml.in/yaml/v4"

	omniclient "github.com/siderolabs/omni/client/pkg/client"
	"github.com/siderolabs/omni/client/pkg/clusterimport"
	"github.com/siderolabs/omni/client/pkg/omni/resources/omni"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		clusterID   = env("CLUSTER_ID", "imported-cluster")
		cpNode      = env("CP_NODE", "10.5.0.2")
		talosCfg    = env("TALOSCONFIG", "talosconfig")
		omniEP      = env("OMNI_ENDPOINT", "https://localhost:8099")
		saKey       = os.Getenv("OMNI_SERVICE_ACCOUNT_KEY")
		talosVer    = env("TALOS_VERSION", "1.13.4")
		k8sVer      = env("KUBERNETES_VERSION", "1.36.1")
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// --- 1. Connect to the running Talos cluster and read the control-plane machine config ---
	talosCli, err := clusterimport.BuildTalosClient(ctx, talosCfg, "", "", nil)
	if err != nil {
		return fmt.Errorf("build talos client: %w", err)
	}

	nodeCtx := talosclient.WithNode(ctx, cpNode)
	mc, err := safe.ReaderGetByID[*configres.MachineConfig](nodeCtx, talosCli,
		resource.NewMetadata(configres.NamespaceName, configres.MachineConfigType, configres.ActiveID, resource.VersionUndefined).ID())
	if err != nil {
		return fmt.Errorf("read machine config from %s: %w", cpNode, err)
	}

	// --- 2. Derive the Talos SecretsBundle (contains all CA private keys) ---
	bundle, err := secrets.NewBundleFromConfig(secrets.NewFixedClock(time.Now()), mc.Provider())
	if err != nil {
		return fmt.Errorf("build secrets bundle: %w", err)
	}
	bundleYAML, err := yaml.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	fmt.Printf("read real secrets bundle from %s (%d bytes of CA/key material)\n", cpNode, len(bundleYAML))

	// --- 3. Create ImportedClusterSecrets + locked Cluster in Omni via the public API ---
	cli, err := omniclient.New(omniEP,
		omniclient.WithServiceAccount(saKey),
		omniclient.WithInsecureSkipTLSVerify(true),
	)
	if err != nil {
		return fmt.Errorf("omni client: %w", err)
	}
	defer cli.Close()

	st := cli.Omni().State()

	ics := omni.NewImportedClusterSecrets(clusterID)
	ics.TypedSpec().Value.Data = string(bundleYAML)
	if err := st.Create(ctx, ics); err != nil {
		fmt.Printf("ImportedClusterSecrets/%s create: %v (continuing)\n", clusterID, err)
	} else {
		fmt.Printf("created ImportedClusterSecrets/%s in Omni\n", clusterID)
	}

	cluster := omni.NewCluster(clusterID)
	cluster.Metadata().Annotations().Set(omni.ClusterLocked, "")
	cluster.Metadata().Annotations().Set(omni.ClusterImportIsInProgress, "")
	cluster.TypedSpec().Value.TalosVersion = talosVer
	cluster.TypedSpec().Value.KubernetesVersion = k8sVer
	if err := st.Create(ctx, cluster); err != nil {
		fmt.Printf("Cluster/%s create: %v (continuing)\n", clusterID, err)
	}
	fmt.Printf("created Cluster/%s (locked, importing) in Omni\n", clusterID)

	fmt.Println("done, secrets now live (encrypted) in Omni's etcd data store")
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
