# Decrypting a self-hosted Omni etcd data store

In a self-hosted Omni the operator supplies the etcd encryption key via
`--private-key-source`. Because that private key is under the operator's control,
the entire etcd data store can be decrypted offline. This documents how the
encryption works and provides tooling to decrypt and inspect the store.

## How Omni encrypts its data store (from the source)

- `internal/backend/runtime/omni/state_etcd.go` builds the COSI etcd state with:
  `encryption.NewMarshaler(compression.NewMarshaler(ProtobufMarshaler, ZStd, 2048), cipher)`
  with `etcd.WithKeyPrefix("/omni/<accountID>")` and `etcd.WithSalt(sha256(accountID))`.
- `encryption.Cipher` is AES-256-GCM. Each etcd value is `0x01 | 12B nonce | GCM(masterKey, plaintext)`.
- The 32-byte master key is random, stored in a `keystorage.KeyStorage` record at etcd key
  `keystore-omni/record-store/<hex(sha256(accountID))>`.
- The master key is wrapped in per-slot envelopes, each slot encrypted to an OpenPGP public key.
  `GetMasterKey(slot, privateKey)` unwraps it. The slot id is `"<uid> <fingerprint>"`.
- The operator provides the OpenPGP private key via `--private-key-source=file:///omni.asc`.
  Whoever holds `omni.asc` can unwrap the master key and decrypt everything.

## Repository layout

| path | what |
|------|------|
| `compose.yaml` | etcd + dex + omni |
| `omni-config.yaml` | Omni config: external etcd, OIDC (dex), initial Admin service account |
| `dex-config.yaml` | minimal OIDC provider so Omni starts (an auth provider must be enabled) |
| `setup.sh` | generates the local PGP key and TLS certs (output is gitignored) |
| `extract_talos_config.py` | pure-Python decryptor: etcd to master key to secrets to `talosctl gen config` |
| `go-tools/keyextract` | decrypt the whole store and dump secret-bearing resources |
| `go-tools/importsecrets` | read a running Talos cluster's secrets and store them in Omni |
| `go-tools/omnietcd` | interactive explorer/editor for the encrypted store |
| `go-tools/BUILD.md` | how to build the Go tools inside an Omni checkout |
| `tests/` | unit tests for the Python decryptor |

Key material (`keys/`, `certs/`, `etcd-certs/`, `talosconfig`), runtime state
(`etcd-data/`, `omni-out/`), decrypted output (`extracted/`, `extracted-python/`)
and compiled binaries are gitignored and never committed.

## Setup

```bash
cd run
./setup.sh                       # PGP key + TLS certs (gitignored)
docker compose up -d             # etcd + dex + omni
```

Build the Go tools per `go-tools/BUILD.md` and copy the binaries next to the
config files, or run the Python tool below.

## Pipeline

```bash
# 1. create a standalone Talos cluster
talosctl cluster create docker --name imported-cluster --workers 1 \
  --talosconfig-destination "$PWD/talosconfig"

# 2. store the cluster's secrets in Omni (ImportedClusterSecrets + locked Cluster)
export OMNI_ENDPOINT=https://localhost:8099
export OMNI_SERVICE_ACCOUNT_KEY=$(cat omni-out/initial-sa-key)
export TALOSCONFIG=$PWD/talosconfig
./importsecrets

# 3. decrypt the whole store and dump the secrets
#    (this lab runs external etcd with mutual TLS; a default embedded Omni
#     needs none of the -etcd-* flags, just -private-key)
./keyextract -etcd https://127.0.0.1:2379 \
  -etcd-ca etcd-certs/ca.crt -etcd-cert etcd-certs/client.crt -etcd-key etcd-certs/client.key \
  -private-key keys/omni.asc

# or, do decrypt + machine-config generation in one step with Python:
python3 -m venv .venv && ./.venv/bin/pip install cryptography
./.venv/bin/python extract_talos_config.py
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The protobuf and range-end helpers run on the standard library alone; the
AES-GCM round-trip tests are skipped unless `cryptography` is installed, and the
zstd test is skipped unless the `zstd` CLI is present.

## Result

- Recovered AES-256-GCM master key, unwrapped from the key slot with `omni.asc`.
- Decrypted every resource in Omni's etcd (430 across 30 types in one run).
- Dumped `ImportedClusterSecrets`, the full Talos secrets bundle (os/Talos CA, etcd CA,
  k8s CA, k8s aggregator CA, k8s service-account key, bootstrap + trustd tokens,
  secretbox encryption secret).
- The extracted Talos root CA private key (ED25519) matched the running cluster's CA
  (identical SHA-256 fingerprint) and the private key matched that certificate.

Note: Omni's API refuses to read `ImportedClusterSecrets` back
("only create and destroy access is permitted for imported cluster secrets"),
yet the operator recovers it by decrypting etcd directly.
