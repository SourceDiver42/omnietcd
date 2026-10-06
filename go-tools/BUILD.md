# Building the Go tools

These three programs reuse Omni's own packages (the resource registry, the
keyprovider, and the COSI etcd/encryption marshalers), so they build from inside
an Omni source checkout rather than as a standalone module.

1. Clone the matching Omni release:

   ```bash
   git clone --depth 1 --branch v1.12.3 https://github.com/siderolabs/omni.git
   ```

2. Copy each tool into `cmd/` of that checkout:

   ```bash
   cp -r keyextract importsecrets omnietcd omni/cmd/
   ```

3. Build (the omni go.work pulls every dependency):

   ```bash
   cd omni
   go build -o /tmp/keyextract    ./cmd/keyextract
   go build -o /tmp/importsecrets ./cmd/importsecrets
   go build -o /tmp/omnietcd      ./cmd/omnietcd
   ```

## Configuration

`keyextract` and `omnietcd` take CLI flags (an env var of the same meaning is the
default for each, so either works; the flag wins). Defaults resolve against the
current working directory, so by default run them from the directory that holds
`etcd-certs/` and `keys/`.

| flag | env | default | meaning |
|------|-----|---------|---------|
| `-etcd` | `ETCD_ENDPOINT` | `https://127.0.0.1:2379` | etcd endpoint (`http://` for plaintext) |
| `-account-id` | `ACCOUNT_ID` | the test account UUID | Omni account id (defines the etcd key prefix and salt) |
| `-private-key` | `OMNI_PRIVATE_KEY` | `keys/omni.asc` | the OpenPGP private key Omni uses for etcd (`--private-key-source`) |
| `-etcd-ca` | `ETCD_CA` | `etcd-certs/ca.crt` | etcd server CA (empty = system roots) |
| `-etcd-cert` | `ETCD_CERT` | `etcd-certs/client.crt` | etcd client cert for mutual TLS (empty disables) |
| `-etcd-key` | `ETCD_KEY` | `etcd-certs/client.key` | etcd client key for mutual TLS (empty disables) |
| `-insecure` | `ETCD_INSECURE` | off | skip etcd TLS verification |

`keyextract` also has `-out` (`OUT_DIR`, default `extracted`).

```sh
omnietcd -private-key /path/to/omni.asc -etcd https://etcd.internal:2379 types
```

### About the etcd client cert (`-etcd-cert` / `client.crt`)

This is **not** one of Omni's own keys; it is the TLS client certificate used to
authenticate to **etcd**. You only need it when the etcd server is configured for
mutual TLS (`--client-cert-auth`), as the bundled `compose.yaml` here is. Options:

- **Reuse Omni's etcd client credentials.** A self-hosted Omni that uses external
  etcd is already given a client cert/key (config `storage.default.etcd.certFile` /
  `keyFile`, or flags `--etcd-client-cert-path` / `--etcd-client-key-path`). Point
  `-etcd-cert`/`-etcd-key` at those same files.
- **Generate your own**, signed by etcd's client CA. `setup.sh` does this for the
  local stack (`etcd-certs/`).
- **Omit it** (`-etcd-cert='' -etcd-key=''`) when etcd does not require client
  certs, e.g. TLS-without-mTLS or a plaintext `http://` endpoint.

Note: these tools talk to etcd directly, so they need a reachable etcd endpoint.
Omni's *embedded* etcd listens only inside the Omni container, so there you would
run the tool inside/next to that container or expose the endpoint.

| tool | purpose |
|------|---------|
| `keyextract` | decrypt the whole etcd store, dump secret-bearing resources |
| `importsecrets` | read a running Talos cluster's secrets, store them in Omni |
| `omnietcd` | interactive explorer/editor for the encrypted store |
