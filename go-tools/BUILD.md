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
default for each, so either works; the flag wins). The defaults target a default
Docker Omni, which runs embedded etcd on `http://localhost:2379` with no TLS and
no client-cert auth, so usually you only need to point at `omni.asc`.

| flag | env | default | meaning |
|------|-----|---------|---------|
| `-etcd` | `ETCD_ENDPOINT` | `http://127.0.0.1:2379` | etcd endpoint (`https://` to enable TLS) |
| `-account-id` | `ACCOUNT_ID` | _(auto-discovered)_ | Omni account id (etcd key prefix + salt). Discovered from the `/omni/<id>/` keyspace when empty/wrong, so usually omit it. |
| `-private-key` | `OMNI_PRIVATE_KEY` | `omni.asc` | the OpenPGP private key Omni uses for etcd (`--private-key-source`) |
| `-etcd-ca` | `ETCD_CA` | _(empty: system roots)_ | etcd server CA (https only) |
| `-etcd-cert` | `ETCD_CERT` | _(empty: no client auth)_ | etcd client cert for mutual TLS |
| `-etcd-key` | `ETCD_KEY` | _(empty: no client auth)_ | etcd client key for mutual TLS |
| `-insecure` | `ETCD_INSECURE` | off | skip etcd TLS verification |

`keyextract` also has `-out` (`OUT_DIR`, default `extracted`).

```sh
# default embedded Omni (plaintext etcd): just point at the key
omnietcd -private-key /path/to/omni.asc types

# external etcd with mutual TLS
omnietcd -etcd https://etcd.internal:2379 \
  -etcd-ca ca.crt -etcd-cert client.crt -etcd-key client.key \
  -private-key /path/to/omni.asc types
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
