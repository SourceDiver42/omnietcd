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

Each tool reads its configuration from environment variables (see the `env(...)`
defaults at the top of every `main.go`): `ETCD_ENDPOINT`, `ETCD_CA`, `ETCD_CERT`,
`ETCD_KEY`, `OMNI_PRIVATE_KEY`, `ACCOUNT_ID`. Defaults resolve against the current
working directory, so run them from the directory that holds `etcd-certs/` and
`keys/`.

| tool | purpose |
|------|---------|
| `keyextract` | decrypt the whole etcd store, dump secret-bearing resources |
| `importsecrets` | read a running Talos cluster's secrets, store them in Omni |
| `omnietcd` | interactive explorer/editor for the encrypted store |
