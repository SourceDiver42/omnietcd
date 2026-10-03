#!/usr/bin/env bash
# Generate the local key material and TLS certificates used by the stack.
# Everything this writes is gitignored; re-run it on a fresh checkout.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p keys certs etcd-certs omni-out etcd-data
chmod 777 omni-out etcd-data 2>/dev/null || true

# OpenPGP key that Omni uses to encrypt its etcd data store (--private-key-source).
if [ ! -f keys/omni.asc ]; then
  GNUPGHOME="$(mktemp -d)"
  export GNUPGHOME
  gpg --batch --passphrase '' --quick-gen-key "Omni (etcd encryption)" default default never
  gpg -a --export-secret-key > keys/omni.asc
  gpg -a --export > keys/omni.pub
  rm -rf "$GNUPGHOME"
  echo "wrote keys/omni.asc"
fi

# TLS certificate for the Omni API (self-signed, with SANs for local access).
if [ ! -f certs/tls.crt ]; then
  cat > certs/san.cnf <<'EOF'
[req]
distinguished_name=req
x509_extensions=v3
prompt=no
[v3]
subjectAltName=@alt
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
[alt]
DNS.1=omni
DNS.2=localhost
DNS.3=omni.orb.local
DNS.4=host.docker.internal
IP.1=127.0.0.1
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/tls.key -out certs/tls.crt \
    -days 365 -subj "/CN=omni-local" -config certs/san.cnf -extensions v3
  echo "wrote certs/tls.crt"
fi

# TLS PKI for the external etcd (server + client certs off one CA).
if [ ! -f etcd-certs/server.crt ]; then
  cd etcd-certs
  openssl genrsa -out ca.key 2048
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/CN=etcd-ca"

  cat > srv.cnf <<'EOF'
[req]
distinguished_name=d
prompt=no
[d]
CN=etcd
[ext]
subjectAltName=DNS:etcd,DNS:localhost,IP:172.30.0.2,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
EOF
  openssl genrsa -out server.key 2048
  openssl req -new -key server.key -out server.csr -subj "/CN=etcd" -config srv.cnf
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt \
    -days 365 -sha256 -extfile srv.cnf -extensions ext

  cat > cli.cnf <<'EOF'
[req]
distinguished_name=d
prompt=no
[d]
CN=omni-etcd-client
[ext]
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth
EOF
  openssl genrsa -out client.key 2048
  openssl req -new -key client.key -out client.csr -subj "/CN=omni-etcd-client" -config cli.cnf
  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt \
    -days 365 -sha256 -extfile cli.cnf -extensions ext
  chmod 644 ./*.key
  cd ..
  echo "wrote etcd-certs/"
fi

echo "setup complete."
