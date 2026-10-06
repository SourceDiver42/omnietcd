#!/usr/bin/env python3
"""
extract_talos_config.py

Offline extraction of Talos cluster secrets from a self-hosted Omni's etcd data
store, and regeneration of a plain Talos machine config from them.

It reproduces, in Python, exactly what Omni does internally:

  1. Read the key-slot record from etcd
     (key: keystore-omni/record-store/<hex(sha256(accountID))>).
  2. Unwrap the 32-byte AES-256 master key from the PGP key slot using the
     OpenPGP private key the operator supplies via --private-key-source (omni.asc).
  3. For each resource value under /omni/<accountID>/..., AES-256-GCM decrypt
     (0x01 | 12B nonce | ciphertext+tag), then zstd-decompress if framed.
  4. Pull the Talos SecretsBundle out of the ImportedClusterSecrets/ClusterSecrets
     resource, write it as a Talos `secrets.yaml`, and run
     `talosctl gen config --with-secrets` to produce controlplane/worker configs.

Only dependency beyond the stdlib is `cryptography` (AES-GCM). `gpg`, `zstd` and
(optionally) `talosctl` are invoked as subprocesses.
"""

import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from hashlib import sha256

# ----------------------------------------------------------------------------- config
# Defaults target a default Docker Omni: embedded etcd on http://localhost:2379,
# plaintext, no client-cert auth. TLS/cert options are only needed for external
# etcd. All overridable via flags (see main) or the matching env vars.
RUN = os.path.dirname(os.path.abspath(__file__))
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")            # "" = auto-discover from etcd
ETCD = os.environ.get("ETCD_ENDPOINT", "http://127.0.0.1:2379")
ETCD_CA = os.environ.get("ETCD_CA", "")                  # empty = system roots
ETCD_CERT = os.environ.get("ETCD_CERT", "")              # empty = no client auth
ETCD_KEY = os.environ.get("ETCD_KEY", "")
ETCD_INSECURE = os.environ.get("ETCD_INSECURE", "") != ""
OMNI_PRIV = os.environ.get("OMNI_PRIVATE_KEY", "omni.asc")
CLUSTER = os.environ.get("CLUSTER_ID", "imported-cluster")
CP_ENDPOINT = os.environ.get("CP_ENDPOINT", "https://127.0.0.1:6443")
OUT = os.environ.get("OUT_DIR", "extracted-python")


# ----------------------------------------------------------------- minimal protobuf
def _read_varint(buf, i):
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def iter_fields(buf):
    """Yield (field_number, wire_type, value) for a protobuf message.

    value is an int for varints, raw bytes for length-delimited fields.
    Raises if the buffer does not parse cleanly as protobuf.
    """
    i, n = 0, len(buf)
    while i < n:
        tag, i = _read_varint(buf, i)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            val, i = _read_varint(buf, i)
            yield field, wire, val
        elif wire == 2:
            ln, i = _read_varint(buf, i)
            if i + ln > n:
                raise ValueError("truncated length-delimited field")
            yield field, wire, buf[i:i + ln]
            i += ln
        elif wire == 5:
            yield field, wire, buf[i:i + 4]
            i += 4
        elif wire == 1:
            yield field, wire, buf[i:i + 8]
            i += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")


def walk_byte_strings(buf, depth=0, out=None):
    """Recursively collect every length-delimited byte string in a protobuf blob,
    descending into sub-messages that themselves parse as protobuf."""
    if out is None:
        out = []
    if depth > 8:
        return out
    try:
        fields = list(iter_fields(buf))
    except Exception:
        return out
    for _f, wire, val in fields:
        if wire == 2:
            out.append(val)
            walk_byte_strings(val, depth + 1, out)
    return out


# ----------------------------------------------------------------------- etcd (HTTP v3)
def _etcd_ctx():
    # Plaintext endpoint: no TLS context at all (matches a default embedded Omni).
    if not ETCD.startswith("https://"):
        return None
    ctx = ssl.create_default_context(cafile=ETCD_CA or None)
    ctx.check_hostname = False
    if ETCD_INSECURE:
        ctx.verify_mode = ssl.CERT_NONE
    # Client cert only when both parts are given (mutual-TLS etcd).
    if ETCD_CERT and ETCD_KEY:
        ctx.load_cert_chain(ETCD_CERT, ETCD_KEY)
    return ctx


def prefix_range_end(key: bytes) -> bytes:
    """Return the etcd range_end that selects all keys with the given prefix."""
    end = bytearray(key)
    for j in range(len(end) - 1, -1, -1):
        if end[j] < 0xFF:
            end[j] += 1
            return bytes(end[:j + 1])
    return b""


def etcd_range(key: bytes, prefix=False, keys_only=False, limit=0):
    """Return list of (key_bytes, value_bytes). If prefix, range over key*."""
    body = {"key": base64.b64encode(key).decode()}
    if prefix:
        body["range_end"] = base64.b64encode(prefix_range_end(key)).decode()
    if keys_only:
        body["keys_only"] = True
    if limit:
        body["limit"] = str(limit)
    req = urllib.request.Request(
        f"{ETCD}/v3/kv/range",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=_etcd_ctx(), timeout=15) as r:
        resp = json.load(r)
    out = []
    for kv in resp.get("kvs", []):
        out.append((base64.b64decode(kv["key"]), base64.b64decode(kv.get("value", ""))))
    return out


# ----------------------------------------------------------------- master-key unwrap
def parse_keystorage(blob: bytes):
    """Parse cosi key_storage.Storage -> {slot_id: armored_pgp_encrypted_key}."""
    slots = {}
    for field, wire, val in iter_fields(blob):
        if field == 2 and wire == 2:  # map<string, KeySlot> entry
            slot_id = None
            enc = None
            for f2, w2, v2 in iter_fields(val):
                if f2 == 1 and w2 == 2:
                    slot_id = v2.decode()
                elif f2 == 2 and w2 == 2:  # KeySlot message
                    for f3, w3, v3 in iter_fields(v2):
                        if f3 == 2 and w3 == 2:  # encrypted_key bytes
                            enc = v3
            if slot_id is not None and enc is not None:
                slots[slot_id] = enc
    return slots


def gpg_decrypt(armored_pgp: bytes, private_key_path: str) -> bytes:
    with tempfile.TemporaryDirectory() as home:
        subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--quiet", "--import", private_key_path],
            check=True, capture_output=True,
        )
        p = subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--quiet", "--pinentry-mode", "loopback",
             "--passphrase", "", "--decrypt"],
            input=armored_pgp, capture_output=True,
        )
        if p.returncode != 0:
            raise RuntimeError("gpg decrypt failed: " + p.stderr.decode())
        return p.stdout


def _keystore_record(account_id: str):
    hexhash = sha256(account_id.encode()).hexdigest()
    kvs = etcd_range(f"keystore-omni/record-store/{hexhash}".encode())
    return kvs[0][1] if kvs else None


def resolve_account() -> str:
    """Return the account id whose keystore record exists: the configured one, or
    one discovered from the /omni/<id>/ resource keyspace (one account per store)."""
    if ACCOUNT_ID and _keystore_record(ACCOUNT_ID) is not None:
        return ACCOUNT_ID
    ids, seen = [], set()
    for key, _ in etcd_range(b"/omni/", prefix=True, keys_only=True, limit=200):
        rest = key[len(b"/omni/"):]
        i = rest.find(b"/")
        if i > 0:
            idv = rest[:i].decode()
            if idv not in seen:
                seen.add(idv)
                ids.append(idv)
    for idv in ids:
        if _keystore_record(idv) is not None:
            return idv
    raise SystemExit(f"keystore record not found (tried account id {ACCOUNT_ID!r}; "
                     f"discovered {ids} in etcd)")


def recover_master_key(account_id: str) -> bytes:
    record = _keystore_record(account_id)
    if record is None:
        raise SystemExit(f"keystore record not found for account id {account_id!r}")
    slots = parse_keystorage(record)
    if not slots:
        raise SystemExit("no key slots found in keystore record")
    slot_id, enc = next(iter(slots.items()))
    master = gpg_decrypt(enc, OMNI_PRIV)
    if len(master) != 32:
        raise SystemExit(f"unexpected master key length {len(master)}")
    print(f"[*] key slot        : {slot_id}")
    print(f"[*] master key (AES-256-GCM): {master.hex()}")
    return master


# ------------------------------------------------------------------- resource decrypt
def decrypt_value(master: bytes, value: bytes) -> bytes:
    if len(value) < 14 or value[0] != 1:
        raise ValueError("not an Omni-encrypted value")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ct = value[1:13], value[13:]
    plain = AESGCM(master).decrypt(nonce, ct, None)
    if len(plain) > 1 and plain[0] == 0x00:          # compression marshaler frame
        frame = plain[2:]                             # plain[1] = compressor id (zstd)
        plain = subprocess.run(["zstd", "-d", "-c"], input=frame,
                               capture_output=True, check=True).stdout
    return plain


def extract_bundle(master: bytes, account_id: str):
    """Find the Talos SecretsBundle YAML inside ImportedClusterSecrets/ClusterSecrets."""
    prefix_base = f"/omni/{account_id}/default/".encode()
    for rtype in (b"ImportedClusterSecrets.omni.sidero.dev",
                  b"ClusterSecrets.omni.sidero.dev"):
        for key, value in etcd_range(prefix_base + rtype + b"/", prefix=True):
            try:
                plain = decrypt_value(master, value)
            except Exception as e:
                print(f"    (skip {key.decode(errors='replace')}: {e})")
                continue
            for s in walk_byte_strings(plain):
                try:
                    text = s.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if "secretboxencryptionsecret" in text and "certs" in text:
                    print(f"[*] found secrets bundle in {rtype.decode()} "
                          f"({len(text)} bytes)")
                    return text
    raise SystemExit("no secrets bundle found in the data store")


# --------------------------------------------------------------------------- main
def parse_args():
    import argparse
    p = argparse.ArgumentParser(
        description="Decrypt a self-hosted Omni etcd store and rebuild a Talos machine config.")
    p.add_argument("--etcd", default=ETCD, help="etcd endpoint (https:// to enable TLS)")
    p.add_argument("--private-key", default=OMNI_PRIV,
                   help="OpenPGP private key Omni uses for etcd (omni.asc)")
    p.add_argument("--account-id", default=ACCOUNT_ID, help="Omni account id (auto-discovered when empty)")
    p.add_argument("--etcd-ca", default=ETCD_CA, help="etcd server CA (https only)")
    p.add_argument("--etcd-cert", default=ETCD_CERT, help="etcd client cert for mutual TLS")
    p.add_argument("--etcd-key", default=ETCD_KEY, help="etcd client key for mutual TLS")
    p.add_argument("--insecure", action="store_true", default=ETCD_INSECURE,
                   help="skip etcd TLS verification")
    p.add_argument("--cluster", default=CLUSTER, help="cluster name for the generated config")
    p.add_argument("--endpoint", default=CP_ENDPOINT, help="Kubernetes API endpoint for the generated config")
    p.add_argument("--out", default=OUT, help="output directory")
    return p.parse_args()


def main():
    global ETCD, OMNI_PRIV, ACCOUNT_ID, ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_INSECURE, CLUSTER, CP_ENDPOINT, OUT
    a = parse_args()
    ETCD, OMNI_PRIV, ACCOUNT_ID = a.etcd, a.private_key, a.account_id
    ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_INSECURE = a.etcd_ca, a.etcd_cert, a.etcd_key, a.insecure
    CLUSTER, CP_ENDPOINT, OUT = a.cluster, a.endpoint, a.out

    if not os.path.exists(OMNI_PRIV):
        raise SystemExit(
            f"private key {OMNI_PRIV!r} not found.\n"
            "This tool needs the OpenPGP key Omni encrypts its etcd with (the omni.asc\n"
            "passed to Omni's --private-key-source). Point to it with:\n"
            "  extract_talos_config.py --private-key /path/to/omni.asc [flags]")

    os.makedirs(OUT, exist_ok=True)
    print("=" * 66)
    print(" Omni etcd -> Talos machine config  (pure-Python extraction)")
    print("=" * 66)
    print(f"[*] etcd            : {ETCD}")

    account_id = resolve_account()
    print(f"[*] account id      : {account_id}")
    master = recover_master_key(account_id)
    bundle_yaml = extract_bundle(master, account_id)

    secrets_path = os.path.join(OUT, "secrets.yaml")
    with open(secrets_path, "w") as f:
        f.write(bundle_yaml)
    print(f"[*] wrote Talos secrets bundle -> {secrets_path}")

    # Transform the secrets into a full, valid Talos machine config.
    talosctl = subprocess.run(["which", "talosctl"], capture_output=True).stdout.strip()
    if not talosctl:
        print("[!] talosctl not found; secrets.yaml written, skipping config gen.")
        return
    cmd = ["talosctl", "gen", "config", CLUSTER, CP_ENDPOINT,
           "--with-secrets", secrets_path, "--output-dir", OUT, "--force"]
    print("[*] " + " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode == 0:
        print(f"\n[+] machine configs written to {OUT}:")
        for fn in sorted(os.listdir(OUT)):
            print(f"      {fn}")
        print("\n    controlplane.yaml / worker.yaml are signed by the extracted CA")
        print("    and are directly usable with `talosctl apply-config`.")


if __name__ == "__main__":
    main()
