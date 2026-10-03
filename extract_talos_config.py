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
RUN = os.path.dirname(os.path.abspath(__file__))
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "287cfd52-735b-4dbf-bfc8-c47593e09c3b")
ETCD = os.environ.get("ETCD_ENDPOINT", "https://127.0.0.1:2379")
ETCD_CA = os.environ.get("ETCD_CA", f"{RUN}/etcd-certs/ca.crt")
ETCD_CERT = os.environ.get("ETCD_CERT", f"{RUN}/etcd-certs/client.crt")
ETCD_KEY = os.environ.get("ETCD_KEY", f"{RUN}/etcd-certs/client.key")
OMNI_PRIV = os.environ.get("OMNI_PRIVATE_KEY", f"{RUN}/keys/omni.asc")
CLUSTER = os.environ.get("CLUSTER_ID", "imported-cluster")
CP_ENDPOINT = os.environ.get("CP_ENDPOINT", "https://10.5.0.2:6443")
OUT = os.environ.get("OUT_DIR", f"{RUN}/extracted-python")


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
    ctx = ssl.create_default_context(cafile=ETCD_CA)
    ctx.load_cert_chain(ETCD_CERT, ETCD_KEY)
    ctx.check_hostname = False
    return ctx


def prefix_range_end(key: bytes) -> bytes:
    """Return the etcd range_end that selects all keys with the given prefix."""
    end = bytearray(key)
    for j in range(len(end) - 1, -1, -1):
        if end[j] < 0xFF:
            end[j] += 1
            return bytes(end[:j + 1])
    return b""


def etcd_range(key: bytes, prefix=False):
    """Return list of (key_bytes, value_bytes). If prefix, range over key*."""
    body = {"key": base64.b64encode(key).decode()}
    if prefix:
        body["range_end"] = base64.b64encode(prefix_range_end(key)).decode()
    req = urllib.request.Request(
        f"{ETCD}/v3/kv/range",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=_etcd_ctx(), timeout=15) as r:
        resp = json.load(r)
    out = []
    for kv in resp.get("kvs", []):
        out.append((base64.b64decode(kv["key"]), base64.b64decode(kv["value"])))
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


def recover_master_key() -> bytes:
    hexhash = sha256(ACCOUNT_ID.encode()).hexdigest()
    kskey = f"keystore-omni/record-store/{hexhash}".encode()
    kvs = etcd_range(kskey)
    if not kvs:
        raise SystemExit(f"keystore record not found: {kskey.decode()}")
    slots = parse_keystorage(kvs[0][1])
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


def extract_bundle(master: bytes):
    """Find the Talos SecretsBundle YAML inside ImportedClusterSecrets/ClusterSecrets."""
    prefix_base = f"/omni/{ACCOUNT_ID}/default/".encode()
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
def main():
    os.makedirs(OUT, exist_ok=True)
    print("=" * 66)
    print(" Omni etcd -> Talos machine config  (pure-Python extraction)")
    print("=" * 66)
    print(f"[*] etcd            : {ETCD}")
    print(f"[*] account id      : {ACCOUNT_ID}")

    master = recover_master_key()
    bundle_yaml = extract_bundle(master)

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
