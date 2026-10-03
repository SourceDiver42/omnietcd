"""Unit tests for the pure parsing/crypto helpers in extract_talos_config.py.

The protobuf and range-end helpers run with the standard library alone. The
AES-GCM round-trip tests are skipped when the `cryptography` package is not
installed, and the zstd test is skipped when the `zstd` CLI is unavailable.
"""

import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import extract_talos_config as m  # noqa: E402


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field, wire):
    return varint((field << 3) | wire)


def ld(field, payload):
    """length-delimited field encoding."""
    return tag(field, 2) + varint(len(payload)) + payload


def vint(field, value):
    return tag(field, 0) + varint(value)


class ProtobufTests(unittest.TestCase):
    def test_read_varint(self):
        self.assertEqual(m._read_varint(b"\x01", 0), (1, 1))
        self.assertEqual(m._read_varint(varint(300), 0), (300, 2))
        self.assertEqual(m._read_varint(varint(16384), 0), (16384, 3))

    def test_iter_fields_mixed(self):
        buf = vint(1, 1) + ld(3, b"hi")
        fields = list(m.iter_fields(buf))
        self.assertEqual(fields, [(1, 0, 1), (3, 2, b"hi")])

    def test_iter_fields_truncated_raises(self):
        buf = tag(2, 2) + varint(10) + b"short"
        with self.assertRaises(ValueError):
            list(m.iter_fields(buf))

    def test_walk_byte_strings_descends(self):
        inner = ld(1, b"hello")
        outer = ld(2, inner)
        found = m.walk_byte_strings(outer)
        self.assertIn(b"hello", found)
        self.assertIn(inner, found)

    def test_parse_keystorage(self):
        enc = b"-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----\n"
        key_slot = vint(1, 1) + ld(2, enc)            # KeySlot{algorithm=1, encrypted_key=enc}
        map_entry = ld(1, b"slot-id") + ld(2, key_slot)  # map<string,KeySlot> entry
        storage = vint(1, 1) + ld(2, map_entry)       # Storage{version=1, key_slots=...}
        slots = m.parse_keystorage(storage)
        self.assertEqual(slots, {"slot-id": enc})


class RangeEndTests(unittest.TestCase):
    def test_increments_last_byte(self):
        self.assertEqual(m.prefix_range_end(b"/omni/x/"), b"/omni/x0")

    def test_simple(self):
        self.assertEqual(m.prefix_range_end(b"abc"), b"abd")

    def test_rollover_trims(self):
        self.assertEqual(m.prefix_range_end(b"a\xff"), b"b")

    def test_all_ff(self):
        self.assertEqual(m.prefix_range_end(b"\xff\xff"), b"")


HAVE_CRYPTO = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:
    pass


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class DecryptTests(unittest.TestCase):
    def _seal(self, key, plaintext):
        # Mirror Omni's format: 0x01 | 12-byte nonce | AES-256-GCM(ct+tag).
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = b"\x00" * 12
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return b"\x01" + nonce + ct

    def test_decrypt_uncompressed(self):
        key = b"\x11" * 32
        value = self._seal(key, b"plain protobuf bytes")
        self.assertEqual(m.decrypt_value(key, value), b"plain protobuf bytes")

    def test_rejects_bad_marker(self):
        key = b"\x11" * 32
        with self.assertRaises(ValueError):
            m.decrypt_value(key, b"\x02" + b"\x00" * 20)

    @unittest.skipUnless(shutil.which("zstd"), "zstd CLI not available")
    def test_decrypt_zstd_framed(self):
        key = b"\x22" * 32
        payload = b"cluster:\n  secret: topsecret\n" * 50
        frame = subprocess.run(
            ["zstd", "-q", "-c"], input=payload, capture_output=True, check=True
        ).stdout
        # compression marshaler prefix: 0x00, compressor-id, <zstd frame>
        plain = b"\x00\x01" + frame
        value = self._seal(key, plain)
        self.assertEqual(m.decrypt_value(key, value), payload)


if __name__ == "__main__":
    unittest.main()
