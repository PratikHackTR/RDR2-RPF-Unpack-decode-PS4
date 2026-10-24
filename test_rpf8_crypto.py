"""Synthetic tests only: no game files, real TFIT material or Oodle DLL."""
import contextlib
import io
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from rpf8_crypto import Archive, Crypto, LIMIT, main


def make_archive(payload, logical=None, codec=0, key=255, resource=0, signature=0):
    logical = len(payload) if logical is None else logical
    data = (b'R' * 16 if resource else b'') + payload
    data += b'\0' * (-len(data) % 16)
    data += b'S' * 256 if signature else b''
    header = struct.pack('<IIIHH', 0x52504638, 1, 0, 255, 0).ljust(272, b'\0')
    a = 0x12345678 | key << 40 | 76 << 48 | resource << 56 | signature << 57
    b = len(data) // 16 | (304 // 16) << 28 | codec << 59
    return header + struct.pack('<QQQ', a, b, logical) + b'\0' * 8 + data


class DecoderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, data):
        path = self.root / 'synthetic.rpf'
        path.write_bytes(data)
        return path

    def test_plain(self):
        a = Archive(self.archive(make_archive(b'hello')))
        self.assertEqual(a.entries[0]['hash'], 0x12345678)
        self.assertEqual(a.read(a.entries[0]), b'hello')

    def test_raw_deflate(self):
        original = b'synthetic text' * 100
        z = zlib.compressobj(wbits=-15)
        payload = z.compress(original) + z.flush()
        a = Archive(self.archive(make_archive(payload, len(original), codec=1)))
        self.assertEqual(a.read(a.entries[0]), original)

    def test_deflate_overflow(self):
        z = zlib.compressobj(wbits=-15)
        payload = z.compress(b'A' * 10000) + z.flush()
        a = Archive(self.archive(make_archive(payload, 10, codec=1)))
        with self.assertRaisesRegex(ValueError, 'DEFLATE'):
            a.read(a.entries[0])

    def test_resource_and_signature_are_stripped(self):
        a = Archive(self.archive(make_archive(b'B' * 32, 32, resource=1, signature=1)))
        self.assertEqual(a.read(a.entries[0]), b'B' * 32)

    def test_wrapped_nested_rejected(self):
        a = Archive(self.archive(make_archive(b'B' * 32, 32, resource=1)))
        with self.assertRaisesRegex(ValueError, 'unwrapped'):
            a.nested(a.entries[0])

    def test_nested_nonzero_offset(self):
        child = make_archive(b'inner')
        a = Archive(self.archive(make_archive(child)))
        nested = a.nested(a.entries[0])
        self.assertEqual(nested.offset, 304)
        self.assertEqual(nested.read(nested.entries[0]), b'inner')

    def test_malformed_container(self):
        with self.assertRaises(ValueError):
            Archive(self.archive(b'not RPF8'))
        path = self.archive(make_archive(b'hello'))
        with self.assertRaises(ValueError):
            Archive(path, size=path.stat().st_size + 1)

    def test_entry_outside_archive(self):
        data = bytearray(make_archive(b'hello'))
        struct.pack_into('<Q', data, 280, 999999 << 28 | 1)
        with self.assertRaisesRegex(ValueError, 'bounds'):
            Archive(self.archive(data))

    def test_missing_crypto_for_toc(self):
        data = bytearray(make_archive(b'hello'))
        struct.pack_into('<H', data, 12, 0)
        with self.assertRaisesRegex(ValueError, 'Encrypted'):
            Archive(self.archive(data))

    def test_missing_oodle_and_unknown_codec(self):
        for codec, message in ((2, 'Oodle'), (3, 'Unsupported codec')):
            a = Archive(self.archive(make_archive(b'hello', codec=codec)))
            with self.assertRaisesRegex(ValueError, message):
                a.read(a.entries[0])

    def test_limit_checked_before_decompression(self):
        a = Archive(self.archive(make_archive(b'hello', LIMIT + 1, codec=2)))
        with self.assertRaisesRegex(ValueError, 'limit'):
            a.read(a.entries[0])

    def test_tfit_synthetic_cbc_and_tag_guard(self):
        # Deliberately fake tables. Tests arithmetic/chaining, NOT real keys.
        c = Crypto('unused.elf', 'unused.json', 'unused.h')
        c.loaded = True
        c.keys = [(0,) * 80] * 164
        c.tables = [(0,) * 256] * 272
        c.iv = bytes(range(16))
        data = bytes(range(32)) + b'partial'
        self.assertEqual(c.decrypt(data, 192), c.iv + data[:16] + b'partial')
        self.assertEqual(c.decrypt(data, 255), data)
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            c.decrypt(data, 212)

    def test_cli_and_no_overwrite(self):
        path = self.archive(make_archive(b'hello'))
        output = self.root / 'extracted'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['extract', str(path), '--out', str(output)]), 0)
        self.assertEqual((output / '00000_12345678.ext76').read_bytes(), b'hello')
        self.assertEqual(json.loads((output / 'report.json').read_text())['failures'], [])
        with self.assertRaises(FileExistsError):
            main(['extract', str(path), '--out', str(output)])

    def test_cli_partial_failure_not_success(self):
        path = self.archive(make_archive(b'hello', codec=3))
        output = self.root / 'partial'
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['extract', str(path), '--out', str(output)]), 1)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(report['extracted'], 0)
        self.assertEqual(len(report['failures']), 1)


if __name__ == '__main__':
    unittest.main()
