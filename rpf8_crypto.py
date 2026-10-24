"""RDR2 PS4 RPF8 reader / TFIT decoder. Project: PratikHackTR.

Portable adaptation of the decoder recovered from our localization workflow.
Format/TFIT references: https://github.com/0x1F9F1/Swage
No game executable, encryption key/table bytes or Oodle runtime is embedded.
See README.md for the private prerequisites and validation boundaries.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import re
import struct
import sys
import zlib
from pathlib import Path

LIMIT = 64 * 1024 * 1024
# A public Swage lookup identifier, NOT the IV bytes themselves.
IV_ID = '5C8xGcF{L^AxqTQd!ofA'


class Crypto:
    """Load private material from explicit offsets in a user-supplied ELF."""

    def __init__(self, elf, locations, swage_header):
        self.elf = Path(elf)
        self.locations = Path(locations)
        self.swage_header = Path(swage_header)
        self.loaded = False

    def load(self):
        if self.loaded:
            return
        source = self.swage_header.read_text(encoding='utf-8')

        def ids(name):
            match = re.search(r'\b' + name + r'\s*\[[^\]]*\]\s*\{(.*?)\};', source, re.S)
            if not match:
                raise ValueError(f'Missing Swage definition: {name}')
            return re.findall(r'"([^"\n]+)"', match.group(1))

        locations = json.loads(self.locations.read_text(encoding='utf-8'))
        key_ids = ids('RDR2_PS4_KEY_HASHES')
        table_ids = ids('RDR2_TFIT_TABLE_HASHES')
        if len(key_ids) != 164 or len(table_ids) != 272:
            raise ValueError('Expected 164 PS4 keys and 272 TFIT table identifiers')
        with self.elf.open('rb') as f:
            if f.read(4) != b'\x7fELF':
                raise ValueError('Supply a decrypted ELF, not an encrypted SELF/PKG')
            length = self.elf.stat().st_size

            def get(identifier, expected):
                if identifier not in locations:
                    raise ValueError(f'Missing private location for identifier {identifier}')
                row = locations[identifier]
                offset, size = int(row['offset']), int(row['size'])
                if size != expected or offset < 0 or offset + size > length:
                    raise ValueError(f'Invalid ELF location for identifier {identifier}')
                f.seek(offset)
                data = f.read(size)
                if len(data) != size:
                    raise ValueError('Truncated ELF material')
                return data

            self.keys = [struct.unpack('<80I', get(s, 320)) for s in key_ids]
            self.tables = [struct.unpack('<256I', get(s, 1024)) for s in table_ids]
            self.iv = get(IV_ID, 16)
        self.loaded = True

    def decrypt(self, data, tag, initial=None):
        if tag == 255:
            return data
        self.load()
        index = 163 if tag == 192 else tag
        if not 0 <= index < len(self.keys):
            raise ValueError(f'Unsupported PS4 TFIT key tag: {tag}')
        key = self.keys[index]
        previous = self.iv if initial is None else initial
        out = bytearray(data)
        for pos in range(0, len(data) // 16 * 16, 16):
            block = data[pos:pos + 16]
            v = block
            for round_index in range(17):
                order = (tuple(range(16)) if round_index in (0, 1, 16)
                         else (0, 7, 10, 13, 1, 4, 11, 14, 2, 5, 8, 15, 3, 6, 9, 12))
                values = []
                for word in range(4):
                    value = key[(round_index + 1) * 4 + word]
                    for j in range(4):
                        value ^= self.tables[round_index * 16 + word * 4 + j][v[order[word * 4 + j]]]
                    values.append(value)
                v = struct.pack('<4I', *values)
            out[pos:pos + 16] = bytes(a ^ b for a, b in zip(v, previous))
            previous = block
        return bytes(out)


class Oodle:
    """Lazy loading: plaintext and DEFLATE do not require this DLL."""

    def __init__(self, path):
        self.path = Path(path).resolve() if path else None
        self.lib = None

    def decompress(self, data, logical):
        if self.path is None:
            raise ValueError('Codec 2 requires your own compatible 64-bit Oodle DLL (--oodle)')
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ValueError('The Oodle integration requires 64-bit Python')
        if self.lib is None:
            self.lib = ctypes.CDLL(str(self.path))
            self.lib.OodleLZ_Decompress.restype = ctypes.c_longlong
            self.lib.OodleLZ_Decompress.argtypes = [
                ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
            ] + [ctypes.c_void_p] * 10
        target = ctypes.create_string_buffer(logical)
        source = ctypes.create_string_buffer(data)
        n = self.lib.OodleLZ_Decompress(
            source, len(data), target, logical, 1, 0, 0,
            None, None, None, None, None, None, 3,
        )
        if n != logical:
            raise ValueError(f'Oodle output length mismatch: {n} != {logical}')
        return target.raw


class Archive:
    def __init__(self, path, offset=0, size=None, *, crypto=None, oodle=None):
        self.path = Path(path)
        self.offset = offset
        self.size = self.path.stat().st_size - offset if size is None else size
        self.crypto = crypto
        self.oodle = oodle or Oodle(None)
        file_size = self.path.stat().st_size
        if offset < 0 or self.size < 272 or offset + self.size > file_size:
            raise ValueError('RPF container bounds')
        with self.path.open('rb') as f:
            f.seek(offset)
            self.header = f.read(272)
            magic, count, names, tag, self.platform = struct.unpack_from('<IIIHH', self.header)
            if magic != 0x52504638 or count > 100000 or 272 + count * 24 > self.size:
                raise ValueError('Invalid or unsupported RPF8 header')
            self.toc = self._decrypt(f.read(count * 24), tag)
        self.entries = []
        for i in range(count):
            a, b, c = struct.unpack_from('<QQQ', self.toc, 24 * i)
            e = dict(index=i, hash=a & 0xffffffff, ext=(a >> 48) & 255,
                     key=(a >> 40) & 255, config=(a >> 32) & 255,
                     resource=(a >> 56) & 1, signature=(a >> 57) & 1,
                     offset=((b >> 28) & 0x7fffffff) * 16,
                     stored=(b & 0xfffffff) * 16, codec=b >> 59, logical=c)
            if e['offset'] + e['stored'] > self.size:
                raise ValueError(f'RPF entry {i} bounds; check ELF/map/platform')
            self.entries.append(e)

    def _decrypt(self, data, tag, initial=None):
        if tag == 255:
            return data
        if self.crypto is None:
            raise ValueError('Encrypted data requires --elf, --locations and --swage-header')
        return self.crypto.decrypt(data, tag, initial)

    def nested(self, e):
        if e['resource'] or e['key'] != 255 or e['codec'] != 0:
            raise ValueError('Only unwrapped nested archives are supported')
        if e['logical'] > e['stored']:
            raise ValueError('Nested archive size exceeds entry storage')
        return Archive(self.path, self.offset + e['offset'], e['logical'],
                       crypto=self.crypto, oodle=self.oodle)

    def read(self, e):
        if e['ext'] == 254:
            raise ValueError('Directory/metadata entry is not an extractable file')
        if e['stored'] > LIMIT:
            raise ValueError('64 MiB stored-entry limit')
        if e['offset'] < 0 or e['offset'] + e['stored'] > self.size:
            raise ValueError('RPF entry bounds')
        size = e['stored'] - 16 * e['resource'] - 256 * e['signature']
        if size < 0:
            raise ValueError('Invalid resource/signature overhead')
        with self.path.open('rb') as f:
            f.seek(self.offset + e['offset'] + 16 * e['resource'])
            data = f.read(size)
        if len(data) != size:
            raise ValueError('Truncated entry')
        if e['key'] != 255:
            config = e['config']
            head = 0x400 << ((config & 3) * 2) if config & 3 else 0
            length = 0x400 << ((config >> 2) & 7) if (config >> 2) & 7 else 0
            stride = (((config >> 5) & 7) + 1) << 16 if length else 0
            ranges, cursor, tail = [], 0, len(data) - 1024

            def add(start, end):
                nonlocal cursor
                start, end = max(start, cursor), min(end, len(data))
                if start < end:
                    ranges.append((start, end))
                    cursor = end

            add(0, head)
            if head < tail:
                chunk = 0x80000 if e['resource'] and e['codec'] else (0x2000 if e['codec'] else 0x1000)
                if length and stride == chunk and tail < stride < len(data):
                    cursor = stride
                elif length:
                    block = stride if cursor else 0
                    while block + length <= tail:
                        add(block, block + length)
                        block += stride
                add(tail, len(data))
            out = bytearray(data)
            previous = None
            for start, end in ranges:
                out[start:end] = self._decrypt(data[start:end], e['key'], previous)
                complete_end = start + (end - start) // 16 * 16
                if complete_end - start >= 16:
                    previous = data[complete_end - 16:complete_end]
            data = bytes(out)
        logical = e['logical']
        if e['resource']:
            logical = (logical & 0xfffffff0) + ((logical >> 32) & 0xfffffff0)
        if not 0 <= logical <= LIMIT:
            raise ValueError('64 MiB decoded-entry limit')
        if e['codec'] == 2:
            return self.oodle.decompress(data, logical)
        if e['codec'] == 1:
            decoder = zlib.decompressobj(-15)
            decoded = decoder.decompress(data, logical + 1)
            if len(decoded) != logical or not decoder.eof:
                raise ValueError('DEFLATE output length/stream mismatch')
            return decoded
        if e['codec'] != 0:
            raise ValueError(f'Unsupported codec: {e["codec"]}')
        if logical > len(data):
            raise ValueError('Uncompressed logical size exceeds available data')
        return data[:logical]


def main(argv=None):
    parser = argparse.ArgumentParser(description='RDR2 PS4 RPF8 reader / TFIT decoder')
    parser.add_argument('command', choices=('list', 'extract'))
    parser.add_argument('archive', type=Path)
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--locations', type=Path)
    parser.add_argument('--swage-header', type=Path)
    parser.add_argument('--oodle', type=Path)
    parser.add_argument('--offset', type=lambda s: int(s, 0), default=0)
    parser.add_argument('--size', type=lambda s: int(s, 0))
    parser.add_argument('--index', type=int, help='Extract one entry (zero based)')
    parser.add_argument('--out', type=Path, help='New, non-existing output directory')
    args = parser.parse_args(argv)
    supplied = [args.elf, args.locations, args.swage_header]
    if any(supplied) and not all(supplied):
        parser.error('--elf, --locations and --swage-header must be supplied together')
    crypto = Crypto(*supplied) if all(supplied) else None
    archive = Archive(args.archive, args.offset, args.size, crypto=crypto, oodle=Oodle(args.oodle))
    if args.command == 'list':
        print(json.dumps(archive.entries, indent=2))
        return 0
    if args.out is None:
        parser.error('extract requires --out')
    rows = archive.entries
    if args.index is not None:
        if not 0 <= args.index < len(rows):
            parser.error('--index is outside this archive')
        rows = [rows[args.index]]
    args.out.mkdir(parents=True, exist_ok=False)
    failures = []
    extracted = 0
    for e in rows:
        if e['ext'] == 254:
            continue
        try:
            data = archive.read(e)
            name = f'{e["index"]:05d}_{e["hash"]:08x}.ext{e["ext"]}'
            with (args.out / name).open('xb') as f:
                f.write(data)
            extracted += 1
            print(name, len(data), flush=True)
        except (OSError, ValueError, zlib.error) as exc:
            failures.append(dict(index=e['index'], error=str(exc)))
            print(f'Entry {e["index"]}: {exc}', file=sys.stderr, flush=True)
    (args.out / 'report.json').write_text(
        json.dumps(dict(extracted=extracted, failures=failures), indent=2), encoding='utf-8')
    return 1 if failures else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, zlib.error) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(1)
