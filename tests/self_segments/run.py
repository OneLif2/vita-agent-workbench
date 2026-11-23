"""Offline strict SELF decoding tests; synthetic containers, no device or network."""
from pathlib import Path
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from self_segments import parse_self, SelfError, FULL_PERMISSION_AUTHID


def fixture(data=(b"audited-feature\0" * 4,), *, compressed=True, legacy=False, pad=False):
    n = len(data); header_len = 4096; phoff = 224; infooff = phoff + n * 32
    versionoff = infooff + n * 32; ctrloff = versionoff + 16
    need = 4096
    phdrs = []
    for i, chunk in enumerate(data):
        off = (need + 15) & ~15; need = off + len(chunk)
        phdrs.append((1, off, 0x81000000 + i * 0x10000, 0x81000000 + i * 0x10000,
                       len(chunk), len(chunk) + 16, 5, 4096))
    sht = need; elf_size = sht + 40
    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    fields = (ident, 0xFE04, 40, 1, 0, 52, 0, 0x05000000, 52, 32, n, 0, 0, 0)
    image = bytearray(header_len)
    struct.pack_into("<IIHHI14Q", image, 0, 0x00454353, 3, 0xC0, 1, 0x600,
                     header_len, elf_size, 0, 0, 4, 128, 160, phoff, 0, infooff,
                     versionoff, ctrloff, 704, 0)
    struct.pack_into("<QIIQQ", image, 128, FULL_PERMISSION_AUTHID, 0, 8, 0x1000000000000, 0)
    struct.pack_into("<16sHHIIIIIHHHHHH", image, 160, *fields)
    for i, ph in enumerate(phdrs):
        struct.pack_into("<8I", image, phoff + 32 * i, *ph)
    cursor = ctrloff
    for kind, size in ((4, 80), (5, 272), (6, 272), (7, 80)):
        struct.pack_into("<4I", image, cursor, kind, size, 0 if kind == 7 else 1, 0)
        cursor += size
    if legacy:
        assert not compressed
        elf = bytearray(elf_size)
        f = list(fields); f[6] = sht; f[11:14] = [40, 1, 0]
        struct.pack_into("<16sHHIIIIIHHHHHH", elf, 0, *f)
        for i, ph in enumerate(phdrs):
            struct.pack_into("<8I", elf, 52 + 32 * i, *ph)
            elf[ph[1]:ph[1] + len(data[i])] = data[i]
            struct.pack_into("<4Q", image, infooff + i * 32,
                             header_len + ph[1], len(data[i]), 1, 2)
        image.extend(elf)
    else:
        for i, chunk in enumerate(data):
            while len(image) % 16: image.append(0)
            start = len(image); stored = zlib.compress(chunk, 9) if compressed else chunk
            if pad: stored += b"\0" * ((-len(stored)) % 4)
            image.extend(stored)
            struct.pack_into("<4Q", image, infooff + i * 32,
                             start, len(stored), 2 if compressed else 1, 2)
    struct.pack_into("<Q", image, 0x20, len(image))
    return bytes(image)


def alter(image, offset, fmt, *values):
    b = bytearray(image); struct.pack_into(fmt, b, offset, *values); return bytes(b)


def replace_stored(image, stored):
    v = parse_self(image); assert len(v.segments) == 1
    b = bytearray(image[:v.header_len]); b.extend(stored)
    s = v.segments[0]
    struct.pack_into("<4Q", b, s.info_offset, v.header_len, len(stored), 2, 2)
    struct.pack_into("<Q", b, 0x20, len(b))
    return bytes(b)


count = 0
def good(name, image):
    global count
    v = parse_self(image); assert v.segments; count += 1; return v


def bad(name, image, **kwargs):
    global count
    try: parse_self(image, **kwargs)
    except SelfError: count += 1; return
    raise AssertionError("accepted malformed SELF: " + name)


data = (b"feature-one\0" * 5, b"feature-two\0" * 3)
views = [good("compressed", fixture(data)), good("compressed-pad", fixture(data, pad=True)),
         good("uncompressed-packed", fixture(data, compressed=False)),
         good("uncompressed-packed-pad", fixture(data, compressed=False, pad=True)),
         good("legacy-full-elf", fixture(data, compressed=False, legacy=True))]
assert len({x.logical_bytes for x in views}) == 1
assert [s.data for s in views[0].segments] == list(data)
empty = good("compressed-empty-segment", fixture((b"",)))
assert empty.logical_bytes == b"\0" * 4096

base = fixture(); view = parse_self(base); first = view.segments[0]; ph = view.phdr_offset; si = first.info_offset
for name, image in (
    ("truncated-header", base[:100]),
    ("magic", alter(base, 0, "<I", 0)),
    ("version", alter(base, 4, "<I", 4)),
    ("sdk", alter(base, 8, "<H", 0)),
    ("kind", alter(base, 10, "<H", 2)),
    ("physical-length", alter(base, 0x20, "<Q", len(base) + 1)),
    ("logical-bomb", alter(base, 0x18, "<Q", 0xFFFFFFFFFFFFFFFF)),
    ("metadata", alter(base, 12, "<I", 4096)),
    ("header-table-overlap", alter(base, 0x38, "<Q", 0)),
    ("header-unclaimed", alter(base, 4095, "<B", 1)),
    ("wrong-authid", alter(base, 0x80, "<Q", FULL_PERMISSION_AUTHID + 1)),
    ("wrong-arm", alter(base, view.elf_offset + 18, "<H", 3)),
    ("bad-elf-type", alter(base, view.elf_offset + 16, "<H", 2)),
    ("bad-ph-count", alter(base, view.elf_offset + 44, "<H", 0xFFFF)),
    ("bad-ph-size", alter(base, view.elf_offset + 42, "<H", 31)),
    ("encrypted", alter(base, si + 24, "<Q", 1)),
    ("unknown-compression", alter(base, si + 16, "<Q", 3)),
    ("physical-overflow", alter(base, si, "<Q", 0xFFFFFFFFFFFFFFFF)),
    ("length-overflow", alter(base, si + 8, "<Q", 0xFFFFFFFFFFFFFFFF)),
    ("inside-header", alter(base, si, "<Q", 1)),
    ("logical-overflow", alter(base, ph + 4, "<I", 0xFFFFFFFF)),
    ("load-memory-overflow", alter(base, ph + 8, "<II", 0xFFFFFFF0, 0xFFFFFFF0)),
    ("filesz-exceeds-memsz", alter(base, ph + 20, "<I", 1)),
    ("bad-alignment", alter(base, ph + 28, "<I", 3)),
    ("control-size-zero", alter(base, view.section_info_offset + 32 + 16 + 4, "<I", 0)),
): bad(name, image)

# A caller-supplied tighter allocation budget must remain a bound, never a hint.
bad("caller-limit", base, max_logical_size=100)
bad("caller-invalid-limit", base, max_logical_size=1 << 31)

compressed = base[first.stored_offset:first.stored_offset + first.stored_size]
bad("zlib-truncated", replace_stored(base, compressed[:-1]))
bad("zlib-garbage", replace_stored(base, compressed + b"x"))
bad("zlib-second-member", replace_stored(base, compressed + zlib.compress(b"another")))
bad("zlib-extra-four-zero", replace_stored(base, compressed + b"\0" * 4))
bad("zlib-output-bomb", replace_stored(base, zlib.compress(b"A" * 1000000)))
bad("zlib-too-short", replace_stored(base, zlib.compress(b"x")))
bad("zlib-bad-adler", replace_stored(base, compressed[:-1] + bytes([compressed[-1] ^ 1])))
appended = bytearray(base + b"hidden-marker"); struct.pack_into("<Q", appended, 0x20, len(appended))
bad("physical-trailer-with-correct-length", bytes(appended))

multi = fixture(data); mv = parse_self(multi); a, b = mv.segments
bad("mixed-compression", alter(multi, b.info_offset + 16, "<Q", 1))
bad("physical-overlap", alter(multi, b.info_offset, "<Q", a.stored_offset))
bad("logical-overlap", alter(multi, mv.phdr_offset + 32 + 4, "<I", a.file_offset))
bad("virtual-overlap", alter(multi, mv.phdr_offset + 32 + 8, "<II", a.virtual_address, a.virtual_address))
gap = a.stored_offset + a.stored_size
assert gap < b.stored_offset
bad("nonzero-alignment-gap", alter(multi, gap, "<B", 1))

legacy = fixture(data, compressed=False, legacy=True); lv = parse_self(legacy)
bad("legacy-mirror-phdr", alter(legacy, lv.header_len + 52, "<I", 2))
bad("legacy-unclaimed-elf-byte", alter(legacy, lv.header_len + 1024, "<B", 1))
tail = bytearray(legacy + b"hidden")
struct.pack_into("<Q", tail, 0x20, len(tail)); struct.pack_into("<Q", tail, 0x18, lv.elf_file_size + 6)
bad("legacy-trailer-with-correct-self-length", bytes(tail))

# A feature audit must not treat nonloaded physical bytes as program features.
physical_only = bytearray(base)
ctrl = struct.unpack_from("<Q", base, 0x68)[0]
physical_only[ctrl + 20:ctrl + 20 + len(b"not-a-feature")] = b"not-a-feature"
pv = good("control-payload-not-logical", bytes(physical_only))
assert b"not-a-feature" not in pv.logical_bytes

print(f"PASS {count} strict SELF segment cases; bounded zlib, ranges, identity, exact EOF and legacy/packed equivalence (host only)")
