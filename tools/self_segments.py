"""Bounded Vita SDK plain-SELF segment decoder for offline release auditing.

No loader, filesystem writes or device control. Feature audits must inspect
logical_bytes; forbidden marker audits must inspect BOTH it and the physical
image, since legacy uncompressed fself containers retain ELF section tables.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
import zlib

FULL_PERMISSION_AUTHID = 0x2F00000000000001
MAX_IMAGE = 32 * 1024 * 1024
MAX_SEGMENTS = 64


class SelfError(ValueError):
    pass


def need(ok: bool, why: str) -> None:
    if not ok:
        raise SelfError(why)


def region(offset: int, size: int, limit: int, what: str) -> tuple[int, int]:
    need(0 <= offset <= limit and 0 <= size <= limit - offset, what + " out of bounds")
    return offset, offset + size


def disjoint(ranges: list[tuple[int, int]], what: str) -> None:
    ordered = sorted((a, b) for a, b in ranges if b > a)
    need(all(a >= previous[1] for previous, (a, _) in zip(ordered, ordered[1:])), what + " overlap")


@dataclass(frozen=True)
class Segment:
    index: int
    ph_type: int
    file_offset: int
    file_size: int
    memory_size: int
    virtual_address: int
    flags: int
    stored_offset: int
    stored_size: int
    compression: int
    encryption: int
    info_offset: int
    data: bytes


@dataclass(frozen=True)
class SelfImage:
    authid: int
    elf_offset: int
    phdr_offset: int
    section_info_offset: int
    header_len: int
    elf_file_size: int
    compressed: bool
    legacy_elf_mirror: bool
    segments: tuple[Segment, ...]
    logical_bytes: bytes


def _inflate(stored: bytes, expected: int) -> bytes:
    """At most expected+1 output, exactly one zlib member and optional 4B pad."""
    decoder = zlib.decompressobj()
    try:
        data = decoder.decompress(stored, expected + 1)
    except zlib.error as exc:
        raise SelfError("bad zlib stream") from exc
    need(len(data) == expected and decoder.eof and not decoder.unconsumed_tail,
         "zlib output size/eof mismatch")
    trailer = decoder.unused_data
    # Older installed VitaSDK writes an exact stream. Newer VitaSDK may
    # include its 0..3 zero bytes of 4-byte padding in sinfo.length.
    if trailer:
        consumed = len(stored) - len(trailer)
        need(len(trailer) <= 3 and not any(trailer) and
             len(stored) % 4 == 0 and len(trailer) == (-consumed) % 4,
             "extra zlib member/trailer")
    return data


def parse_self(image: bytes, label: str = "SELF", *,
               required_authid: int = FULL_PERMISSION_AUTHID,
               max_logical_size: int = MAX_IMAGE) -> SelfImage:
    """Parse supported plain ARM32 fself layouts, rejecting ambiguous wrappers.

    Supports SDK's legacy uncompressed full-ELF mirror and packed plain
    uncompressed/compressed segments. It does not accept encrypted/mixed
    segments, arbitrary trailing data, overlapping logical/physical ranges,
    or decompression beyond the declared and globally bounded file size.
    """
    need(isinstance(image, bytes), label + ": bytes required")
    need(0x100 <= len(image) <= MAX_IMAGE and 0 < max_logical_size <= MAX_IMAGE,
         label + ": image size limit")
    magic, version, sdk, kind, metadata = struct.unpack_from("<IIHHI", image)
    need(magic == 0x00454353 and version == 3 and sdk == 0xC0 and kind == 1,
         label + ": unsupported SELF header")
    (header_len, elf_size, self_size, unknown, self_offset, appoff, elfoff,
     phoff, shoff, infooff, versionoff, ctrloff, ctrlsize, padding) = struct.unpack_from("<14Q", image, 16)
    need(0x100 <= header_len <= len(image) and header_len % 16 == 0 and
         self_size == len(image) and 0 < elf_size <= max_logical_size,
         label + ": SELF size/header mismatch")
    need(unknown == 0 and padding == 0 and self_offset == 4 and shoff == 0,
         label + ": unsupported SELF fields")
    need(metadata < header_len and metadata >= 0x80, label + ": metadata offset")
    region(appoff, 32, header_len, "appinfo")
    authid, vendor, self_type, app_version, app_padding = struct.unpack_from("<QIIQQ", image, appoff)
    need(authid == required_authid and vendor == 0 and self_type in (8, 13) and
         app_version == 0x1000000000000 and app_padding == 0,
         label + ": authid/appinfo mismatch")
    region(elfoff, 52, header_len, "ELF header")
    ident, etype, machine, eversion, entry, e_phoff, e_shoff, e_flags, ehsize, phsize, phnum, shsize, shnum, shindex = struct.unpack_from("<16sHHIIIIIHHHHHH", image, elfoff)
    need(ident[:7] == b"\x7fELF\x01\x01\x01" and not any(ident[7:]) and
         machine == 40 and eversion == 1 and ehsize == 52 and phsize == 32 and
         1 <= phnum <= MAX_SEGMENTS and e_phoff == 52,
         label + ": unsupported ARM32 ELF header")
    need(etype in (0xFE00, 0xFE04, 0xFFA5) and e_flags in (0x05000000, 0x05001000),
         label + ": unsupported ELF type/flags")
    need(e_shoff == 0 and shsize == 0 and shnum == 0 and shindex == 0,
         label + ": unexpected wrapper section table")
    tables = [(0, 128), region(appoff, 32, header_len, "appinfo"),
              region(elfoff, 52, header_len, "ELF header"),
              region(phoff, phnum * 32, header_len, "program headers"),
              region(infooff, phnum * 32, header_len, "segment table"),
              region(versionoff, 16, header_len, "SCE version"),
              region(ctrloff, ctrlsize, header_len, "control info")]
    disjoint(tables, "header tables")
    covered = bytearray(header_len)
    for first, last in tables:
        covered[first:last] = b"\1" * (last - first)
    need(not any(byte for byte, known in zip(image[:header_len], covered) if not known),
         label + ": nonzero unclaimed header bytes")
    need(ctrlsize > 0, label + ": missing control info")
    # A bounded chain prevents arbitrary bytes being disguised as another
    # header record. Feature strings are never sourced from these headers.
    cursor = ctrloff
    control_types = []
    while cursor < ctrloff + ctrlsize:
        region(cursor, 16, ctrloff + ctrlsize, "control header")
        ctype, size, used, reserved = struct.unpack_from("<4I", image, cursor)
        need(size >= 16 and size % 16 == 0 and size <= ctrloff + ctrlsize - cursor,
             label + ": control info size")
        need(ctype in (4, 5, 6, 7) and used == (0 if ctype == 7 else 1) and reserved == 0 and
             size == (80 if ctype in (4, 7) else 272),
             label + ": unsupported control info")
        control_types.append(ctype)
        cursor += size
    need(cursor == ctrloff + ctrlsize and control_types == [4, 5, 6, 7],
         label + ": control chain mismatch")
    raw = []
    logical_ranges = []
    physical_ranges = []
    memory_ranges = []
    for i in range(phnum):
        ph_type, offset, vaddr, paddr, filesz, memsz, flags, align = struct.unpack_from("<8I", image, phoff + 32 * i)
        stored_offset, stored_size, compression, encryption = struct.unpack_from("<4Q", image, infooff + 32 * i)
        need(ph_type in (1, 0x60000000) and encryption == 2 and compression in (1, 2),
             label + ": unsupported segment type/encoding")
        need(align != 0 and align <= 0x1000 and align & (align - 1) == 0,
             label + ": segment alignment")
        logical_ranges.append(region(offset, filesz, elf_size, "logical segment"))
        physical_ranges.append(region(stored_offset, stored_size, len(image), "stored segment"))
        need(stored_offset >= header_len and stored_size <= MAX_IMAGE,
             label + ": segment overlaps header")
        if ph_type == 1:
            need(filesz <= memsz and vaddr == paddr and flags in (4, 5, 6, 7),
                 label + ": load segment shape")
            memory_ranges.append(region(vaddr, memsz, 1 << 32, "load memory"))
        else:
            need(vaddr == 0 and paddr == 0 and memsz == 0 and flags == 0,
                 label + ": relocation segment shape")
        raw.append((i, ph_type, offset, filesz, memsz, vaddr, flags,
                    stored_offset, stored_size, compression, encryption, infooff + 32 * i))
    disjoint(logical_ranges, "logical segments")
    disjoint(physical_ranges, "stored segments")
    disjoint(memory_ranges, "load memory")
    modes = {x[9] for x in raw}
    need(len(modes) == 1, label + ": mixed compression is not supported")
    compressed = modes == {2}
    legacy = (not compressed and len(image) == header_len + elf_size and
              image[header_len:header_len + 7] == b"\x7fELF\x01\x01\x01" and
              all(x[7] == header_len + x[2] and x[8] == x[3] for x in raw))
    if legacy:
        mirror = image[header_len:]
        region(0, 52, len(mirror), "mirrored ELF header")
        need(struct.unpack_from("<H", mirror, 18)[0] == 40 and
             struct.unpack_from("<H", mirror, 44)[0] == phnum and
             struct.unpack_from("<H", mirror, 42)[0] == 32,
             label + ": mirrored ELF identity mismatch")
        mirror_phoff = struct.unpack_from("<I", mirror, 28)[0]
        region(mirror_phoff, phnum * 32, len(mirror), "mirrored program headers")
        need(mirror[mirror_phoff:mirror_phoff + phnum * 32] == image[phoff:phoff + phnum * 32],
             label + ": mirrored program headers mismatch")
        # Legacy tools copy a complete ELF, including non-loaded section
        # tables. Require that table to account for the file's exact EOF;
        # arbitrary appendages cannot be hidden by inflating SELF lengths.
        mirror_shoff = struct.unpack_from("<I", mirror, 32)[0]
        mirror_shsize, mirror_shnum, mirror_shstr = struct.unpack_from("<3H", mirror, 46)
        need(mirror_shsize == 40 and 0 < mirror_shnum <= 4096 and
             mirror_shstr < mirror_shnum,
             label + ": mirrored section header shape")
        section_range = region(mirror_shoff, mirror_shnum * 40, len(mirror), "mirrored sections")
        need(section_range[1] == len(mirror), label + ": unclaimed mirrored ELF trailer")
        mirror_covered = bytearray(len(mirror))
        for first, last in [(0, 52), (mirror_phoff, mirror_phoff + phnum * 32),
                            section_range, *logical_ranges]:
            mirror_covered[first:last] = b"\1" * (last - first)
        for i in range(mirror_shnum):
            name, typ, flags, addr, off, size, link, info, alignment, entsize = struct.unpack_from("<10I", mirror, mirror_shoff + 40 * i)
            need(alignment == 0 or alignment & (alignment - 1) == 0,
                 label + ": mirrored section alignment")
            if typ != 8:  # SHT_NOBITS has memory size but no file bytes.
                first, last = region(off, size, mirror_shoff, "mirrored section data")
                mirror_covered[first:last] = b"\1" * (last - first)
        need(not any(byte for byte, known in zip(mirror, mirror_covered) if not known),
             label + ": unclaimed mirrored ELF bytes")
    else:
        # Packed SDK output: first segment at header_len, 16-byte alignment
        # between segments, no unclaimed trailer. Alignment gaps must be zero.
        end = header_len
        for x in raw:
            start, size = x[7], x[8]
            expected = end if end == header_len else (end + 15) & ~15
            need(start == expected and not any(image[end:start]),
                 label + ": noncanonical segment gap")
            end = start + size
        need(end == len(image), label + ": unclaimed physical trailer")
    segments = []
    extent = max(b for _, b in logical_ranges)
    need(extent <= max_logical_size, label + ": logical allocation limit")
    logical = bytearray(extent)
    for x in raw:
        stored = image[x[7]:x[7] + x[8]]
        if compressed:
            data = _inflate(stored, x[3])
        else:
            extra = stored[x[3]:]
            need(x[3] <= len(stored) <= x[3] + 3 and not any(extra),
                 label + ": uncompressed segment length/pad")
            if extra:
                need(len(stored) % 4 == 0 and len(extra) == (-x[3]) % 4,
                     label + ": noncanonical segment pad")
            data = stored[:x[3]]
        logical[x[2]:x[2] + x[3]] = data
        segments.append(Segment(*x, data))
    return SelfImage(authid, elfoff, phoff, infooff, header_len, elf_size,
                     compressed, legacy, tuple(segments), bytes(logical))
