"""Non-deployable synthetic plain ARM32 SELF for offline host protocol tests."""
import struct,zlib
FULL_PERMISSION_AUTHID=0x2F00000000000001

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
