"""Fail before ELF conversion when the core lacks actual PT_LOAD headroom."""
import struct
import sys
from pathlib import Path


def main(path):
    elf = Path(path).read_bytes()
    if elf[:7] != b"\x7fELF\x01\x01\x01" or struct.unpack_from("<H", elf, 18)[0] != 40:
        raise SystemExit("layout: expected a little-endian 32-bit ARM ELF")
    off = struct.unpack_from("<I", elf, 28)[0]
    step, count = struct.unpack_from("<HH", elf, 42)
    if step < 32 or off + count * step > len(elf):
        raise SystemExit("layout: inconsistent program headers")
    loads = []
    for i in range(count):
        typ, _, va, _, _, memsz, flags, _ = struct.unpack_from("<8I", elf, off+i*step)
        if typ == 1:
            loads.append((va, memsz, flags))
    if len(loads) < 2 or not (loads[0][2] & 1) or not (loads[1][2] & 2):
        raise SystemExit("layout: expected executable then writable load segments")
    gap = loads[1][0] - (loads[0][0] + loads[0][1])
    if gap < 4096:
        raise SystemExit(f"layout: only {gap} bytes of real headroom; need 4096 before conversion")
    print(f"PASS core layout: {gap} bytes of actual SCE metadata headroom")


if __name__ == "__main__":
    main(sys.argv[1])
