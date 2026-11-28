"""The Vita app snapshot must request system RW. No device and no install.

The header comment may name the failing POSIX mode. The sceIoOpen call itself
must pass 0666, the same mode the other Vita writers use.
"""
from pathlib import Path
source = Path(__file__).resolve().parents[2] / 'source' / 'wb_app_spool_vita.h'
text = source.read_text(encoding='utf-8')
open_lines = [line.strip() for line in text.splitlines() if 'sceIoOpen(' in line]
assert len(open_lines) == 1, open_lines
assert open_lines[0].endswith(',0666);'), open_lines[0]
assert '0600' not in open_lines[0]
assert ',0600)' not in text and ', 0600)' not in text
print('PASS app snapshot spool opens with 0666')
