"""Generate synthetic host test replies from the independent native core definition."""
from pathlib import Path
import re

_header=(Path(__file__).resolve().parents[1]/"source"/"wb_ver.h").read_text(encoding="utf-8")
VERSION=re.search(r'^#define\s+WB_VERSION\s+"(\d{2}\.\d{2})"\s*$',_header,re.M)[1]
BUILD=VERSION+re.search(r'^#define\s+WB_BUILD_TAG\s+WB_VERSION\s+"([^"]+)"\s*$',_header,re.M)[1]
