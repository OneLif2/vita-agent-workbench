import zipfile, re, os, json, collections

VPK = r"D:\OneDrive\_python_test\PS-Vita-REA\v1.55\analysis\ssh-vita.vpk"
OUT = r"D:\OneDrive\_python_test\PS-Vita-REA\v1.55\analysis\extracted"
os.makedirs(OUT, exist_ok=True)

z = zipfile.ZipFile(VPK)
print("=== entries ===")
for i in z.infolist():
    print(f"{i.file_size:>9}  {i.filename}")
z.extractall(OUT)

def strings(path, minlen=4):
    data = open(path, "rb").read()
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "ignore"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "ignore"))
    return out

targets = []
for root, _, files in os.walk(OUT):
    for f in files:
        p = os.path.join(root, f)
        if os.path.getsize(p) > 1024 and (f.endswith(".bin") or f.endswith(".suprx") or f.endswith(".skprx") or f == "eboot.bin"):
            targets.append(p)

print("\n=== modules analysed ===")
for t in targets:
    print(os.path.relpath(t, OUT), os.path.getsize(t))

allstr = {}
for t in targets:
    allstr[os.path.relpath(t, OUT)] = strings(t)

keywords = {
    "sftp/scp": r"sftp|scp|SFTP|SCP",
    "crypto": r"chacha20|ChaCha20|aes128-ctr|aes256-ctr|hmac-sha2|curve25519|ed25519|rsa-sha2",
    "auth": r"password|publickey|authorized_keys|login|lockout|attempt",
    "commands": r"^(ls|cp|mv|rm|mkdir|rmdir|unzip|zip|tar|gunzip|gzip|curl|wget|nc|apps|df|du|stat|find|grep|sha256|md5|cat|head|tail|touch|chmod|pwd|cd|help|ps|mods|mem|input|shot|screenshot|reboot|power)$",
    "paths": r"ux0:|ur0:|uma0:|imc0:|savedata|app0:",
    "plugin": r"\.suprx|\.skprx|taihen|kernel|module_start|plugin",
    "menu": r"Select|D-pad|keep.awake|Start SSH|Stop SSH|Restart",
}

for name, ss in allstr.items():
    print(f"\n=== {name}: {len(ss)} strings ===")
    for label, pat in keywords.items():
        rx = re.compile(pat, re.I)
        hits = [s for s in ss if rx.search(s)]
        uniq = list(dict.fromkeys(hits))
        print(f"-- {label} ({len(uniq)})")
        for h in uniq[:25]:
            print("   ", h[:120])

json.dump({k: v for k, v in allstr.items()}, open(os.path.join(OUT, "strings.json"), "w", encoding="utf-8"), ensure_ascii=False)
print("\nsaved strings.json")
