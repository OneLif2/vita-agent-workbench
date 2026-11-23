import ftplib, os, sys, time

OUT = r"D:\OneDrive\_python_test\PS-Vita-REA\v1.52\evidence\diag-" + time.strftime("%Y%m%dT%H%M%S")
os.makedirs(OUT, exist_ok=True)

ftp = ftplib.FTP()
ftp.connect("192.0.2.10", 1337, timeout=20)
ftp.login("anonymous", "")
ftp.cwd("ux0:")
print("cwd ok")

files = [
    "run.log", "startup.log", "timeline.txt", "peer.txt",
    "mac-public-pin.txt", "updater.log", "install.log",
    "power-last-r1.txt", "power-last-manual.txt",
]
for name in files:
    try:
        with open(os.path.join(OUT, name), "wb") as fh:
            ftp.retrbinary("RETR data/INAP00018/" + name, fh.write)
        print("got", name, os.path.getsize(os.path.join(OUT, name)))
    except Exception as e:
        print("miss", name, e)

# listings for context
for d, label in (("data/INAP00018", "root"), ("data/INAP00018/payload", "payload")):
    try:
        print("cwd", d, "->", ftp.cwd(d))
        lines = []
        ftp.retrlines("LIST", lines.append)
        print("\n".join(lines[:20]))
    except Exception as e:
        print("list fail", d, e)

ftp.quit()
print("OUT=", OUT)
