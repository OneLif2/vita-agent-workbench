"""After independently pairing once, record runs A and B using only the saved pin. No writes to Vita."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

import pinned_check as pair
import check_in_place as health

def same_unit(a,b):
    fields=("host","port","host_fingerprint","pin_file_sha256","core","build")
    if not all(a.get(k)==b.get(k) for k in fields):
        raise ValueError("endpoint, build or saved identity changed")
    if not all(re.fullmatch("[0-9A-F]{16}",r.get("run","")) for r in (a,b)):
        raise ValueError("invalid run id")
    if a["run"]==b["run"]:
        raise ValueError("same run: Workbench has not restarted")
    if not a.get("transport_sha256") or not b.get("transport_sha256") or a["transport_sha256"]==b["transport_sha256"]:
        raise ValueError("expected two distinct authenticated SSH sessions")

def public(host,port):
    path,fp=pair.canonical_saved(pair.pin_path(host,port),host,port)
    return fp,hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase",choices=["first","second"])
    p.add_argument("--records",type=Path,required=True)
    p.add_argument("--host",default=pair.DEFAULT_HOST)
    p.add_argument("--port",type=int,default=2222)
    p.add_argument("--key",type=Path,default=Path.home()/".ssh"/"id_ecdsa_wb")
    a=p.parse_args(); host,port=pair.endpoint(a.host,a.port)
    parent=a.records.resolve(); parent.mkdir(parents=True,exist_ok=True)
    dest=parent/(a.phase+".json")
    if dest.exists(): raise ValueError("phase already recorded; will not overwrite")
    first=json.loads((parent/"first.json").read_text(encoding="utf8")) if a.phase=="second" else None
    fp,file_hash=public(host,port)
    if first is not None and (first["host"],first["port"],first["host_fingerprint"],first["pin_file_sha256"])!=(host,port,fp,file_hash):
        raise ValueError("saved pairing changed since first run; refusing to connect")
    v=health.measure(host,fp,a.key,case="core",port=port)
    if v.get("result")!="PASS" or (fp,file_hash)!=public(host,port):
        raise ValueError("health did not pass or pin file changed")
    v.update(host=host,port=port,host_fingerprint=fp,pin_file_sha256=file_hash,
             utc=datetime.now(timezone.utc).isoformat(),phase=a.phase)
    if first is not None:
        same_unit(first,v)
        v["run_before_restart"]=first["run"]
        v["across_restart"]="PASS"
    with dest.open("x",encoding="utf8") as f:json.dump(v,f,indent=2);f.write("\n")
    print(dest.read_text(encoding="utf8"));return 0

if __name__=="__main__":
    try: sys.exit(main())
    except (ValueError,OSError,health.Problem) as e:
        print("INCONCLUSIVE:",e,file=sys.stderr);sys.exit(2)
