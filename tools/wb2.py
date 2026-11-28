"""Workbench 2.0 (02.18+) PC-Side Agent-Operated CLI.

- Always verifies the pinned Vita SSH host key on the PC side and prints it
  in the PC terminal (never on the Vita OLED screen).
- Zero-button self-update: `wb2.py update [vpk]` uploads via Turbo SFTP,
  verifies WBQ2 stage (`install ... --no-reload`), runs `update apply`
  (`INAP00019` atomic promote + auto-relaunch with zero button presses),
  waits for reconnect, verifies the new build & run ID, and cleans up `/inbox`.
- Generic agent app commands: `patch-eboot`, `install-vpk`, `launch`, `apps`.
- Fast Turbo SFTP transfers (`push` / `pull`) & interactive PTY `exec`.
"""
from __future__ import annotations
import argparse, hashlib, hmac, json, os, re, socket, sys, time
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import paramiko
import pinned_check as pin
import stage_review as F
import wbterm as W

HOST, PORT, USER = W.HOST, W.PORT, W.USER
PIN = "HOST_SHA256"
DEFAULT_VPK = ROOT / "build/workbench_0221.vpk"
ANSI_SGR = re.compile(r"\x1b\[[0-9;]*m")
ANSI_SGR_B = re.compile(rb"\x1b\[[0-9;]*m")
PROMPT_RE = re.compile(rb"(?:pi@vita:[^\r\n]*\$ |(?:ux0|ur0|uma0):[^\r\n]*> )$")
PROMPT_STR_RE = re.compile(r"(?:pi@vita:[^\r\n]*\$ |(?:ux0|ur0|uma0):[^\r\n]*> )$")


def need(ok: bool, msg: str):
    if not ok:
        raise RuntimeError(msg)


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def verify_and_print_pin(quiet: bool = False) -> tuple[Path, str]:
    pf, h = pin.canonical_saved(pin.pin_path(HOST, PORT), HOST, PORT)
    need(hmac.compare_digest(h, PIN), f"Saved host pin mismatch: {h}")
    if not quiet:
        print(f"[WB2 PC-PIN VERIFIED] {USER}@{HOST}:{PORT} host_key_sha256={h}", file=sys.stderr, flush=True)
    return pf, h


def pty_cmd(t, cmd: str, timeout: float = 60.0) -> list[str]:
    t.ch.settimeout(timeout)
    t.ch.sendall((cmd + "\r").encode("ascii"))
    buf = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = t.ch.recv(16384)
        if not chunk:
            break
        buf += chunk
        if PROMPT_RE.search(ANSI_SGR_B.sub(b"", buf)):
            break
    text = ANSI_SGR.sub("", buf.decode("utf8", "replace"))
    text = PROMPT_STR_RE.sub("", text)
    lines = [ln.rstrip("\r") for ln in text.split("\n")]
    if lines and lines[0].strip() == cmd.strip():
        lines = lines[1:]
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return lines


def open_sftp(quiet: bool = False):
    _, expected = verify_and_print_pin(quiet=quiet)
    owner = Path(os.environ.get("WB_KEY", str(Path.home() / ".ssh/id_ecdsa_wb")))
    sock = socket.create_connection((HOST, PORT), timeout=8)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 524288)
    tr = paramiko.Transport(sock)
    tr.default_window_size = 4 * 1024 * 1024
    tr.default_max_packet_size = 65536
    tr.start_client(timeout=8)
    key = tr.get_remote_server_key()
    need(key.get_name() == pin.ALGO and hmac.compare_digest(pin.digest(key.asbytes()), expected), "Live SSH host key mismatch")
    tr.auth_publickey(USER, paramiko.ECDSAKey.from_private_key_file(str(owner)))
    need(tr.is_authenticated() and tr.is_active(), "Owner ECDSA key rejected")
    return tr, paramiko.SFTPClient.from_transport(tr)


def sftp_push(local: Path, remote_leaf: str, quiet: bool = False) -> dict:
    data = local.read_bytes()
    total = len(data)
    sha = hashlib.sha256(data).hexdigest()
    t0 = time.perf_counter()
    tr, sftp = open_sftp(quiet=quiet)
    meter = None if quiet else W.TransferMeter()
    try:
        t_xfer = time.perf_counter()
        # Send exact SSH_FILEXFER_ATTR_SIZE in SSH_FXP_OPEN so the Vita displays real 0-100% progress.
        attr = paramiko.SFTPAttributes()
        attr.st_size = total
        flags = paramiko.sftp.SFTP_FLAG_WRITE | paramiko.sftp.SFTP_FLAG_CREATE | paramiko.sftp.SFTP_FLAG_TRUNC
        t_code, msg = sftp._request(paramiko.sftp.CMD_OPEN, "/" + remote_leaf, flags, attr)
        need(t_code == paramiko.sftp.CMD_HANDLE, f"SFTP OPEN rejected: code={t_code}")
        handle = msg.get_binary()
        with paramiko.SFTPFile(sftp, handle, "wb", -1) as dst:
            dst.set_pipelined(True)
            t_wr = time.perf_counter()
            if meter:
                meter.update("SFTP PUT", 0, total)
            for off in range(0, total, 32768):
                chunk = data[off:off + 32768]
                dst.write(chunk)
                if meter:
                    meter.update("SFTP PUT", off + len(chunk), total)
            dt_wr = max(time.perf_counter() - t_wr, 1e-6)
        dt = max(time.perf_counter() - t_xfer, 1e-6)
        sftp.close()
    finally:
        if meter:
            meter.finish()
        tr.close()
        time.sleep(0.3)
    return {
        "remote": f"ux0:/VITA-POC/{remote_leaf}",
        "bytes": total,
        "sha256": sha,
        "stream_mb_s": round((total / 1048576) / dt_wr, 3),
        "mb_s": round((total / 1048576) / dt, 3),
        "transfer_s": round(dt, 3),
        "total_s": round(time.perf_counter() - t0, 3),
    }


def sftp_pull(remote_leaf: str, local: Path, quiet: bool = False) -> dict:
    t0 = time.perf_counter()
    tr, sftp = open_sftp(quiet=quiet)
    meter = None if quiet else W.TransferMeter()
    try:
        t_xfer = time.perf_counter()
        rpath = "/" + remote_leaf.lstrip("/")
        st = sftp.stat(rpath)
        total = int(st.st_size) if st and st.st_size is not None else None
        chunks = []
        done = 0
        with sftp.open(rpath, "rb") as src:
            src.prefetch(total)
            if meter:
                meter.update("SFTP GET", 0, total)
            while True:
                blk = src.read(32768)
                if not blk:
                    break
                chunks.append(blk)
                done += len(blk)
                if meter:
                    meter.update("SFTP GET", done, total)
        data = b"".join(chunks)
        dt = max(time.perf_counter() - t_xfer, 1e-6)
        sftp.close()
    finally:
        if meter:
            meter.finish()
        tr.close()
        time.sleep(0.25)
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(data)
    return {
        "remote": f"ux0:/VITA-POC/{remote_leaf.lstrip('/')}",
        "local": str(local),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "mb_s": round((len(data) / 1048576) / dt, 3),
        "total_s": round(time.perf_counter() - t0, 3),
    }


def cmd_status(_args):
    verify_and_print_pin()
    with W.paired_terminal() as t:
        ident = t.check()
        need(ident["host_sha256"] == PIN, "Terminal host pin mismatch")
        out = {
            "identity": ident,
            "wb_status": pty_cmd(t, "wb status"),
            "df_h": pty_cmd(t, "df -h"),
            "uptime": pty_cmd(t, "uptime"),
            "free_h": pty_cmd(t, "free -h"),
        }
    print(json.dumps(out, indent=2))


def cmd_exec(args):
    verify_and_print_pin()
    with W.paired_terminal() as t:
        ident = t.check()
        need(ident["host_sha256"] == PIN, "Terminal host pin mismatch")
        for line in pty_cmd(t, args.command, timeout=args.timeout):
            print(line)


def cmd_push(args):
    local = Path(args.local).resolve()
    need(local.is_file(), f"Missing local file: {local}")
    leaf = args.remote_leaf or f"{local.stem}-{int(time.time())}{local.suffix}"
    res = sftp_push(local, leaf)
    with W.paired_terminal() as t:
        t.check()
        chk = pty_cmd(t, f'sha256sum "{res["remote"]}"')
    res["device_sha256_check"] = chk
    need(any(res["sha256"] in x for x in chk), f"Device SHA-256 mismatch: {chk}")
    print(json.dumps(res, indent=2))


def cmd_pull(args):
    res = sftp_pull(args.remote_leaf, Path(args.local).resolve())
    print(json.dumps(res, indent=2))


def cmd_update(args):
    verify_and_print_pin()
    vpk = Path(args.vpk).resolve() if args.vpk else DEFAULT_VPK
    need(vpk.is_file(), f"Missing VPK: {vpk}")
    sha = sha256_file(vpk)
    build_tag = args.build_tag or "02.21-hyper-sftp"
    pkg = F.package(SimpleNamespace(vpk=vpk, sha256=sha, build=build_tag))
    target_ver = pkg["version"]
    leaf = f"workbench_{target_ver.replace('.', '')}-{sha[:12]}.vpk"
    remote = f"ux0:/VITA-POC/{leaf}"
    q = W.quoted_path(remote)

    with W.paired_terminal() as t:
        before_ident = t.check()
        need(before_ident["host_sha256"] == PIN, "Host pin mismatch")
        stat = F.reply(t, f"tree-stat {q}")

    if stat == ["TTY1 OK ABSENT"]:
        up = sftp_push(vpk, leaf, quiet=True)
    elif stat == ["TTY1 OK FILE"]:
        up = {"method": "reused-existing", "remote": remote, "bytes": pkg["size"], "sha256": sha}
    else:
        raise RuntimeError(f"Unexpected destination state: {stat}")

    # Stage & immediately apply via zero-button WBQ2 + INAP00019 auto-return
    with W.paired_terminal() as t:
        t.ch.settimeout(60)
        s = t.check()
        insp = F.reply(t, f"inspect {q}")
        expected_insp = [
            f"file bytes={pkg['size']} sha256={sha}",
            *pkg["members"],
            f"title_id=INAP00018 app_ver={target_ver} title=Vita Agent Workbench",
        ]
        need(sorted(insp) == sorted(expected_insp), f"Vita inspect mismatch: {insp}")
        pend0 = F.reply(t, "pending")
        if pend0 != [f"pending-core: {pkg['receipt']}"]:
            ack = F.reply(t, f"install {q} sha256={sha} --no-reload")
            need(any(x.startswith(f"OK install version={target_ver} title=INAP00018 ") for x in ack) and
                 not any(x.startswith(("ERR", "WARN")) for x in ack), f"Stage failed: {ack}")
        else:
            ack = ["reused-existing-stage"]
        pend1 = F.reply(t, "pending")
        need(pend1 == [f"pending-core: {pkg['receipt']}"], f"Pending mismatch: {pend1}")
        apply_out = F.reply(t, "update apply")
        need(any("launching INAP00019" in x for x in apply_out), f"Unexpected update apply reply: {apply_out}")

    # Poll until the promoted Workbench returns to SSH LISTENING with zero button presses
    t_wait = time.monotonic()
    deadline = t_wait + 150
    attempts = []
    after_ident = None
    time.sleep(4.0)
    while time.monotonic() < deadline:
        try:
            with W.paired_terminal() as t:
                t.ch.settimeout(20)
                cur = t.check()
                if cur["version"] != target_ver or cur["run"] == before_ident["run"]:
                    attempts.append({"seen": cur["version"], "run": cur["run"]})
                    time.sleep(2.0)
                    continue
                need(cur["build"] == build_tag and cur["host_sha256"] == PIN, f"Unexpected post-update identity: {cur}")
                pend_post = F.reply(t, "pending")
                need(pend_post == ["pending-core: no"], f"Queue not cleared: {pend_post}")
                wbs = pty_cmd(t, "wb status")
                rm_out = pty_cmd(t, f"rm {q}")
                after_ident = cur
                break
        except Exception as exc:
            attempts.append({"wait": repr(exc)})
            time.sleep(2.0)

    need(after_ident is not None, f"Timed out waiting for {target_ver} auto-return: {attempts[-4:]}")
    receipt = {
        "utc": F.utc(),
        "mode": "ZERO_BUTTON_AGENT_UPDATE",
        "physical_buttons_pressed": 0,
        "before": before_ident,
        "upload": up,
        "stage_ack": ack,
        "apply_reply": apply_out,
        "after": after_ident,
        "reboot_s": round(time.monotonic() - t_wait, 2),
        "wb_status": wbs,
        "inbox_cleanup": rm_out,
        "vpk_sha256": sha,
    }
    if args.receipt:
        out_p = Path(args.receipt).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf8")
    print(json.dumps(receipt, indent=2))


def cmd_patch_eboot(args):
    verify_and_print_pin()
    src = args.eboot
    cleanup = False
    if src.startswith("ux0:/VITA-POC/") or src.startswith("/inbox/"):
        remote = src.replace("/inbox/", "ux0:/VITA-POC/", 1)
        up = {"method": "on-device", "remote": remote}
    else:
        lp = Path(src).resolve()
        need(lp.is_file(), f"Missing local eboot: {lp}")
        leaf = f"patch-{args.title}-{int(time.time())}.bin"
        up = sftp_push(lp, leaf, quiet=True)
        remote = up["remote"]
        cleanup = not args.keep
    ver_arg = f" --ver {args.ver}" if args.ver else ""
    with W.paired_terminal() as t:
        ident = t.check()
        res = pty_cmd(t, f'app patch-eboot {args.title} "{remote}"{ver_arg}', timeout=120)
        if cleanup:
            pty_cmd(t, f'rm "{remote}"')
    need(any(x.startswith("OK app-patch-eboot ") for x in res), f"patch-eboot failed: {res}")
    print(json.dumps({"identity": ident, "upload": up, "patch": res}, indent=2))


def cmd_install_vpk(args):
    verify_and_print_pin()
    src = args.vpk
    cleanup = False
    if src.startswith("ux0:/VITA-POC/") or src.startswith("/inbox/"):
        remote = src.replace("/inbox/", "ux0:/VITA-POC/", 1)
        up = {"method": "on-device", "remote": remote}
    else:
        lp = Path(src).resolve()
        need(lp.is_file(), f"Missing local VPK: {lp}")
        leaf = f"app-{lp.stem}-{int(time.time())}.vpk"
        up = sftp_push(lp, leaf, quiet=True)
        remote = up["remote"]
        cleanup = not args.keep
    with W.paired_terminal() as t:
        ident = t.check()
        res = pty_cmd(t, f'app install-vpk "{remote}"', timeout=args.timeout)
        if cleanup:
            pty_cmd(t, f'rm "{remote}"')
    need(any(x.startswith("OK app-install-vpk ") for x in res), f"install-vpk failed: {res}")
    print(json.dumps({"identity": ident, "upload": up, "install": res}, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="sub", required=True)

    sub.add_parser("status", help="Show PC-verified host key + Vita status, storage, RAM & clocks")

    p_ex = sub.add_parser("exec", help="Execute a shell command/pipeline over paired PTY")
    p_ex.add_argument("command")
    p_ex.add_argument("--timeout", type=float, default=60.0)

    p_up = sub.add_parser("update", help="Zero-button Workbench core update via Turbo SFTP + WBQ2 + INAP00019")
    p_up.add_argument("vpk", nargs="?", help="Path to workbench_XXXX.vpk")
    p_up.add_argument("--build-tag", default="02.21-hyper-sftp")
    p_up.add_argument("--receipt", help="Optional JSON receipt output path")

    p_pu = sub.add_parser("push", help="Upload file to /inbox via Turbo SFTP + verify SHA-256")
    p_pu.add_argument("local")
    p_pu.add_argument("remote_leaf", nargs="?")

    p_pl = sub.add_parser("pull", help="Download file from /inbox via Turbo SFTP")
    p_pl.add_argument("remote_leaf")
    p_pl.add_argument("local")

    p_pe = sub.add_parser("patch-eboot", help="Generic atomic eboot patch for any user title")
    p_pe.add_argument("title")
    p_pe.add_argument("eboot")
    p_pe.add_argument("--ver", help="Optional XX.YY APP_VER update in param.sfo")
    p_pe.add_argument("--keep", action="store_true")

    p_iv = sub.add_parser("install-vpk", help="Install any non-system user VPK")
    p_iv.add_argument("vpk")
    p_iv.add_argument("--keep", action="store_true")
    p_iv.add_argument("--timeout", type=float, default=1800.0)

    args = ap.parse_args()
    {
        "status": cmd_status,
        "exec": cmd_exec,
        "update": cmd_update,
        "push": cmd_push,
        "pull": cmd_pull,
        "patch-eboot": cmd_patch_eboot,
        "install-vpk": cmd_install_vpk,
    }[args.sub](args)


if __name__ == "__main__":
    main()
