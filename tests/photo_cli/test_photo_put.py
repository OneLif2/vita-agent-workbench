"""Real argparse/cmd_put with a local SSH contract double; zero network."""
import base64
import contextlib
import hashlib
import io
import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(os.environ.get("WB_TEST_TOOLS", Path(__file__).resolve().parents[2] / "tools"))))
import wbctl


JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwg"
    "JC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIy"
    "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR"
    "CAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAj/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QA"
    "FAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AJ/AB//Z")


def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))


PNG = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)) +
       chunk(b"IDAT", zlib.compress(b"\x00\x80")) + chunk(b"IEND", b""))


def digest(data):
    return hashlib.sha256(data).hexdigest()


ROOT = "ux0:/VITA-POC/"
HELP = "workbench 01.58 commands\r\n  photo-export <file> <sha256>\r\n"


class Peer:
    """Never overwrite; album is distinct from staging; verify bytes at export."""
    def __init__(self):
        self.calls = []
        self.files = {}
        self.album = []
        self.tweak = {}

    def __call__(self, command, *, timeout=0, stdin_bytes=None):
        assert timeout > 0
        args = command.split()
        cmd = args[0]
        self.calls.append(cmd)
        if cmd == "help":
            reply = (0, HELP)
        elif cmd == "ext":
            _, verb, path = args
            assert verb == "stat"
            reply = (0, f"F {path} {len(self.files[path])}" if path in self.files else "ERR not-found")
        elif cmd == "put":
            _, path, length, expected = args
            if isinstance(stdin_bytes,wbctl.wb_tree.FileSource):
                stdin_bytes=stdin_bytes.path.read_bytes()  # small inert contract fixture only
            assert int(length) == len(stdin_bytes) and expected == "sha256=" + digest(stdin_bytes)
            if path in self.files:
                reply = (1, "ERR destination-exists")
            else:
                self.files[path] = stdin_bytes
                reply = (0, f"OK put path={path} bytes={length} {expected}")
        elif cmd == "photo-export":
            _, path, expected = args
            assert stdin_bytes is None
            raw = self.files[path]
            if digest(raw) != expected:
                reply = (1, "ERR photo-sha")
            else:
                self.album.append(expected)
                reply = (0, f"OK photo-export bytes={len(raw)} sha256={expected}")
        else:
            raise AssertionError(command)
        return self.tweak.get(cmd, lambda pair: pair)(reply)


class PhotoPut(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.peer = Peer()

    def go(self, raw=JPEG, name="image.jpg", flags=("--image",), remote=None):
        self.peer.calls.clear()
        src = self.base / name
        src.write_bytes(raw)
        argv = ["put", str(src)]
        if remote is not None:
            argv.append(remote)
        argv.extend(flags)
        stream = io.StringIO()
        with mock.patch.object(wbctl, "ssh", side_effect=self.peer), contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            try:
                code = wbctl.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, stream.getvalue()

    def test_jpeg_from_parser_to_export(self):
        rc, out = self.go()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.peer.calls, ["help", "ext", "put", "photo-export"])
        self.assertEqual(self.peer.album, [digest(JPEG)])

    def test_png_and_explicit_dest(self):
        self.assertEqual(self.go(PNG, "original.PNG", remote=ROOT+"valid-2.PNG")[0], 0)
        self.assertEqual(self.peer.files[ROOT+"valid-2.PNG"], PNG)
        self.assertEqual(self.peer.album, [digest(PNG)])

    def test_plain_put_never_exports(self):
        self.assertEqual(self.go(raw=b"any normal bytes", flags=())[0], 0)
        self.assertEqual(self.peer.calls, ["put"])
        self.assertEqual(self.peer.album, [])

    def test_plain_put_conflicting_receipt_fails(self):
        self.peer.tweak["put"] = lambda ok: (0, ok[1]+"\nERR upload-failed")
        self.assertEqual(self.go(flags=())[0], 4)

    def test_plain_put_path_cannot_append_an_option(self):
        self.assertEqual(self.go(flags=(), remote=ROOT+"file --install")[0], 2)
        self.assertEqual(self.peer.calls, [])

    def test_old_core_no_side_effect(self):
        self.peer.tweak["help"] = lambda _: (0, "workbench 01.57 commands\n  put <path> <bytes>\n")
        self.assertEqual(self.go()[0], 3)
        self.assertEqual(self.peer.calls, ["help"])

    def test_unreachable_capability_no_side_effect(self):
        self.peer.tweak["help"] = lambda _: (255, "Connection lost")
        self.assertEqual(self.go()[0], 3)
        self.assertEqual(self.peer.calls, ["help"])
        self.peer.tweak["help"] = lambda _: (0, HELP+"ERR conflicting reply")
        self.assertEqual(self.go()[0], 3)
        self.assertEqual(self.peer.calls, ["help"])

    def test_existing_same_contents_no_reupload(self):
        self.peer.files[ROOT+"image.jpg"] = JPEG
        self.assertEqual(self.go()[0], 0)
        self.assertEqual(self.peer.calls, ["help", "ext", "photo-export"])
        self.assertEqual(self.peer.album, [digest(JPEG)])

    def test_same_size_wrong_digest_no_overwrite_or_import(self):
        path = ROOT+"image.jpg"
        self.peer.files[path] = b"x"*len(JPEG)
        self.assertEqual(self.go()[0], 5)
        self.assertEqual(self.peer.calls, ["help", "ext", "photo-export"])
        self.assertEqual((self.peer.album, self.peer.files[path]), ([], b"x"*len(JPEG)))

    def test_different_size_collision_no_mutation(self):
        path = ROOT+"image.jpg"
        self.peer.files[path] = b"previous file"
        self.assertEqual(self.go()[0], 4)
        self.assertEqual(self.peer.calls, ["help", "ext"])
        self.assertEqual(self.peer.files[path], b"previous file")

    def test_ambiguous_stat_no_put(self):
        self.peer.tweak["ext"] = lambda _: (0, "ERR not-found\nERR io-error")
        self.assertEqual(self.go()[0], 4)
        self.assertEqual(self.peer.calls, ["help", "ext"])

    def test_missing_or_conflicting_upload_receipt_no_export(self):
        for kind, alter in [
            ("missing", lambda _: (0, "")),
            ("mixed", lambda ok: (0, ok[1]+"\nERR failed")),
            ("exit", lambda ok: (1, ok[1])),
            ("hash", lambda ok: (0, ok[1][:-1]+"!")),
        ]:
            with self.subTest(kind=kind):
                self.peer.files.clear()
                self.peer.tweak["put"] = alter
                self.assertEqual(self.go()[0], 4)
                self.assertNotIn("photo-export", self.peer.calls)

    def test_unknown_or_lost_export_reply_is_not_retried(self):
        for kind, alter in [
            ("timeout", lambda _: (124, "TIMEOUT")),
            ("dropped", lambda _: (255, "connection closed")),
            ("conflict", lambda ok: (0, ok[1]+"\nERR conflicting")),
            ("duplicate", lambda ok: (0, ok[1]+"\n"+ok[1])),
            ("wrong digest", lambda ok: (0, ok[1][:-1]+"!")),
            ("wrong status", lambda ok: (1, ok[1])),
        ]:
            with self.subTest(kind=kind):
                self.peer.files.clear()
                self.peer.tweak["photo-export"] = alter
                rc, out = self.go()
                self.assertEqual(rc, 6)
                self.assertIn("INCONCLUSIVE", out)
                self.assertEqual(self.peer.calls.count("photo-export"), 1)

    def test_non_ascii_local_name_gets_safe_digest_name(self):
        for name in ["two words.jpg", "\u76f8\u7247.jpg"]:
            with self.subTest(name=name):
                self.peer.files.clear()
                self.assertEqual(self.go(name=name)[0], 0)
                self.assertEqual(set(self.peer.files), {ROOT+"photo-"+digest(JPEG)+".jpg"})

    def test_explicit_remote_cannot_escape_or_change_format(self):
        for path in [ROOT+"bad.jpg --install", ROOT+"../bad.jpg", ROOT+"sub/bad.jpg", ROOT+"image.png",
                     "ux0:picture/image.jpg", ROOT+"a"*96+".jpg"]:
            with self.subTest(path=path):
                self.assertEqual(self.go(remote=path)[0], 2)
                self.assertEqual(self.peer.calls, [])

    def test_extension_and_signature_must_match(self):
        for raw, name in [(JPEG, "bad.png"), (PNG, "bad.jpg"), (JPEG, "x.bin"), (JPEG[:-2],"truncated.jpg"),
                          (PNG[:-1], "truncated.png"), (PNG[:16]+bytes(4)+PNG[20:], "width-zero.png"),
                          (b"", "empty.jpg"), (b"PK\x03\x04","package.jpg")]:
            with self.subTest(name=name):
                self.assertEqual(self.go(raw, name)[0], 2)
                self.assertEqual(self.peer.calls, [])

    def test_size_cap_before_ssh(self):
        # Only a size/signature acceptance check — no claim that these padding
        # bytes describe a real decodable image.
        limit = 8*1024*1024
        image = JPEG[:-2]+bytes(limit-len(JPEG))+JPEG[-2:]
        self.assertEqual(self.go(image)[0], 0)
        self.assertEqual(self.go(image[:-2]+b"x"+JPEG[-2:])[0], 2)
        self.assertEqual(self.peer.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
