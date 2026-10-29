import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile

import apk_check

HAVE_JDK = shutil.which("keytool") and shutil.which("jarsigner")


def make_unsigned_apk(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", "not really binary, enough for detection tests")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)


def splice_v2_block(src, dst):
    """Insert a fake APK Signing Block (v2 id, dummy payload) before the central directory.

    Structure: [u64 S][u64 pairLen][u32 id][payload][u64 S][magic]. S = bytes after the first
    size field, excluding it. This checks the parser's layout handling, not signature validity.
    """
    with open(src, "rb") as fh:
        data = fh.read()
    eocd = data.rfind(b"PK\x05\x06")
    cd_off = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    payload = b"\x00" * 16
    pair = struct.pack("<Q", 4 + len(payload)) + struct.pack("<I", apk_check.V2_ID) + payload
    body_after_first = len(pair) + 8 + 16  # pairs + second size field + magic
    block = (struct.pack("<Q", body_after_first) + pair +
             struct.pack("<Q", body_after_first) + apk_check.APK_SIG_BLOCK_MAGIC)
    new_cd = cd_off + len(block)
    head = data[:cd_off] + block
    tail = bytearray(data[cd_off:])
    eocd_rel = eocd - cd_off
    tail[eocd_rel + 16:eocd_rel + 20] = struct.pack("<I", new_cd)
    with open(dst, "wb") as fh:
        fh.write(head + bytes(tail))


class SchemeDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unsigned_has_no_scheme(self):
        p = os.path.join(self.tmp, "u.apk")
        make_unsigned_apk(p)
        self.assertEqual(apk_check.detect_schemes(p), [])

    def test_v2_block_detected(self):
        src = os.path.join(self.tmp, "u.apk")
        dst = os.path.join(self.tmp, "v2.apk")
        make_unsigned_apk(src)
        splice_v2_block(src, dst)
        self.assertIn("v2", apk_check.detect_schemes(dst))

    @unittest.skipUnless(HAVE_JDK, "needs keytool and jarsigner")
    def test_v1_signed_with_jarsigner(self):
        apk = os.path.join(self.tmp, "signed.apk")
        make_unsigned_apk(apk)
        ks = os.path.join(self.tmp, "k.jks")
        subprocess.run(["keytool", "-genkeypair", "-keystore", ks, "-storepass", "testpass",
                        "-keypass", "testpass", "-alias", "t", "-keyalg", "RSA", "-keysize", "2048",
                        "-validity", "10", "-dname", "CN=Test Publisher, O=Lab"],
                       check=True, capture_output=True)
        subprocess.run(["jarsigner", "-keystore", ks, "-storepass", "testpass", "-keypass",
                        "testpass", "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
                        apk, "t"], check=True, capture_output=True)
        self.assertEqual(apk_check.detect_schemes(apk), ["v1"])

        res = apk_check.check_apk(apk, trusted=set(), apksigner=None)
        self.assertIsNotNone(res.sha256)
        self.assertIn("v1-only signature", " ".join(res.problems))
        self.assertIs(res.trusted, False)
        # The fingerprint must match what keytool reports for the same certificate.
        out = subprocess.run(["keytool", "-list", "-v", "-keystore", ks, "-storepass", "testpass",
                              "-alias", "t"], capture_output=True, text=True).stdout
        expected = re.search(r"SHA256:\s*([0-9A-F:]+)", out).group(1)
        self.assertEqual(res.sha256, apk_check.normalize_fp(expected))


class TrustListTests(unittest.TestCase):
    def test_normalize_and_load(self):
        self.assertEqual(apk_check.normalize_fp("AB:cd:01"), "abcd01")
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt")
        tmp.write("# comment\nAB:CD\n\n01 23\n")
        tmp.close()
        try:
            self.assertEqual(apk_check.load_trusted(tmp.name), {"abcd", "0123"})
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
