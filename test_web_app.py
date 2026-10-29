import io
import os
import unittest

import web_app

SAMPLE = os.path.join(os.path.dirname(__file__), "samples", "signed.apk")
UNSIGNED = os.path.join(os.path.dirname(__file__), "samples", "unsigned.apk")


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


class WebAppTests(unittest.TestCase):
    def setUp(self):
        web_app.app.config["TESTING"] = True
        self.client = web_app.app.test_client()
        os.environ["TRUSTED_FILE"] = os.path.join(os.path.dirname(__file__), "trusted.txt")

    def tearDown(self):
        os.environ.pop("TRUSTED_FILE", None)

    def _upload(self, path, name=None):
        with open(path, "rb") as fh:
            data = fh.read()
        return {"apk": (io.BytesIO(data), name or os.path.basename(path))}

    def test_index_renders(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"APK signature check", r.data)

    def test_api_signed_apk_is_trusted(self):
        r = self.client.post("/api/check", data=self._upload(SAMPLE),
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["schemes"], ["v1"])
        self.assertIs(body["trusted"], True)
        self.assertEqual(len(body["sha256"]), 64)

    def test_api_unsigned_apk_reports_problem(self):
        r = self.client.post("/api/check", data=self._upload(UNSIGNED),
                             content_type="multipart/form-data")
        body = r.get_json()
        self.assertEqual(body["schemes"], [])
        self.assertTrue(any("no signature" in p for p in body["problems"]))

    def test_rejects_non_apk_filename(self):
        r = self.client.post("/api/check",
                             data={"apk": (io.BytesIO(b"hello"), "notes.txt")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_path_traversal_name_is_sanitised(self):
        r = self.client.post("/api/check",
                             data={"apk": (io.BytesIO(_read(SAMPLE)), "../../etc/x.apk")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("..", r.get_json()["path"])

    def test_html_escapes_filename(self):
        r = self.client.post("/check",
                             data={"apk": (io.BytesIO(_read(UNSIGNED)), "<script>x</script>.apk")},
                             content_type="multipart/form-data")
        self.assertNotIn(b"<script>x</script>", r.data)

    def test_missing_field(self):
        r = self.client.post("/api/check", data={}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
