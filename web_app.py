#!/usr/bin/env python3
"""Web front end for the APK signature checker.

Upload an .apk and get the signing schemes, signer, SHA-256 fingerprint and
trusted-list result, as a page or as JSON.

Device triage (rat_detect.py) is deliberately NOT exposed here. It drives a
phone over ADB, and a public website must not be able to reach that.

Run locally:
  python3 web_app.py                       # http://127.0.0.1:5000
  TRUSTED_FILE=trusted.txt python3 web_app.py

Do not bind to 0.0.0.0 on a shared network without putting authentication in
front of it. Uploaded APKs are checked and deleted; they are not kept.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import asdict

from flask import Flask, abort, jsonify, render_template_string, request
from werkzeug.utils import secure_filename

import apk_check

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "200"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APK signature check</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#111}
 code{word-break:break-all}
 .card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
 .bad{color:#b00020;font-weight:600}
 .ok{color:#136f2a;font-weight:600}
 .warn{color:#8a5a00}
 button{padding:.5rem 1rem}
</style></head><body>
<h1>APK signature check</h1>
<p>Upload an APK to see how it is signed. Files are checked and then deleted.</p>
<form method="post" action="/check" enctype="multipart/form-data">
  <input type="file" name="apk" accept=".apk" required>
  <button type="submit">Check</button>
</form>
{% if result %}
  <div class="card">
    <h2>{{ result.name }}</h2>
    <p>Schemes: <strong>{{ result.schemes|join(', ') or 'none' }}</strong></p>
    <p>Signer: {{ result.signer_subject or 'unknown' }}</p>
    <p>SHA-256: <code>{{ result.sha256 or 'unknown' }}</code></p>
    {% if result.trusted is not none %}
      <p>Trusted: {% if result.trusted %}<span class="ok">yes</span>{% else %}<span class="bad">NO</span>{% endif %}</p>
    {% endif %}
    {% for p in result.problems %}<p class="warn">! {{ p }}</p>{% endfor %}
  </div>
{% endif %}
{% if error %}<p class="bad">{{ error }}</p>{% endif %}
</body></html>"""


def _trusted() -> set[str] | None:
    path = os.environ.get("TRUSTED_FILE")
    return apk_check.load_trusted(path) if path else None


def _check_upload(storage):
    """Save the upload to a temp dir, check it, delete it. Returns an ApkResult."""
    name = secure_filename(storage.filename or "")
    if not name or not name.lower().endswith(".apk"):
        abort(400, description="Upload a file ending in .apk")
    tmp = tempfile.mkdtemp(prefix="apkcheck-")
    try:
        path = os.path.join(tmp, name)
        storage.save(path)
        result = apk_check.check_apk(path, _trusted(), shutil.which("apksigner"))
        result.path = name  # do not expose the temp path
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.get("/")
def index():
    return render_template_string(PAGE, result=None, error=None)


@app.post("/check")
def check_page():
    if "apk" not in request.files:
        return render_template_string(PAGE, result=None, error="No file uploaded."), 400
    result = _check_upload(request.files["apk"])
    data = asdict(result)
    data["name"] = result.path
    return render_template_string(PAGE, result=data, error=None)


@app.post("/api/check")
def check_api():
    if "apk" not in request.files:
        return jsonify(error="send the APK as multipart field 'apk'"), 400
    result = _check_upload(request.files["apk"])
    return jsonify(asdict(result))


@app.errorhandler(413)
def too_large(_):
    return jsonify(error=f"file larger than {MAX_UPLOAD_MB} MB"), 413


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port)
