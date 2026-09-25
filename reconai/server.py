"""
ReconAI HTTP server for the Forensic Command Center frontend.
Standard-library only: exposes the reconai.api functions as the REST routes they document,
and serves frontend/ from the same origin.

    ./venv/bin/python -m reconai.server            # http://127.0.0.1:8600
    ./venv/bin/python -m reconai.server --port 9000
"""

import argparse
import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from reconai import api

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
UPLOAD_DIR = os.path.join(BASE_DIR, "data", "uploads")
DEMO_RAW_PATH = os.path.join(BASE_DIR, "data", "demo_evidence.raw")
DEMO_GT_PATH = os.path.join(BASE_DIR, "data", "ground_truth.json")
MAX_UPLOAD_BYTES = 4 * 1024 ** 3
EVIDENCE_EXTENSIONS = {".raw", ".dd", ".img", ".bin", ".mem", ".dmp"}


class ReconHandler(BaseHTTPRequestHandler):
    server_version = "ReconAI/1.4"

    # ---------- plumbing ----------
    def _send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, mime: str, filename: str = None):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(filename)}"')
        self.end_headers()
        self.wfile.write(data)

    def _error(self, message: str, status=HTTPStatus.BAD_REQUEST):
        self._send_json({"status": "ERROR", "message": message}, status)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def log_message(self, fmt, *args):
        if "/api/" in (args[0] if args else ""):
            super().log_message(fmt, *args)

    # ---------- routes ----------
    def do_GET(self):
        url = urlparse(self.path)
        parts = [unquote(p) for p in url.path.strip("/").split("/") if p]
        query = parse_qs(url.query)

        if parts[:2] != ["api", "forensics"]:
            return self._serve_static(url.path)
        route = parts[2:]

        if route == ["cases"]:
            return self._send_json(api.api_list_cases())
        if len(route) == 2 and route[0] == "cases":
            view = api.api_get_case_view(route[1])
            return self._send_json(view, HTTPStatus.OK if view["status"] == "SUCCESS" else HTTPStatus.NOT_FOUND)
        if len(route) == 4 and route[0] == "files" and route[3] == "hex":
            length = int(query.get("length", ["256"])[0])
            return self._send_json(api.api_hex_dump(route[1], route[2], length))
        if len(route) == 4 and route[0] == "files" and route[3] == "download":
            try:
                data, filename, mime = api.api_download_file(route[1], route[2])
            except FileNotFoundError as e:
                return self._error(str(e), HTTPStatus.NOT_FOUND)
            # Repaired artifacts carry their own name; never let them download under the original's name
            filename = api._find_item(route[1], route[2]).get("derived_filename") or filename
            return self._send_bytes(data, mime, filename)
        if len(route) == 2 and route[0] == "report":
            fmt = query.get("format", ["pdf"])[0]
            rep = api.api_get_report(route[1], fmt)
            if rep["status"] != "SUCCESS":
                return self._error(rep["message"], HTTPStatus.NOT_FOUND)
            if fmt == "pdf":
                return self._send_bytes(rep["pdf_bytes"], "application/pdf", f"ReconAI_Report_{route[1]}.pdf")
            return self._send_bytes(rep["report_json"].encode("utf-8"), "application/json", f"ReconAI_Report_{route[1]}.json")
        if route == ["audit"] and query.get("case"):
            view = api.api_get_case_view(query["case"][0])
            return self._send_bytes(json.dumps(view.get("custody", {}).get("audit", {}), indent=2, default=str).encode(),
                                    "application/json", f"ReconAI_Audit_{query['case'][0]}.json")
        return self._error("Unknown route.", HTTPStatus.NOT_FOUND)

    def do_POST(self):
        route = [unquote(p) for p in urlparse(self.path).path.strip("/").split("/") if p][2:]
        try:
            if route == ["upload"]:
                return self._upload()
            if route == ["recover"]:
                return self._recover(self._read_json())
            if route == ["copilot"]:
                body = self._read_json()
                return self._send_json(api.api_copilot(body.get("case_id", ""), body.get("query", "")))
            if route == ["demo"]:
                from scripts.make_test_image import generate_evidence_disk
                generate_evidence_disk(DEMO_RAW_PATH, DEMO_GT_PATH)
                return self._send_json({"status": "SUCCESS", "message": "Fresh synthetic test disk generated."})
        except json.JSONDecodeError:
            return self._error("Request body is not valid JSON.")
        except Exception as e:  # surface engine failures to the UI instead of dropping the connection
            return self._error(f"{type(e).__name__}: {e}", HTTPStatus.INTERNAL_SERVER_ERROR)
        return self._error("Unknown route.", HTTPStatus.NOT_FOUND)

    def _upload(self):
        filename = os.path.basename(unquote(self.headers.get("X-Filename", "")))
        ext = os.path.splitext(filename)[1].lower()
        if not filename or ext not in EVIDENCE_EXTENSIONS:
            return self._error(f"Upload a disk image ({', '.join(sorted(EVIDENCE_EXTENSIONS))}).")
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 < length <= MAX_UPLOAD_BYTES:
            return self._error("Image is empty or larger than 4 GB.")
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        dest = os.path.join(UPLOAD_DIR, filename)
        remaining = length
        with open(dest, "wb") as f:
            while remaining:
                chunk = self.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
        hash_info = api.api_analyze_image(dest)["analysis"]
        return self._send_json({"status": "SUCCESS", "filename": filename, "hash_metadata": hash_info})

    def _recover(self, body):
        examiner = (body.get("examiner") or "").strip()
        if not examiner:
            return self._error("Examiner name is required for chain of custody.")
        if body.get("source") == "demo":
            if not os.path.exists(DEMO_RAW_PATH):
                from scripts.make_test_image import generate_evidence_disk
                generate_evidence_disk(DEMO_RAW_PATH, DEMO_GT_PATH)
            image_path = DEMO_RAW_PATH
        else:
            image_path = os.path.join(UPLOAD_DIR, os.path.basename(body.get("filename") or ""))
            if not os.path.isfile(image_path):
                return self._error("Uploaded image not found. Upload it again.", HTTPStatus.NOT_FOUND)
        result = api.api_recover_image(image_path, case_id=(body.get("case_id") or "").strip() or None,
                                       examiner_name=examiner)
        return self._send_json(api.api_get_case_view(result["case_id"]))

    def _serve_static(self, path: str):
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        full = os.path.realpath(os.path.join(FRONTEND_DIR, rel))
        if not full.startswith(os.path.realpath(FRONTEND_DIR) + os.sep) or not os.path.isfile(full):
            return self._error("Not found.", HTTPStatus.NOT_FOUND)
        mime = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            self._send_bytes(f.read(), mime)


def main():
    parser = argparse.ArgumentParser(description="ReconAI Forensic Command Center server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8600)
    args = parser.parse_args()
    os.chdir(BASE_DIR)  # api.py writes recovery/ relative to the project root
    httpd = ThreadingHTTPServer((args.host, args.port), ReconHandler)
    print(f"ReconAI Command Center → http://{args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
