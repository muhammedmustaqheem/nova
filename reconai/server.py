"""
ReconAI Standard HTTP & REST Server
Serves static frontend assets from frontend/ and exposes REST API endpoints:
  - GET  /api/forensics/cases
  - GET  /api/forensics/cases/:id
  - POST /api/forensics/upload
  - POST /api/forensics/recover
  - GET  /api/forensics/files
  - GET  /api/forensics/files/:id
  - GET  /api/forensics/files/:id/download
  - GET  /api/forensics/files/:id/hex
  - POST /api/forensics/copilot
  - GET  /api/forensics/report
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
MAX_UPLOAD_BYTES = 4 * 1024 ** 3


class ReconHandler(BaseHTTPRequestHandler):
    server_version = "ReconAI/1.4"

    def _send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, mime: str, filename: str = None):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
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

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

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
        if route == ["files"]:
            case_id = query.get("case", [""])[0]
            cat = query.get("category", ["ALL"])[0]
            stat = query.get("status", ["ALL"])[0]
            src = query.get("source", ["ALL"])[0]
            return self._send_json(api.api_get_files(case_id, cat, stat, src))
        if len(route) == 4 and route[0] == "files" and route[3] == "hex":
            length = int(query.get("length", ["512"])[0])
            return self._send_json(api.api_hex_dump(route[1], route[2], length))
        if len(route) == 4 and route[0] == "files" and route[3] == "download":
            try:
                data, filename, mime = api.api_download_file(route[1], route[2])
            except FileNotFoundError as e:
                return self._error(str(e), HTTPStatus.NOT_FOUND)
            return self._send_bytes(data, mime, filename)
        if len(route) == 2 and route[0] == "report":
            fmt = query.get("format", ["pdf"])[0]
            rep = api.api_get_report(route[1], fmt)
            if rep["status"] != "SUCCESS":
                return self._error(rep["message"], HTTPStatus.NOT_FOUND)
            if fmt == "pdf":
                return self._send_bytes(rep["pdf_bytes"], "application/pdf", f"ReconAI_Report_{route[1]}.pdf")
            return self._send_bytes(rep["report_json"].encode("utf-8"), "application/json", f"ReconAI_Report_{route[1]}.json")

        return self._error("API route not found", HTTPStatus.NOT_FOUND)

    def do_POST(self):
        url = urlparse(self.path)
        parts = [unquote(p) for p in url.path.strip("/").split("/") if p]
        if parts[:2] != ["api", "forensics"]:
            return self._error("Invalid API endpoint", HTTPStatus.NOT_FOUND)
        route = parts[2:]

        if route == ["upload"]:
            content_type = self.headers.get("Content-Type", "")
            filename = unquote(self.headers.get("X-Filename") or "evidence.raw")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_UPLOAD_BYTES:
                return self._error("File exceeds max upload limit (4GB)")
            file_bytes = self.rfile.read(length) if length else b""
            return self._send_json(api.api_upload_image(file_bytes, filename))

        if route == ["recover"]:
            body = self._read_json()
            image_path = body.get("image_path") or os.path.join("data", "demo_evidence.raw")
            case_id = body.get("case_id")
            examiner = body.get("examiner_name") or "Agent V. Vance"
            scope = body.get("scope") or "Complete Forensic Triage"
            return self._send_json(api.api_recover_image(image_path, case_id, examiner, scope))

        if route == ["copilot"]:
            body = self._read_json()
            case_id = body.get("case_id") or ""
            prompt = body.get("prompt") or body.get("query") or ""
            return self._send_json(api.api_copilot_ask(case_id, prompt))

        return self._error("Unsupported POST route", HTTPStatus.NOT_FOUND)

    def _serve_static(self, path: str):
        if path in ("/", "", "/index.html"):
            target_path = os.path.join(FRONTEND_DIR, "index.html")
        else:
            rel = path.lstrip("/")
            target_path = os.path.join(FRONTEND_DIR, rel)

        if not os.path.isfile(target_path):
            target_path = os.path.join(FRONTEND_DIR, "index.html")

        mime, _ = mimetypes.guess_type(target_path)
        mime = mime or "text/html"

        try:
            with open(target_path, "rb") as f:
                content = f.read()
            self._send_bytes(content, mime)
        except OSError:
            self._error("Asset file not found", HTTPStatus.NOT_FOUND)


def main():
    parser = argparse.ArgumentParser(description="ReconAI Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host IP")
    parser.add_argument("--port", type=int, default=8700, help="Port")
    args = parser.parse_args()

    server_address = (args.host, args.port)
    httpd = ThreadingHTTPServer(server_address, ReconHandler)
    print(f"ReconAI Command Center Server running on http://{args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()


if __name__ == "__main__":
    main()
