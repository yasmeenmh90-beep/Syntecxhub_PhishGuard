"""Local web inspector (standard library only), bound to 127.0.0.1.

    GET  /               the inspector page
    GET  /api/kb         signals, samples and rule-base stats
    POST /api/inspect    {"text": str, "overrides": {signal: cf | null}} -> full analysis
    POST /api/report     {"text", "overrides", "format": "md" | "json" | "txt"} -> report text
"""
from __future__ import annotations

import json
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from .inspect import inspect, load_samples
from .knowledge import KnowledgeBase
from .report import to_json, to_markdown, to_text

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
MAX_BODY = 256 * 1024


def _overrides(kb: KnowledgeBase, raw) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("overrides must be an object")
    clean = {}
    for key, value in raw.items():
        if key not in kb.questions:
            raise ValueError(f"unknown signal {key!r}")
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not -1 <= value <= 1):
            raise ValueError(f"invalid value for {key!r}")
        clean[key] = value
    return clean


def _text(body: dict) -> str:
    text = body.get("text", "")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("paste a message to inspect")
    return text


def kb_payload(kb: KnowledgeBase) -> dict:
    return {
        "name": kb.name, "version": kb.version,
        "stats": {"rules": len(kb.rules), "signals": len(kb.questions), "depth": max(kb.level(r) for r in kb.rules)},
        "threats": list(kb.verdict.get("threats", [])),
        "context": list(kb.verdict.get("context", [])),
        "signals": [{"id": q.id, "text": q.text, "category": q.category} for q in kb.questions.values()],
        "samples": {k: {"title": v["title"], "kind": v["kind"], "text": v["text"]} for k, v in load_samples().items()},
    }


def inspect_payload(kb: KnowledgeBase, text: str, overrides: dict) -> dict:
    out = inspect(kb, text, overrides)
    result = out["result"]
    data = result.to_dict()
    return {
        "extraction": out["extraction"].to_dict(),
        "facts": out["facts"],
        "verdict": out["verdict"],
        "recommendations": data["recommendations"],
        "conclusions": data["conclusions"],
        "trace": data["trace"],
        "graph": out["graph"],
        "whatif": out["whatif"],
    }


def make_handler(kb: KnowledgeBase):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PhishGuard"

        def log_message(self, *args) -> None:
            pass

        def _send(self, status, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload, status=200) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self) -> None:
            if self.path in ("/", "/index.html"):
                self._send(200, (WEB_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif self.path == "/api/kb":
                self._json(kb_payload(kb))
            else:
                self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._json({"error": "message too long"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("expected a JSON object")
                if self.path == "/api/inspect":
                    self._json(inspect_payload(kb, _text(body), _overrides(kb, body.get("overrides"))))
                elif self.path == "/api/report":
                    fmt = str(body.get("format", "md"))
                    render = {"md": to_markdown, "json": to_json, "txt": to_text}.get(fmt)
                    if render is None:
                        raise ValueError("format must be md, json or txt")
                    out = inspect(kb, _text(body), _overrides(kb, body.get("overrides")))
                    self._json({"filename": f"phishguard_report.{fmt}", "content": render(out["result"])})
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except (ValueError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    return Handler


def create_server(kb: Optional[KnowledgeBase] = None, port: int = 8770) -> ThreadingHTTPServer:
    kb = kb or KnowledgeBase.load()
    handler = make_handler(kb)
    for candidate in [port] + list(range(port + 1, port + 20)) + [0]:
        try:
            return ThreadingHTTPServer(("127.0.0.1", candidate), handler)
        except OSError:
            continue
    raise OSError("no free port available")


def serve(port: int = 8770, open_browser: bool = True) -> None:
    server = create_server(port=port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"PhishGuard running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
