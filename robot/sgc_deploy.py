#!/usr/bin/env python3
# SGC Mission Control — local deploy/red-team web backend
# Copyright © 2026 Brandon Green. All rights reserved.
# PRIVATE — Do not publish before provisional patent filed.
#
# Defensive security research only.
# Anthropic CVP Reference: b317987c-50db-4115-9219-4ece18b2db06
#
# Serves a local web UI (sgc_ui.html) and streams build / flash / red-team
# output to the browser in real time. All actions target owned hardware in a
# controlled research environment.

"""
sgc_deploy.py

Two cooperating servers in one process:

  * HTTP control plane  — stdlib http.server on localhost:8765
        GET  /                serve sgc_ui.html
        POST /build           cargo build   in ~/Projects/sgc-firmware/
        POST /flash           pyocd load (the `sgc-flash` alias) in the firmware dir
        POST /run             mock_deterministic_layer.py --mode MODE
                              MODE from JSON body {"mode": "..."} or ?mode=...
                              (dryrun | normal | redteam)

  * WebSocket stream    — `websockets` library on localhost:8766
        broadcasts each subprocess output line to every connected browser.

The two run on separate ports because the `websockets` HTTP layer only accepts
GET handshakes (it rejects POST and request bodies), while the control plane
needs real POST endpoints with JSON bodies. HTTP requests schedule the
subprocess onto the asyncio loop, which owns the WebSocket clients.
"""

import asyncio
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    from websockets.asyncio.server import serve
except ImportError:
    sys.exit(
        "The 'websockets' library (>=13) is required. Install it with:\n"
        "    python3 -m pip install 'websockets>=13'"
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HOST = "localhost"
HTTP_PORT = 8765   # control plane (GET / + POST actions)
WS_PORT = 8766     # live output stream

ROBOT_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(ROBOT_DIR, "sgc_ui.html")
MOCK_SCRIPT = os.path.join(ROBOT_DIR, "mock_deterministic_layer.py")
FIRMWARE_DIR = os.path.expanduser("~/Projects/sgc-firmware")

BUILD_CMD = ["cargo", "build"]

# Replicates the `sgc-flash` shell alias (a shell alias is not visible to a
# subprocess), run from the firmware directory:
#   pyocd load -t lpc55s69 -f 1000000 -O connect_mode=attach --format elf \
#       target/thumbv8m.main-none-eabihf/debug/sgc
FLASH_CMD = [
    os.path.join(FIRMWARE_DIR, ".recovery-venv", "bin", "pyocd"),
    "load",
    "-t", "lpc55s69",
    "-f", "1000000",
    "-O", "connect_mode=attach",
    "--format", "elf",
    "target/thumbv8m.main-none-eabihf/debug/sgc",
]

VALID_MODES = ("dryrun", "normal", "redteam")


# ---------------------------------------------------------------------------
# Live state (owned by the asyncio loop)
# ---------------------------------------------------------------------------

CLIENTS = set()          # connected WebSocket connections
TASKS = set()            # keep background tasks referenced so they aren't GC'd
BUSY = False             # only one command runs at a time
LOOP = None              # asyncio loop, set in amain(); used from HTTP threads


async def broadcast(obj):
    """Send a JSON message to every connected WebSocket client."""
    message = json.dumps(obj)
    for connection in list(CLIENTS):
        try:
            await connection.send(message)
        except Exception:
            CLIENTS.discard(connection)


async def run_command(label, argv, cwd):
    """Run a subprocess and stream its merged stdout/stderr to all clients."""
    global BUSY
    BUSY = True
    await broadcast({"type": "start", "label": label, "cmd": " ".join(argv)})
    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError as exc:
            await broadcast({"type": "line", "text": "[error] {}".format(exc)})
            await broadcast({"type": "exit", "label": label, "code": 127})
            return

        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            await broadcast({"type": "line", "text": text})

        code = await proc.wait()
        await broadcast({"type": "exit", "label": label, "code": code})
    finally:
        BUSY = False


async def try_start(label, argv, cwd):
    """Accept a command if idle. Runs on the loop thread, so BUSY is race-free."""
    global BUSY
    if BUSY:
        return False
    BUSY = True
    task = asyncio.create_task(run_command(label, argv, cwd))
    TASKS.add(task)
    task.add_done_callback(TASKS.discard)
    return True


# ---------------------------------------------------------------------------
# HTTP control plane (stdlib, runs in a background thread)
# ---------------------------------------------------------------------------

class ControlHandler(BaseHTTPRequestHandler):
    server_version = "SGCMissionControl/1.0"

    def _send(self, code, text, ctype="text/plain"):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html", "/sgc_ui.html"):
            try:
                with open(HTML_PATH, encoding="utf-8") as fh:
                    html = fh.read()
            except FileNotFoundError:
                return self._send(404, "sgc_ui.html not found next to sgc_deploy.py")
            return self._send(200, html, "text/html")
        return self._send(404, "not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/build":
            return self._action("build", BUILD_CMD, FIRMWARE_DIR)
        if path == "/flash":
            return self._action("flash", FLASH_CMD, FIRMWARE_DIR)
        if path == "/run":
            mode = self._mode()
            if mode not in VALID_MODES:
                return self._send(400, "mode must be one of {}".format(VALID_MODES))
            argv = [sys.executable, "-u", MOCK_SCRIPT, "--mode", mode]
            return self._action("run:{}".format(mode), argv, ROBOT_DIR)
        return self._send(404, "not found")

    def _mode(self):
        """Resolve run mode: JSON body {"mode": ...} first, then ?mode=, else dryrun."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            raw = self.rfile.read(length)
            try:
                mode = json.loads(raw).get("mode")
                if mode:
                    return mode
            except (ValueError, AttributeError):
                pass
        query = parse_qs(urlparse(self.path).query)
        return query.get("mode", ["dryrun"])[0]

    def _action(self, label, argv, cwd):
        if LOOP is None:
            return self._send(503, "stream not ready")
        future = asyncio.run_coroutine_threadsafe(try_start(label, argv, cwd), LOOP)
        try:
            accepted = future.result(timeout=5)
        except Exception as exc:  # noqa: BLE001 — surface scheduling failures to the client
            return self._send(500, "could not start: {}".format(exc))
        if not accepted:
            return self._send(409, "another command is already running")
        return self._send(
            202, json.dumps({"status": "started", "label": label}), "application/json"
        )

    def log_message(self, fmt, *args):
        pass  # quiet; output goes over the WebSocket


# ---------------------------------------------------------------------------
# WebSocket stream
# ---------------------------------------------------------------------------

async def ws_handler(connection):
    """Register a client and keep the connection open to receive broadcasts."""
    CLIENTS.add(connection)
    try:
        await connection.send(json.dumps({
            "type": "line",
            "text": "[ui] connected — SGC mission control ready",
        }))
        async for _ in connection:
            pass  # inbound messages are unused; control flows over HTTP
    except Exception:
        pass
    finally:
        CLIENTS.discard(connection)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def amain():
    global LOOP
    LOOP = asyncio.get_running_loop()

    httpd = ThreadingHTTPServer((HOST, HTTP_PORT), ControlHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    async with serve(ws_handler, HOST, WS_PORT):
        print("SGC Mission Control")
        print("  UI:        http://{}:{}/".format(HOST, HTTP_PORT))
        print("  Stream:    ws://{}:{}/".format(HOST, WS_PORT))
        print("  Firmware:  {}".format(FIRMWARE_DIR))
        print("  Mock:      {}".format(MOCK_SCRIPT))
        print("  Ctrl-C to stop.")
        try:
            await asyncio.Future()  # run forever
        finally:
            httpd.shutdown()


def main():
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
