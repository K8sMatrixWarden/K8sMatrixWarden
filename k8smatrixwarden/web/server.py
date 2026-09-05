"""
Thin stdlib `http.server` shell over WebApp (web/app.py).

`serve()` builds the platform once, wraps a WebApp, and dispatches every request to
`WebApp.route(...)`. No third-party web framework, the same zero-dependency stance the rest
of the tool takes, so `k8smatrixwarden web` runs on a bare Python install.
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from ..bootstrap import build_platform
from ..core.report_store import DEFAULT_DIR
from .app import WebApp

_MAX_BODY = 2 * 1024 * 1024  # 2 MiB cap on POST bodies


def make_handler(app: WebApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "k8smatrixwarden-web"
        protocol_version = "HTTP/1.1"

        def _dispatch(self, method: str) -> None:
            path, _, query = self.path.partition("?")
            length = min(int(self.headers.get("Content-Length", 0) or 0), _MAX_BODY)
            body = self.rfile.read(length) if length else b""
            resp = app.route(method, path, query, body)
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(resp.body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(resp.body)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_HEAD(self):
            self._dispatch("GET")

        def log_message(self, fmt, *args):  # keep the console quiet unless it's an error
            if not str(args[1] if len(args) > 1 else "").startswith("2"):
                super().log_message(fmt, *args)

    return Handler


def is_loopback(host: str) -> bool:
    """True only when this bind address can be reached from this machine alone.

    Conservative by construction: anything unrecognised, a hostname, or `""`/`0.0.0.0`
    (which bind every interface), is treated as remote-reachable."""
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


#: The one background dashboard this process may run, and the lock guarding it. A second
#: server on the same port would either fail to bind or (on Windows, which permits it)
#: shadow the first, so starting is idempotent by construction rather than by hope.
_BACKGROUND: dict = {}
_BACKGROUND_LOCK = threading.Lock()


def background_status() -> dict:
    """What the in-process dashboard is doing, if anything. Never raises."""
    with _BACKGROUND_LOCK:
        if not _BACKGROUND:
            return {"running": False}
        thread = _BACKGROUND.get("thread")
        alive = bool(thread and thread.is_alive())
        if not alive:
            # The serving thread died (a bind failure surfaced late, or shutdown raced).
            # Report it as not running rather than advertising a URL nothing answers.
            return {"running": False, "last_error": _BACKGROUND.get("error"),
                    "host": _BACKGROUND.get("host"), "port": _BACKGROUND.get("port")}
        started = _BACKGROUND.get("started_at", 0.0)
        return {"running": True, "host": _BACKGROUND["host"],
                "port": _BACKGROUND["port"], "url": _BACKGROUND["url"],
                "reports_dir": _BACKGROUND.get("reports_dir"),
                "scanning_enabled": _BACKGROUND.get("allow_scan"),
                "uptime_seconds": round(time.time() - started, 1) if started else None}


def start_background(host: str = "127.0.0.1", port: int = 8080,
                     reports_dir: str = DEFAULT_DIR,
                     config_path: Optional[str] = None, allow_scan: bool = True,
                     allow_remote_kubeconfig: bool = False) -> dict:
    """Start the dashboard on a daemon thread and return immediately.

    The CLI's `serve()` blocks on `serve_forever()`, which is right for a terminal and
    useless to a caller that must answer an RPC. This runs the SAME `WebApp` and the same
    `ThreadingHTTPServer` on a background thread, so there is one dashboard implementation
    and the MCP tool cannot drift from `k8smatrixwarden web`.

    Idempotent: starting when one is already running returns the running one rather than
    binding a second socket. On Windows two processes CAN bind the same port, and the
    older one silently wins every connection, so "already running" has to be an answer
    rather than a race.

    A bind failure is returned as an error, not raised: the caller is an RPC handler and
    "port in use" is information, not a crash.
    """
    with _BACKGROUND_LOCK:
        thread = _BACKGROUND.get("thread")
        if thread and thread.is_alive():
            return {"status": "already-running", "host": _BACKGROUND["host"],
                    "port": _BACKGROUND["port"], "url": _BACKGROUND["url"],
                    "message": ("a dashboard is already running in this process; stop it "
                                "first to change host, port or options")}
        platform = build_platform(config_path)
        local = is_loopback(host)
        app = WebApp(platform, reports_dir=reports_dir, allow_scan=allow_scan,
                     allow_client_kubeconfig=local or allow_remote_kubeconfig)
        try:
            httpd = ThreadingHTTPServer((host, port), make_handler(app))
        except OSError as exc:
            return {"status": "error",
                    "error": f"could not bind {host}:{port}: {exc}"}
        httpd.daemon_threads = True
        serving = threading.Thread(target=httpd.serve_forever, name="kmw-dashboard",
                                   daemon=True)
        serving.start()
        url = f"http://{host}:{port}/"
        _BACKGROUND.update({"httpd": httpd, "thread": serving, "host": host,
                            "port": port, "url": url, "reports_dir": reports_dir,
                            "allow_scan": allow_scan, "started_at": time.time(),
                            "error": None})
        return {"status": "started", "host": host, "port": port, "url": url,
                "loopback_only": local, "scanning_enabled": allow_scan}


def stop_background() -> dict:
    """Shut the background dashboard down. Safe to call when none is running."""
    with _BACKGROUND_LOCK:
        httpd = _BACKGROUND.get("httpd")
        thread = _BACKGROUND.get("thread")
        if not httpd or not (thread and thread.is_alive()):
            _BACKGROUND.clear()
            return {"status": "not-running"}
        host, port = _BACKGROUND.get("host"), _BACKGROUND.get("port")
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        _BACKGROUND.clear()
        return {"status": "stopped", "host": host, "port": port}


def serve(host: str = "127.0.0.1", port: int = 8080,
          reports_dir: str = DEFAULT_DIR,
          config_path: Optional[str] = None, allow_scan: bool = True,
          open_browser: bool = False,
          allow_remote_kubeconfig: bool = False) -> None:
    platform = build_platform(config_path)
    # A kubeconfig in a request body is arbitrary code: loading it runs its credential
    # plugin as this process's user. On loopback the only caller is the operator, so the
    # browser file-picker is just a convenience. On any routable address it is remote code
    # execution, so it is refused unless explicitly re-enabled.
    local = is_loopback(host)
    allow_client_kubeconfig = local or allow_remote_kubeconfig
    app = WebApp(platform, reports_dir=reports_dir, allow_scan=allow_scan,
                 allow_client_kubeconfig=allow_client_kubeconfig)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    url = f"http://{host}:{port}/"
    print(f"K8sMatrixWarden dashboard -> {url}")
    print(f"    reports dir: {reports_dir}   ·   scanning: "
          f"{'enabled' if allow_scan else 'disabled'}   ·   Ctrl-C to stop")
    if not local:
        print(f"    WARNING: bound to {host}, reachable beyond this machine, and the "
              f"dashboard has NO authentication.\n"
              f"             Anyone who can reach it can read every saved report"
              + ("" if not allow_scan else " and start scans") + ".")
        if allow_client_kubeconfig:
            print("    WARNING: --allow-remote-kubeconfig is on. A kubeconfig in a request "
                  "body executes its\n"
                  "             credential plugin as this user, that is remote code "
                  "execution unless you have\n"
                  "             put your own authentication in front of this port.")
        else:
            print("    Client-supplied kubeconfigs are refused (credential plugins would "
                  "execute here).\n"
                  "             Scan from the CLI on this host, or use "
                  "--allow-remote-kubeconfig behind your own auth.")
    if open_browser:
        threading.Timer(0.5, lambda: _open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\ndashboard stopped")
    finally:
        httpd.server_close()


def _open(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass
