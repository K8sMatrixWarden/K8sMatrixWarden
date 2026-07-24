"""Test package init.

Scans now persist by default (CLI `scan`, MCP `run_scan`/`intelligent_scan`) so they show
up in the web dashboard. To keep the test session from writing those default-saved scans
into the real per-user store (`~/.k8smatrixwarden/reports`), point the shared store at a
throwaway temp directory for the whole session.

This must run before any `k8smatrixwarden` import, because `report_store.DEFAULT_DIR` is
resolved once at import time. It does, `run_tests.py` imports `tests.<module>`, which
loads this package `__init__` first, and pytest loads it before collecting the test
modules that import the package.
"""
import os as _os
import tempfile as _tempfile

_os.environ.setdefault(
    "K8SMATRIXWARDEN_REPORTS_DIR",
    _os.path.join(_tempfile.gettempdir(), "k8smatrixwarden-test-reports"),
)
