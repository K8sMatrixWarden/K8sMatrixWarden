"""
kube-bench adapter (§22), normalizes `kube-bench --json` output into a
{control_id: status} map that the CIS engine uses to resolve node/file/process controls.

Run on a node/cluster:  kube-bench run --benchmark cis-1.8 --json > kb.json
Then:                    k8smatrixwarden cis --kube-bench-json kb.json
"""
from __future__ import annotations

import json
from typing import Optional


def parse_kube_bench_json(path_or_text: str, *, is_path: bool = True) -> dict:
    """Return {test_number: status} from kube-bench JSON. Empty on any parse failure."""
    try:
        if is_path:
            with open(path_or_text, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        else:
            data = json.loads(path_or_text)
    except Exception:
        return {}

    results: dict[str, str] = {}
    controls = data.get("Controls") or ([data] if "tests" in data else [])
    for control in controls:
        for test in control.get("tests", []) or []:
            for r in test.get("results", []) or []:
                num = r.get("test_number")
                status = r.get("status")
                if num and status:
                    results[str(num)] = str(status).upper()
    return results


def maybe_load(path: Optional[str]) -> dict:
    return parse_kube_bench_json(path) if path else {}
