"""The DVKA evaluation harness: the answer key is consistent and the scanner scores as recorded."""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.path.insert(0, os.path.join(ROOT, "eval", "dvka"))

import run_eval  # noqa: E402
from k8smatrixwarden.bootstrap import build_platform  # noqa: E402

_REPORT = None


def _report():
    global _REPORT
    if _REPORT is None:
        _REPORT = run_eval.run()
    return _REPORT


def test_every_expected_rule_id_exists():
    ids = set(build_platform().registry.rules.ids())
    with open(os.path.join(ROOT, "eval", "dvka", "ground_truth.json")) as fh:
        gt = json.load(fh)
    unknown = {r for e in gt["entries"] for r in e["expect"]} - ids
    assert not unknown, f"answer key names rules that do not exist: {sorted(unknown)}"


def test_generated_files_are_in_sync_with_the_catalog():
    """build.py is deterministic: rebuilding must not change any generated file."""
    import glob
    import hashlib

    def digest():
        files = glob.glob(os.path.join(ROOT, "eval", "dvka", "manifests", "*.yaml")) + [
            os.path.join(ROOT, "eval", "dvka", n) for n in
            ("cluster_fixture.json", "cluster_fixture_hardened.json", "ground_truth.json",
             "CATALOG.md")]
        return {f: hashlib.sha256(open(f, "rb").read()).hexdigest() for f in sorted(files)}
    before = digest()
    subprocess.run([sys.executable, "eval/dvka/build.py"], cwd=ROOT, check=True,
                   capture_output=True)
    assert digest() == before, "eval/dvka is stale: run python3 eval/dvka/build.py"


def test_manifests_are_valid_yaml_objects():
    import glob

    import yaml
    docs = [d for f in glob.glob(os.path.join(ROOT, "eval", "dvka", "manifests", "*.yaml"))
            for d in yaml.safe_load_all(open(f)) if d]
    assert len(docs) > 60 and all("kind" in d and "metadata" in d for d in docs)


def test_the_scanner_detects_what_it_claims_to_cover():
    d = _report()["detection"]
    assert d["recall"] >= 0.95, d["fn"]


def test_the_only_false_positive_is_the_known_look_alike():
    fps = _report()["detection"]["fp"]
    assert [(x["rule"], x["class"]) for x in fps] == [("sec-configmap-credentials", "probe")], fps


def test_documented_gaps_stay_undetected():
    gaps = _report()["detection"]["gaps"]
    assert gaps and not [g["id"] for g in gaps if g["detected"]]


def test_runtime_events_land_in_the_documented_tier():
    rows = run_eval.run(runtime=True)["runtime"]["rows"]
    assert all(r["ok"] for r in rows), [r for r in rows if not r["ok"]]


def test_the_slide_attack_path_is_found():
    assert _report()["attack_path"]["ok"]


def test_an_exposed_workload_outranks_an_isolated_one():
    assert _report()["priority"]["ok"]
