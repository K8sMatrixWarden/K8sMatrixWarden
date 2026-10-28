"""
One cluster's pre-scoping history must not classify another cluster's findings.

Timeline keys are stored `scope#finding`, and `scope_key_of` makes the scope
`cluster@scope`, so two clusters keep separate histories. Entries written before
scoping existed have no prefix, and `raw_timeline(scope=...)` deliberately handed those
to EVERY scoped view so an upgraded store did not lose the history it already had.

That is right for a store holding one cluster. It is wrong the moment a second appears.
Kubernetes Goat deploys the same namespaces and the same workload names everywhere, and
`posture.finding_key()` is `rule|kind|name|namespace` with no cluster in it -- so a local
finding and an EKS finding for the same rule on the same workload share a key exactly.
An unattributable legacy entry then answers "have we seen this before?" for a cluster it
was never observed on, turning a genuinely NEW finding into `regressed` (when the legacy
entry carries a resolved_at) or silently dropping it from `new`.

A measured store on this workstation held 1164 unprefixed entries, 949 of which were
visible inside the EKS scope's view.

The resolve path (report_store.py, `_entry_scope(k) != scope: continue`) was already
strict. Only the read path was lenient. This closes that asymmetry: legacy entries are
shared only while the store cannot be holding more than one cluster.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.report_store import ReportStore

LOCAL = "docker-desktop@cluster-wide"
EKS = "arn:aws:eks:us-east-1:1234:cluster/goat@cluster-wide"
SHARED = "workload-privileged-container|Deployment|system-monitor-deployment|default"


def _store(entries):
    d = tempfile.mkdtemp()
    s = ReportStore(d)
    import json
    with open(s._timeline_path(), "w", encoding="utf-8") as fh:
        json.dump(entries, fh)
    return s


def test_legacy_entries_still_shared_when_only_one_scope_exists():
    """The upgrade case this leniency exists for. It must keep working."""
    s = _store({SHARED: {"first_seen": "2026-01-01T00:00:00Z"},
                f"{LOCAL}#other": {"first_seen": "2026-01-02T00:00:00Z"}})
    assert SHARED in s.raw_timeline(scope=LOCAL), (
        "an upgraded single-cluster store lost the history it already had")


def test_legacy_entries_are_withheld_once_a_second_cluster_appears():
    """Two scopes in one store: an unprefixed entry cannot be attributed to either, so it
    must answer for neither."""
    s = _store({
        SHARED: {"first_seen": "2026-01-01T00:00:00Z",
                 "resolved_at": "2026-02-01T00:00:00Z"},
        f"{LOCAL}#a": {"first_seen": "2026-01-02T00:00:00Z"},
        f"{EKS}#b": {"first_seen": "2026-01-03T00:00:00Z"},
    })
    for scope in (LOCAL, EKS):
        view = s.raw_timeline(scope=scope)
        assert SHARED not in view, (
            f"a legacy entry answered for {scope}; a new finding there would be "
            f"reported as regressed on history from another cluster")
    # Each scope still sees its own.
    assert "a" in s.raw_timeline(scope=LOCAL)
    assert "b" in s.raw_timeline(scope=EKS)


def test_a_scope_never_sees_another_scopes_entries():
    s = _store({f"{LOCAL}#{SHARED}": {"first_seen": "2026-01-01T00:00:00Z"},
                f"{EKS}#{SHARED}": {"first_seen": "2026-03-01T00:00:00Z"}})
    assert s.raw_timeline(scope=LOCAL)[SHARED]["first_seen"].startswith("2026-01")
    assert s.raw_timeline(scope=EKS)[SHARED]["first_seen"].startswith("2026-03")


def test_unscoped_call_still_returns_the_whole_index():
    """`raw_timeline()` with no scope is the raw store view; it is not a scoped answer and
    must not be filtered."""
    s = _store({SHARED: {"first_seen": "x"}, f"{LOCAL}#a": {"first_seen": "y"},
                f"{EKS}#b": {"first_seen": "z"}})
    assert len(s.raw_timeline()) == 3


if __name__ == "__main__":
    import traceback
    bad = 0
    for k, fn in sorted(globals().items()):
        if k.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"pass {k}")
            except Exception:
                bad += 1
                print(f"FAIL {k}")
                traceback.print_exc()
    print("ok" if not bad else f"{bad} failed")


# --------------------------------------------------------------------------- #
# The surfaces that SHOW a timeline must show one cluster's
# --------------------------------------------------------------------------- #

def test_posture_scope_names_the_scans_own_cluster():
    from k8smatrixwarden.core.posture import posture_scope

    class R:
        def __init__(s, i, c):
            s.scan_id, s.cluster, s.scope = i, c, "cluster-wide"

    class S:
        rows = [R("newest", "eks"), R("older", "docker-desktop")]
        def list(s): return s.rows
        @staticmethod
        def scope_key_of(c, sc): return f"{c}@{sc}"

    s = S()
    assert posture_scope(s, "older") == "docker-desktop@cluster-wide"
    assert posture_scope(s, "newest") == "eks@cluster-wide"
    assert posture_scope(s) == "eks@cluster-wide", "no id means the newest scan"
    assert posture_scope(s, "gone") == "eks@cluster-wide", "unknown id falls back"


def test_dashboard_trend_and_timeline_are_narrowed_to_one_cluster():
    """A risk trend that interleaves two clusters' scans is not a trend, and an age
    timeline blended across them describes neither."""
    import inspect

    from k8smatrixwarden.web.app import WebApp
    src = inspect.getsource(WebApp._dashboard_data)
    assert "scope_key_of(chosen.cluster, chosen.scope)" in src, (
        "the dashboard no longer derives the selected report's scope")
    assert "self.store.timeline(scope=scope)" in src, (
        "the dashboard age timeline is not scoped to the selected cluster")
    assert "scope_key_of(r.cluster, r.scope) == scope" in src, (
        "trend/history still span every cluster in the store")


def test_the_timeline_endpoint_is_scoped():
    import inspect

    from k8smatrixwarden.web.app import WebApp
    assert "self.store.timeline()" not in inspect.getsource(WebApp.route), (
        "/api/timeline still returns a whole-store, cross-cluster timeline")
    assert "scope_key_of" in inspect.getsource(WebApp._api_timeline)


