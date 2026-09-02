"""
Scan id uniqueness and ordering, and the report-store integrity that rests on them.

The scan id is not decoration. `generated_at` has second resolution, so the report store
breaks ties on the id, posture reads "the previous scan" off that order, and every report is
stored in a file named after it. An id that repeats therefore does not merely look wrong: it
silently overwrites a scan's history, and an id that sorts wrongly makes posture compare
backwards and report new findings as resolved.

The defect these tests exist for: the trailing field was READ from the clock each time, on
the assumption of roughly microsecond resolution. On Windows the wall clock advances in
~15.6 ms steps, so two thousand consecutive reads return two distinct microsecond values and
every scan inside a tick minted the same id. The field is now seeded from the clock and
advanced by the process, which is what makes it unique and strictly increasing regardless of
what the clock can resolve.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.results import ScanResult, _scan_id
from k8smatrixwarden.web.app import WebApp


def _scan(platform=None, name=""):
    platform = platform or build_platform()
    result = ScannerAgent(platform).scan(ScanRequest(), platform.make_collector(mock=True))
    if name:
        result.name = name
    return result


# --------------------------------------------------------------------------- #
# The id itself
# --------------------------------------------------------------------------- #

def test_two_ids_minted_back_to_back_differ():
    assert _scan_id("x") != _scan_id("x")


def test_ids_minted_in_order_sort_in_order():
    ids = [_scan_id("x") for _ in range(60)]
    assert ids == sorted(ids)


def test_the_clocks_resolution_does_not_limit_uniqueness():
    """The regression, stated as the platform fact that caused it.

    If the trailing field were still read from the clock, this would mint far fewer distinct
    ids than calls on any platform whose wall clock ticks coarsely."""
    from k8smatrixwarden.core.timeutil import now_ist
    distinct_clock_readings = len({now_ist().microsecond for _ in range(2000)})
    ids = [_scan_id("x") for _ in range(2000)]
    assert len(set(ids)) == 2000, (
        f"{len(set(ids))} unique ids from 2000 calls, with only "
        f"{distinct_clock_readings} distinct clock readings available")


def test_the_public_id_format_is_unchanged():
    """Ids appear in filenames, download names, URLs and the dashboard. The fix stays inside
    the existing field rather than widening the format."""
    import re
    assert re.fullmatch(r"nightly-\d{8}-\d{6}-[0-9a-f]{4}", _scan_id("Nightly"))
    assert re.fullmatch(r"scan-\d{8}-\d{6}-[0-9a-f]{4}", _scan_id(""))


def test_ids_stay_within_the_report_stores_safe_charset():
    from k8smatrixwarden.core.report_store import _SAFE_SCAN_ID
    for name in ("", "Prod nightly", "weird/../name", "UPPER Case 42"):
        assert _SAFE_SCAN_ID.fullmatch(_scan_id(name))


def test_a_backwards_clock_step_does_not_reissue_an_id():
    """An NTP correction must not walk the counter back over ids already handed out."""
    import k8smatrixwarden.core.results as results
    before = [_scan_id("x") for _ in range(5)]
    stamp, bucket = results._LAST_ID
    original = results.now_ist
    try:
        # Pretend the clock jumped an hour into the past.
        import datetime as _dt
        results.now_ist = lambda: original() - _dt.timedelta(hours=1)
        after = [_scan_id("x") for _ in range(5)]
    finally:
        results.now_ist = original
    assert len(set(before + after)) == 10
    assert after == sorted(after)
    assert min(after) > max(before), "ids must keep advancing when the clock does not"
    assert results._LAST_ID >= (stamp, bucket)


def test_concurrent_mints_do_not_collide():
    """Reports are saved from the web app's request handlers, so ids are minted from more
    than one thread; two threads reading the same last value would mint the same id."""
    import threading
    minted, lock = [], threading.Lock()

    def work():
        batch = [_scan_id("t") for _ in range(200)]
        with lock:
            minted.extend(batch)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(minted)) == len(minted) == 1600


# --------------------------------------------------------------------------- #
# Rapid scans through the store
# --------------------------------------------------------------------------- #

def _rapid(count):
    """`count` scans saved back to back. Returns (store, results)."""
    platform = build_platform()
    store = ReportStore(tempfile.mkdtemp())
    results = []
    for _ in range(count):
        result = _scan(platform)
        store.save(result)
        results.append(result)
    return store, results


def test_two_scans_in_the_same_moment_are_two_reports():
    store, results = _rapid(2)
    a, b = results
    assert a.scan_id != b.scan_id
    assert a.scan_id < b.scan_id, "the earlier scan must sort first"
    assert store.load(a.scan_id) is not None
    assert store.load(b.scan_id) is not None


def test_ten_rapid_scans_are_ten_reports():
    store, results = _rapid(10)
    ids = [r.scan_id for r in results]
    assert len(set(ids)) == 10
    assert ids == sorted(ids)
    assert len(store.list()) == 10


def test_a_hundred_rapid_scans_are_a_hundred_reports():
    store, results = _rapid(100)
    ids = [r.scan_id for r in results]
    assert len(set(ids)) == 100, "every scan must get its own id"
    assert len(store.list()) == 100, "no report may overwrite another"
    assert len(os.listdir(store.dir)) >= 100
    for result in results:
        assert store.load(result.scan_id) is not None, result.scan_id


def test_every_rapid_report_keeps_its_own_content():
    """Distinct ids are worth nothing if the files end up holding the same scan."""
    store, results = _rapid(10)
    stored = [store.load(r.scan_id) for r in results]
    assert [s.scan_id for s in stored] == [r.scan_id for r in results]


# --------------------------------------------------------------------------- #
# Cross-process collision: the store refuses to overwrite a different scan
# --------------------------------------------------------------------------- #

def test_a_colliding_id_from_another_process_does_not_destroy_the_first_report():
    """Two processes share no counter, so they can mint the same id. Losing a report to
    that would take a whole run of history with it."""
    store = ReportStore(tempfile.mkdtemp())
    first = _scan()
    store.save(first)
    second = _scan()
    second.scan_id = first.scan_id            # as a second process would have minted it
    second.generated_at = "2026-09-02T07:00:00+05:30"
    store.save(second)
    assert second.scan_id != first.scan_id, "the newcomer is filed under a fresh id"
    assert store.load(first.scan_id) is not None, "the original report survives"
    assert store.load(second.scan_id) is not None
    assert len(store.list()) == 2


def test_resaving_the_same_scan_updates_it_rather_than_forking_it():
    """The ordinary path: runtime correlation is attached to a scan already on disk."""
    store = ReportStore(tempfile.mkdtemp())
    result = _scan()
    store.save(result)
    original_id = result.scan_id
    result.runtime = {"correlation": {"correlations": [], "confirmed_exploitation": 0}}
    store.save(result)
    assert result.scan_id == original_id
    assert len(store.list()) == 1
    assert store.load(original_id).runtime is not None


# --------------------------------------------------------------------------- #
# What depends on the ordering
# --------------------------------------------------------------------------- #

def test_the_store_reports_the_newest_scan_as_latest():
    store, results = _rapid(5)
    assert store.resolve(None).scan_id == results[-1].scan_id


def test_posture_compares_same_second_scans_in_the_right_direction():
    """REGRESSION. With a colliding or wrongly-ordered id, posture read the LATER scan as
    the previous one and swapped `new` with `resolved`."""
    from k8smatrixwarden.core.posture import latest_change
    store, results = _rapid(3)
    change = latest_change(store, results[-1].scan_id)
    assert change["current_scan_id"] == results[-1].scan_id
    assert change["previous_scan_id"] == results[-2].scan_id


def test_a_run_of_same_second_scans_has_no_regressions_or_resolutions():
    """Identical mock scans differ in nothing but their id. Anything reported as new or
    resolved across them would be the ordering defect showing through."""
    from k8smatrixwarden.core.posture import latest_change
    store, results = _rapid(4)
    change = latest_change(store, results[-1].scan_id)
    assert change["new"] == []
    assert change["resolved"] == []


def test_the_timeline_does_not_treat_rapid_scans_as_churn():
    store, results = _rapid(5)
    timeline = store.raw_timeline()
    assert timeline, "the timeline records the findings it saw"
    assert not any(entry.get("resolved_at") for entry in timeline.values()
                   if isinstance(entry, dict)), \
        "no finding was fixed between identical scans"


# --------------------------------------------------------------------------- #
# Surfaces that select a scan by id
# --------------------------------------------------------------------------- #

def _app_with(count):
    platform = build_platform()
    directory = tempfile.mkdtemp()
    store = ReportStore(directory)
    results = []
    for _ in range(count):
        result = _scan(platform)
        store.save(result)
        results.append(result)
    return WebApp(platform, reports_dir=directory), results


def test_the_runtime_api_defaults_to_the_latest_scan():
    app, results = _app_with(3)
    body = json.loads(app.route("GET", "/api/runtime").text)
    assert body["scan_id"] == results[-1].scan_id


def test_the_runtime_api_can_select_any_rapid_scan_by_id():
    app, results = _app_with(3)
    for result in results:
        body = json.loads(app.route("GET", "/api/runtime",
                                    query=f"scan_id={result.scan_id}").text)
        assert body["scan_id"] == result.scan_id


def test_the_dashboard_history_lists_every_rapid_scan_once():
    app, results = _app_with(5)
    body = json.loads(app.route("GET", "/api/dashboard").text)
    listed = [entry["scan_id"] for entry in body.get("history", [])]
    assert len(listed) == len(set(listed)) == 5
    assert set(listed) == {r.scan_id for r in results}


def test_the_mcp_report_listing_shows_every_rapid_scan():
    from k8smatrixwarden.mcp.server import build_tools
    store, results = _rapid(4)
    listed = build_tools()["list_reports"](reports_dir=store.dir)
    ids = [entry["scan_id"] for entry in listed]
    assert set(ids) == {r.scan_id for r in results}


def test_a_report_can_be_downloaded_for_each_rapid_scan():
    from k8smatrixwarden.mcp.server import build_tools
    store, results = _rapid(3)
    download = build_tools()["download_report"]
    for result in results:
        out = download(scan_id=result.scan_id, reports_dir=store.dir, format="markdown")
        assert out["scan_id"] == result.scan_id
        assert out["content"]


if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
