"""
The drift detector and the log-tampering rule spoke a syscall vocabulary Falco does not use.

`op` is Falco's raw `evt.type`. Linux does not have a `truncate` syscall in the path these
events take, and it has not had bare `unlink`/`rename`/`open` for years -- libc calls the
`*at` variants. So Falco reports `openat`, `unlinkat`, `renameat2`, `ftruncate`, while:

    correlation._WRITE_OPS = {"write","openwrite","open_write","truncate","rename","unlink"}
    rt-log-clear matcher    = op == "truncate" and "/var/log" in file

Neither could ever match. Two consequences, both false negatives:

  * the `readOnlyRootFilesystem` branch of `detect_drift` was unreachable for any
    Falco-sourced event -- the declared-vs-observed blocker that stayed open across
    several validation passes was this, not a missing provider capability;
  * `rt-log-clear` (Indicator Removal, T1070) could never fire, so log tampering was only
    ever relayed under Falco's name and never detected by KMW.

Measured live on EKS. A pod promising `readOnlyRootFilesystem: true` with an emptyDir at
/var/log truncated /var/log/syslog. Stock Falco "Clear Log Activities" fired with
`evt.type=openat`, `fd.name=/var/log/syslog`. KMW reported drift_count 0.

Two fixes. `op` is canonicalised to the base verb, so the unambiguous mutating syscalls
line up. And `openat` on its own is NOT treated as a write -- a read is also an `openat`,
and inventing writes would be worse than missing them -- so write intent for the open
family comes from the provider having already asserted it, which is the only place that
fact exists.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent, canonical_op, is_write_event
from k8smatrixwarden.core.correlation import detect_drift

# The exact event Falco emitted on EKS, fields verbatim.
LIVE = {"source": "falco", "proc": "sh", "op": "openat", "namespace": "kmw-drift",
        "pod": "readonly-liar", "uid": "0", "file": "/var/log/syslog",
        "rule": "Clear Log Activities", "time": "2026-09-09T18:25:47.750638580Z"}

READONLY_POD = {"metadata": {"name": "readonly-liar", "namespace": "kmw-drift"},
                "spec": {"containers": [{"name": "app", "securityContext": {
                    "readOnlyRootFilesystem": True, "privileged": False}}]}}


def test_the_at_variants_canonicalise_to_their_base_verb():
    for raw, base in (("openat", "open"), ("openat2", "open"), ("unlinkat", "unlink"),
                      ("renameat", "rename"), ("renameat2", "rename"),
                      ("ftruncate", "truncate"), ("pwrite", "write"),
                      ("writev", "write"), ("write", "write")):
        assert canonical_op(raw) == base, raw


def test_a_bare_openat_is_not_called_a_write():
    """A read is an openat too. Guessing here would invent drift on every file read."""
    assert not is_write_event({"op": "openat", "rule": "Read sensitive file untrusted"})


def test_the_provider_asserting_tampering_is_a_write():
    assert is_write_event(LIVE), (
        "Falco's own rule only fires on O_TRUNC; discarding that verdict loses the only "
        "evidence of write intent that exists in the event")


def test_unambiguous_mutating_syscalls_need_no_provider_verdict():
    for op in ("unlinkat", "renameat2", "ftruncate", "write"):
        assert is_write_event({"op": op, "rule": "some rule nobody has a table for"}), op


def test_the_live_drift_case_is_now_detected():
    out = detect_drift([READONLY_POD], [LIVE])
    assert out["drift_count"] == 1, out
    d = out["drift"][0]
    assert d["policy"] == "readOnlyRootFilesystem"
    assert d["declared"] == "readOnlyRootFilesystem: true"
    assert "/var/log/syslog" in d["observed"]
    assert d["severity"] == "CRITICAL"


def test_reading_a_file_on_a_readonly_pod_is_not_drift():
    """The false positive the fix must not introduce."""
    read = dict(LIVE, rule="Read sensitive file untrusted", file="/etc/shadow")
    assert detect_drift([READONLY_POD], [read])["drift_count"] == 0


def test_a_write_inside_a_writable_prefix_is_not_drift():
    tmp = dict(LIVE, file="/tmp/scratch", rule="Clear Log Activities")
    assert detect_drift([READONLY_POD], [tmp])["drift_count"] == 0


def test_rt_log_clear_fires_on_the_real_event():
    # evaluate() takes one event and returns RuntimeAlert objects, not dicts.
    fired = [a for a in RuntimeAgent().evaluate(LIVE)
             if getattr(a, "rule_id", None) == "rt-log-clear"]
    assert fired, ("rt-log-clear still cannot match a real Falco log-tampering event; "
                   "T1070 detection is KMW-blind and only relayed under Falco's name")
