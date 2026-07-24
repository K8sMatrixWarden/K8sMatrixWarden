"""
Live-scan robustness (no real cluster needed).

Covers the resilience layer added so live scanning fails cleanly instead of leaking a
urllib3 traceback, and degrades gracefully when one resource type is inaccessible:
  * `_is_connection_error` classifies transport failures vs HTTP responses
  * a per-resource HTTP 403/404 is recorded as a warning and skipped, not fatal
  * a connection failure raises one clear, actionable RuntimeError

Uses the zero-dependency runner's calling convention (no fixtures): collectors are built
via __new__ to skip network I/O, and `_get_json` is replaced with a plain instance
attribute (instance attrs aren't bound, so the stub receives just `path`).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from k8smatrixwarden.core.evidence import (
    EvidenceCollector, LiveEvidenceCollector, _http_status, _is_connection_error,
    _short_api_error)
from k8smatrixwarden.core.models import Scope, ScopeLevel


class _FakeApiException(Exception):
    """Mimics kubernetes.client.exceptions.ApiException (has .status/.reason). The
    classifier duck-types on .status, so it need not be the real class."""
    def __init__(self, status, reason=""):
        super().__init__(f"({status})\nReason: {reason}")
        self.status = status
        self.reason = reason


def _raise(exc):
    def _stub(_path):
        raise exc
    return _stub


def _collector():
    """A LiveEvidenceCollector with no kube config and no preflight, built via __new__
    so we can unit-test _fetch/collect against a stubbed API with no real cluster."""
    coll = LiveEvidenceCollector.__new__(LiveEvidenceCollector)
    EvidenceCollector.__init__(coll)
    coll._context = "unit-test"
    # the attributes __init__ would have set before any fetch happens
    coll._kubeconfig = None
    coll._auth_detail = None
    return coll


# --------------------------------------------------------------------------- #
# classifier
# --------------------------------------------------------------------------- #
def test_connection_error_classifier_true_for_transport_failures():
    assert _is_connection_error(ConnectionRefusedError("refused"))
    assert _is_connection_error(TimeoutError("timed out"))
    assert _is_connection_error(OSError("no route to host"))


def test_connection_error_classifier_false_for_http_responses():
    # A 403/404 IS an HTTP response, the cluster is reachable, just guarded/missing.
    assert not _is_connection_error(_FakeApiException(403, "Forbidden"))
    assert not _is_connection_error(_FakeApiException(404, "Not Found"))


def test_short_api_error_is_human_readable():
    assert "403" in _short_api_error(_FakeApiException(403, "Forbidden"))
    assert "404" in _short_api_error(_FakeApiException(404, "Not Found"))


# --------------------------------------------------------------------------- #
# per-resource fault tolerance
# --------------------------------------------------------------------------- #
def test_forbidden_resource_is_skipped_not_fatal():
    coll = _collector()
    coll._get_json = _raise(_FakeApiException(403, "Forbidden"))
    out = coll._fetch("Secret", "secrets")
    assert out == []                      # skipped, not raised
    assert coll.warnings                  # and recorded
    assert "Secret" in coll.warnings[0]


def test_missing_api_group_is_skipped():
    coll = _collector()
    coll._get_json = _raise(_FakeApiException(404, "NotFound"))
    assert coll._fetch("Ingress", "ingresses") == []
    assert any("Ingress" in w for w in coll.warnings)


def test_partial_scan_collects_what_it_can():
    """One resource type forbidden, another readable → scan proceeds with the readable
    one and warns about the other (never aborts)."""
    coll = _collector()

    def selective(path):
        if "secrets" in path:
            raise _FakeApiException(403, "Forbidden")
        return [{"metadata": {"name": "p1"}}]

    coll._get_json = selective
    ev = coll.collect({"Pod", "Secret"}, Scope(ScopeLevel.CLUSTER))
    assert len(ev.get("Pod", all_scopes=True)) == 1     # readable type came through
    assert ev.get("Secret", all_scopes=True) == []      # forbidden type empty
    assert any("Secret" in w for w in coll.warnings)


# --------------------------------------------------------------------------- #
# connection failure -> one clean, actionable error
# --------------------------------------------------------------------------- #
def test_connection_failure_midscan_raises_clean_runtimeerror():
    coll = _collector()
    coll._get_json = _raise(ConnectionRefusedError("refused"))
    with pytest.raises(RuntimeError):
        coll._fetch("Pod", "pods")


def test_unreachable_message_is_actionable():
    coll = _collector()
    err = coll._unreachable(ConnectionRefusedError("Max retries exceeded"))
    msg = str(err)
    assert "Cannot reach the Kubernetes API server" in msg
    assert "cluster-info" in msg          # tells the user how to verify
    assert "--mock" in msg                # and the fallback


# --------------------------------------------------------------------------- #
# authentication failure -> fatal, never a silently empty "clean" scan
#
# The kubernetes client only *logs* an exec-credential-plugin failure and then carries
# on with no credentials, so an EKS/GKE/AKS kubeconfig whose cloud profile is not
# configured used to yield 401 on every resource, an empty evidence set, zero findings,
# and an "Excellent" rating for a cluster that was never read. These pin the fix.
# --------------------------------------------------------------------------- #
def test_http_status_extracts_api_exception_status():
    assert _http_status(_FakeApiException(401, "Unauthorized")) == 401
    assert _http_status(ConnectionRefusedError("refused")) is None


def test_unauthorized_is_fatal_not_a_skipped_resource():
    coll = _collector()
    coll._get_json = _raise(_FakeApiException(401, "Unauthorized"))
    with pytest.raises(RuntimeError) as err:
        coll._fetch("Pod", "pods")
    assert "authentication failed" in str(err.value).lower()
    assert not coll.warnings           # NOT downgraded into a per-resource warning


def test_auth_failed_message_names_the_cloud_profile_causes():
    coll = _collector()
    msg = str(coll._auth_failed("aws eks get-token failed (exit 255): "
                                "The config profile (prod) could not be found"))
    assert "profile (prod) could not be found" in msg     # the real reason, verbatim
    assert "AWS / EKS" in msg and "aws configure list-profiles" in msg
    assert "GCP / GKE" in msg and "Azure / AKS" in msg
    assert "would look like a clean cluster" in msg       # says why it refuses to report


def test_degraded_is_true_only_when_nothing_could_be_read():
    coll = _collector()
    coll._get_json = _raise(_FakeApiException(403, "Forbidden"))
    coll.collect({"Pod", "Secret"}, Scope(ScopeLevel.CLUSTER))
    assert coll.degraded               # every type errored => not a clean cluster


def test_partial_read_is_not_degraded():
    coll = _collector()

    def selective(path):
        if "secrets" in path:
            raise _FakeApiException(403, "Forbidden")
        return [{"metadata": {"name": "p1"}}]

    coll._get_json = selective
    coll.collect({"Pod", "Secret"}, Scope(ScopeLevel.CLUSTER))
    assert coll.warnings and not coll.degraded


def test_unread_cluster_scores_unknown_not_excellent():
    """The end-to-end guarantee: a collector that read nothing must never produce a
    passing rating, in any surface."""
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanMode, ScanRequest, Selector
    from k8smatrixwarden.core.reporting import scan_warning_lines
    from k8smatrixwarden.core.results import ScanResult

    class _Blind(EvidenceCollector):
        def _fetch(self, kind, bucket):
            self.warnings.append(f"{kind}: skipped (HTTP 403 Forbidden)")
            return []

    platform = build_platform()
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                          mode=ScanMode.SYNC)
    result = ScannerAgent(platform).scan(request, _Blind(), mode_label="live")

    assert result.risk.rating == "Unknown"
    assert result.risk.security_score == 0
    assert result.evidence_ok is False
    assert result.warnings
    assert "NOT evidence of a secure cluster" in scan_warning_lines(result)[0]

    # and it survives the report store round-trip, so a saved scan still says so
    replayed = ScanResult.from_dict(result.as_dict())
    assert replayed.risk.rating == "Unknown" and replayed.evidence_ok is False

    for fmt, marker in (("html", "Scan incomplete"), ("markdown", "Scan incomplete"),
                        ("text", "SCAN WARNINGS")):
        assert marker in platform.reporting.render(result, fmt), fmt


# --------------------------------------------------------------------------- #
# Credential-plugin detection is provider-agnostic
#
# The silent-no-credentials failure is not AWS-specific: the client swallows ANY exec
# plugin's failure, and its auth-provider loaders can likewise yield no usable token. EKS,
# GKE and AKS all go through the same code path here.
# --------------------------------------------------------------------------- #
import k8smatrixwarden.core.evidence as _ev


def _with_kubeconfig_user(monkey_user):
    """Swap the kubeconfig introspection for a fixed `user:` entry, so the provider
    matrix below runs with no kubeconfig, no cloud CLI and no network."""
    original = _ev._kubeconfig_user
    _ev._kubeconfig_user = lambda kubeconfig, context: monkey_user
    return original


def _exec_user(command, args):
    return {"exec": {"apiVersion": "client.authentication.k8s.io/v1beta1",
                     "command": command, "args": list(args)}}


def test_exec_plugin_failure_detected_for_every_cloud():
    """EKS / GKE / AKS: whatever the command is, a missing binary is reported as the
    reason authentication failed, with the exact argv the kubeconfig declares."""
    cases = [
        ("aws", ["eks", "get-token", "--cluster-name", "prod", "--profile", "prod-admin"]),
        ("gke-gcloud-auth-plugin", []),
        ("kubelogin", ["get-token", "--server-id", "6dae42f8-4368-4678-94ff-3960e28e3630"]),
    ]
    for command, args in cases:
        # a command that certainly does not exist, keeping the real argv visible
        binary = command + "-does-not-exist-k8smw"
        original = _with_kubeconfig_user(_exec_user(binary, args))
        try:
            detail = _ev._credential_failure(None, None)
        finally:
            _ev._kubeconfig_user = original
        assert detail, command
        assert "not installed or not on PATH" in detail, command
        assert binary in detail, command
        for arg in args:
            assert arg in detail, (command, arg)


def test_exec_plugin_nonzero_exit_reports_the_plugins_own_error():
    """The AWS case from the field: `aws eks get-token` exits non-zero because the named
    profile isn't configured. The plugin's own stderr is what the user needs to see."""
    import sys
    message = "The config profile (prod-admin) could not be found"
    # message passed as argv, so this stays free of nested quoting
    original = _with_kubeconfig_user(_exec_user(sys.executable, [
        "-c", "import sys; sys.stderr.write(sys.argv[1]); sys.exit(253)", message]))
    try:
        detail = _ev._credential_failure(None, None)
    finally:
        _ev._kubeconfig_user = original
    assert message in detail
    assert "exit 253" in detail


def test_working_exec_plugin_is_not_reported_as_a_failure():
    import sys
    original = _with_kubeconfig_user(_exec_user(sys.executable, ["-c", "pass"]))
    try:
        assert _ev._credential_failure(None, None) is None
    finally:
        _ev._kubeconfig_user = original


def test_legacy_auth_provider_kubeconfigs_are_also_explained():
    """The pre-`exec` mechanism, still emitted for older GKE/AKS/OIDC clusters. It has no
    command to re-run, but the failure must still name the mechanism and the fix rather
    than leaving the user with a bare 401."""
    for provider, expect in (("gcp", "gcloud auth login"),
                             ("azure", "az login"),
                             ("oidc", "OIDC provider")):
        original = _with_kubeconfig_user({"auth-provider": {"name": provider}})
        try:
            detail = _ev._credential_failure(None, None)
        finally:
            _ev._kubeconfig_user = original
        assert detail and provider in detail, provider
        assert expect in detail, provider


def test_kubeconfig_with_a_static_token_reports_no_credential_failure():
    original = _with_kubeconfig_user({"token": "abc123"})
    try:
        assert _ev._credential_failure(None, None) is None
    finally:
        _ev._kubeconfig_user = original
