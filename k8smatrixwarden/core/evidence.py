"""
Evidence Collector (§6.1).

The ONLY component that touches the cluster. It fetches the union of the resolved rules'
evidence needs, ONCE, constrained to the scan scope, and hands rules a shared, cached,
read-only snapshot. This is the efficiency win over per-tactic agents (redesign §3/§4).

Two backends:
  * MockEvidenceCollector , loads a JSON fixture (default; zero dependencies).
  * LiveEvidenceCollector , reads the K8s API as raw camelCase JSON (matches the fixture
                             exactly) via the optional `kubernetes` client.

`Evidence` is the object passed to every rule. Fields are accessed with dotted paths so
rule code is identical in mock and live mode.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from .models import Scope


# Logical kind -> the fixture/list bucket key.
KIND_ALIASES = {
    "Pod": "pods",
    "Deployment": "deployments",
    "DaemonSet": "daemonsets",
    "StatefulSet": "statefulsets",
    "ReplicaSet": "replicasets",
    "Job": "jobs",
    "CronJob": "cronjobs",
    "Service": "services",
    "Ingress": "ingresses",
    "NetworkPolicy": "networkpolicies",
    "Namespace": "namespaces",
    "Node": "nodes",
    "ServiceAccount": "serviceaccounts",
    "Secret": "secrets",
    "ConfigMap": "configmaps",
    "Role": "roles",
    "RoleBinding": "rolebindings",
    "ClusterRole": "clusterroles",
    "ClusterRoleBinding": "clusterrolebindings",
    "MutatingWebhookConfiguration": "mutatingwebhookconfigurations",
    "ValidatingWebhookConfiguration": "validatingwebhookconfigurations",
    "ComponentConfig": "componentconfig",    # synthetic: control-plane flags
    "CloudIAM": "cloudiam",                   # synthetic: cloud identity bindings
}


class Evidence:
    """A read-only, scope-filterable snapshot of cluster resources."""

    def __init__(self, buckets: dict[str, list[dict]], scope: Scope):
        self._buckets = buckets
        self._scope = scope

    def get(self, kind: str, *, all_scopes: bool = False) -> list[dict]:
        """Return resources of `kind`, scope-filtered unless all_scopes=True."""
        bucket = KIND_ALIASES.get(kind, kind.lower())
        items = self._buckets.get(bucket, []) or []
        if all_scopes:
            return list(items)
        return [r for r in items if self._scope.matches(r)]

    def raw(self, bucket: str) -> Any:
        return self._buckets.get(bucket)

    def namespaces(self) -> list[str]:
        return [ (n.get("metadata", {}) or {}).get("name")
                 for n in self.get("Namespace", all_scopes=True) ]

    @staticmethod
    def dig(obj: dict, path: str, default: Any = None) -> Any:
        """Dotted-path getter, e.g. dig(pod, 'spec.securityContext.privileged')."""
        cur: Any = obj
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return default
            if cur is None:
                return default
        return cur

    @staticmethod
    def containers(resource: dict) -> list[dict]:
        """All containers (regular + init + ephemeral) of a pod/workload."""
        spec = resource.get("spec", {}) or {}
        if "template" in spec:
            spec = (spec.get("template", {}) or {}).get("spec", {}) or {}
        out = []
        out.extend(spec.get("containers", []) or [])
        out.extend(spec.get("initContainers", []) or [])
        out.extend(spec.get("ephemeralContainers", []) or [])
        return out

    @staticmethod
    def pod_spec(resource: dict) -> dict:
        spec = resource.get("spec", {}) or {}
        if "template" in spec:
            return (spec.get("template", {}) or {}).get("spec", {}) or {}
        return spec


class EvidenceCollector:
    """Base collector: caches fetched buckets so each kind is fetched at most once."""

    def __init__(self) -> None:
        self._cache: dict[str, list[dict]] = {}
        #: Non-fatal problems hit while collecting (e.g. a resource type the scanner's
        #: RBAC can't read, or an API group absent on this cluster). The scan proceeds
        #: with whatever it could read; surfaces make partial coverage visible instead of
        #: silently under-reporting. Empty on the mock backend.
        self.warnings: list[str] = []
        #: True once at least one resource type was read successfully (an empty list from
        #: a healthy API still counts, the cluster answered). Stays False when every
        #: fetch errored, which is the difference between "clean cluster" and "we could
        #: not read the cluster at all".
        self.fetched_ok = False
        #: Per-resource-type read outcome, the structural basis for evidence coverage and
        #: assessment confidence (§5). kind -> {status: ok|partial|skipped, count, reason}.
        #: A kind that was never requested does not appear at all; a kind that was
        #: requested and could not be read appears as `skipped`, which is what stops
        #: "we could not look" from being reported as "nothing found".
        self.coverage: dict[str, dict] = {}

    @property
    def degraded(self) -> bool:
        """The scan could not read the cluster, its (empty) result is NOT evidence of a
        clean cluster and must never be rendered as a passing score."""
        return bool(self.warnings) and not self.fetched_ok

    def _record(self, kind: str, status: str, count: int = 0, reason: str = "",
                estimated: Optional[float] = None, basis: str = "measured") -> None:
        """Record how one resource type's read went.

        Three separate facts, deliberately not collapsed into one number:
          status            , ok | partial | skipped, what happened
          estimated_coverage, 0.0-1.0, or None when there is genuinely no basis to estimate
          basis             , measured | estimated | heuristic | unknown, HOW that number
                              was arrived at, so a report never presents a guess as a
                              measurement

        `ok` and `skipped` are measured (1.0 and 0.0, both known exactly). A truncated read
        is `estimated` when the API told us how much was left, and `heuristic` when it did
        not, in which case the fallback fraction is flagged as such rather than displayed
        as if it were counted.
        """
        if estimated is None and status in ("ok", "skipped"):
            estimated = 1.0 if status == "ok" else 0.0
        self.coverage[kind] = {"status": status, "count": count, "reason": reason,
                               "estimated_coverage": estimated, "coverage_basis": basis}

    def collect(self, needs: set[str], scope: Scope) -> Evidence:
        for kind in needs:
            bucket = KIND_ALIASES.get(kind, kind.lower())
            if bucket not in self._cache:
                items = self._fetch(kind, bucket)
                self._cache[bucket] = items
                # `_fetch` records its own outcome when the read was degraded; anything it
                # did not record was a clean read.
                self.coverage.setdefault(
                    kind, {"status": "ok", "count": len(items), "reason": "",
                           "estimated_coverage": 1.0, "coverage_basis": "measured"})
        return Evidence(self._cache, scope)

    def _fetch(self, kind: str, bucket: str) -> list[dict]:  # pragma: no cover - overridden
        raise NotImplementedError

    def cluster_label(self) -> str:
        """Stable identifier for the cluster this collector reads, the key the federation
        view groups saved scans by. Overridden per backend."""
        return "target-cluster"

    def collect_runtime_events(self, *, namespace: str = "falco",
                               since_seconds: int = 3600,
                               tail_lines: int = 2000) -> list[dict]:
        """Pull recent Falco alerts from the cluster as raw Falco event dicts.

        Only the live backend can actually read a Falco DaemonSet's logs; every other
        backend (mock, fixture) has no live stream, so the base returns nothing. This is
        the pull half of the runtime feed, the push half is `POST /api/runtime`."""
        return []


class MockEvidenceCollector(EvidenceCollector):
    """Loads all resources from a single JSON fixture (default backend)."""

    def __init__(self, fixture_path: str):
        super().__init__()
        with open(fixture_path, "r", encoding="utf-8") as fh:
            self._data = json.load(fh)
        self.fetched_ok = True

    def cluster_label(self) -> str:
        return "mock-cluster"

    def _fetch(self, kind: str, bucket: str) -> list[dict]:
        items = self._data.get(bucket, [])
        # Tag items with their kind if the fixture omitted it.
        for it in items:
            it.setdefault("kind", kind)
        return list(items)


def _api_exception_type() -> tuple:
    """The kubernetes client's ApiException, or an empty tuple if the package is absent
    (isinstance(x, ()) is always False, so callers stay safe either way)."""
    try:
        from kubernetes.client.exceptions import ApiException  # type: ignore
        return (ApiException,)
    except Exception:
        return ()


def _is_connection_error(exc: BaseException) -> bool:
    """True when `exc` is a transport/reachability failure, the cluster is down, the
    endpoint is wrong, DNS fails, the connection is refused, or a request times out, 
    as opposed to an HTTP response like 403/404. A connection failure means nothing on
    the cluster is scannable (fatal, one clean message); an HTTP error affects only one
    resource type (skip it, keep scanning)."""
    api_exc = _api_exception_type()
    if api_exc and isinstance(exc, api_exc):
        # status 0/None => the client never received an HTTP response = transport failure.
        return _http_status(exc) is None
    try:
        import urllib3
        if isinstance(exc, urllib3.exceptions.HTTPError):
            return True
    except Exception:
        pass
    return isinstance(exc, (ConnectionError, TimeoutError, OSError))


def _http_status(exc: BaseException) -> Optional[int]:
    """The HTTP status this exception carries, or None when it is not an HTTP response.

    Duck-typed on `.status` (which is what ApiException exposes) instead of an isinstance
    check, so classification behaves identically whether or not the optional `kubernetes`
    package is importable. A status of 0/None means the client never received a response
    at all, a transport failure, not an HTTP status."""
    status = getattr(exc, "status", None)
    return status if isinstance(status, int) and status > 0 else None


#: How long a kubeconfig credential plugin (`aws eks get-token`, `gke-gcloud-auth-plugin`,
#: `kubelogin`) gets to produce a token before we call it broken.
_EXEC_TIMEOUT = 20


def _has_credentials(client) -> bool:
    """True when loading the kubeconfig actually produced usable credentials.

    The kubernetes client stores them on the default Configuration: a bearer token in
    `api_key['authorization']`, a client certificate, or basic-auth. All three empty means
    every request will go out unauthenticated and come back 401."""
    try:
        cfg = client.Configuration.get_default_copy()
    except Exception:
        return True                       # can't tell, let the preflight decide
    return bool((cfg.api_key or {}).get("authorization")
                or getattr(cfg, "cert_file", None)
                or getattr(cfg, "username", None))


#: How the `auth-provider` name in a kubeconfig maps to the command that refreshes it.
#: This is the pre-`exec` mechanism; `gcloud`/`az` still emit it for older clusters, and
#: the client's `_load_gcp_token`/`_load_azure_token`/`_load_oid_token` can likewise end up
#: returning no credentials (an unrefreshable/expired cached token) without raising.
_AUTH_PROVIDER_FIX = {
    "gcp": "run `gcloud auth login` (and install gke-gcloud-auth-plugin)",
    "azure": "run `az login`, or convert the kubeconfig with `kubelogin convert-kubeconfig`",
    "oidc": "re-authenticate with your OIDC provider to refresh the id-token",
}


def _kubeconfig_user(kubeconfig: Optional[str], context: Optional[str]) -> Optional[dict]:
    """The `user:` entry the active context resolves to, or None if it can't be read.

    Best-effort introspection through the client's own loader, so it honours the same
    KUBECONFIG merge order and context selection the real load did."""
    try:
        from kubernetes.config import kube_config
        merger = kube_config.KubeConfigMerger(
            kubeconfig or kube_config.KUBE_CONFIG_DEFAULT_LOCATION)
        loader = kube_config._get_kube_config_loader(
            config_dict=merger.config, active_context=context)
        return dict(loader._user or {})
    except Exception:
        return None


def _credential_failure(kubeconfig: Optional[str],
                        context: Optional[str]) -> Optional[str]:
    """Why the kubeconfig produced no credentials, in the user's own terms, or None.

    `kubernetes.config.load_kube_config()` only *logs* an exec-plugin failure and then
    carries on with NO credentials (see `_load_from_exec_plugin`); its `auth-provider`
    loaders can similarly yield nothing for an expired token they cannot refresh. Either
    way the result is a 401 on every request, which, before this, meant every resource
    type was skipped as a warning and the scan reported zero findings and an "Excellent"
    rating for a cluster it never read.

    Both mechanisms are handled, and both are **provider-agnostic**: an `exec` block is
    re-run whatever its command is (`aws eks get-token`, `gke-gcloud-auth-plugin`,
    `kubelogin`, or anything else), so EKS, GKE and AKS all surface their own real error.

    Best-effort: if the kubeconfig can't be introspected this returns None and the 401
    preflight still fails the scan, just with a generic message.
    """
    import subprocess
    user = _kubeconfig_user(kubeconfig, context)
    if user is None:
        return None
    exec_cfg = dict(user.get("exec") or {})
    command = exec_cfg.get("command")
    if not command:
        # No exec block, an `auth-provider` (the pre-exec GKE/AKS/OIDC mechanism) is the
        # other way a kubeconfig silently ends up with no usable token. We can't re-run it
        # the way we can an exec plugin, but we can name it and the command that fixes it.
        provider = ((user.get("auth-provider") or {}).get("name") or "").strip().lower()
        if provider:
            fix = _AUTH_PROVIDER_FIX.get(provider,
                                         "re-authenticate with that provider")
            return (f"the kubeconfig authenticates with auth-provider {provider!r}, which "
                    f"returned no usable token (it is missing or expired and could not be "
                    f"refreshed), {fix}")
        return None
    # Same command the kubernetes client itself would run, no new trust boundary.
    argv = [str(command)] + [str(a) for a in (exec_cfg.get("args") or [])]
    env = dict(os.environ)
    for e in (exec_cfg.get("env") or []):
        if isinstance(e, dict) and e.get("name"):
            env[str(e["name"])] = str(e.get("value", ""))
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, env=env,
                              timeout=_EXEC_TIMEOUT)
    except FileNotFoundError:
        return (f"credential plugin {command!r} is not installed or not on PATH "
                f"(the kubeconfig authenticates with: {' '.join(argv)})")
    except subprocess.TimeoutExpired:
        return f"credential plugin {' '.join(argv)} timed out after {_EXEC_TIMEOUT}s"
    except Exception as exc:
        return f"could not run credential plugin {' '.join(argv)}: {exc}"
    if proc.returncode == 0:
        return None
    detail = [ln for ln in (proc.stderr or proc.stdout or "").splitlines() if ln.strip()]
    return (f"{' '.join(argv)} failed (exit {proc.returncode}): "
            + (detail[-1].strip()[:300] if detail else "no output"))


def _short_api_error(exc: BaseException) -> str:
    """A one-line, human reason for skipping a resource type (used in scan warnings)."""
    status = _http_status(exc)
    if status is not None:
        if status == 401:
            return "HTTP 401 Unauthorized, the cluster rejected our credentials"
        if status == 403:
            return "HTTP 403 Forbidden, scanner ServiceAccount lacks read RBAC for it"
        if status == 404:
            return "HTTP 404, API group/resource not present on this cluster"
        reason = (getattr(exc, "reason", "") or "").strip()
        return f"HTTP {status} {reason}".strip()
    first = (str(exc).splitlines() or [""])[0][:120]
    return f"{type(exc).__name__}: {first}" if first else type(exc).__name__


class LiveEvidenceCollector(EvidenceCollector):
    """
    Reads the live cluster as raw camelCase JSON via the optional `kubernetes` client.
    Imported lazily so the tool runs without the dependency.

    Resilient by design: a connection failure (cluster down / wrong endpoint) fails fast
    with one clear, actionable message instead of a urllib3 traceback, and a per-resource
    HTTP error (RBAC-forbidden secret, absent API group) is recorded as a warning and
    skipped rather than aborting the whole scan.
    """

    #: Per-request cap (seconds) so an unreachable/slow API server can't hang a scan.
    _REQUEST_TIMEOUT = 15
    _PREFLIGHT_TIMEOUT = 6
    #: Set by `_get_json` when a list was truncated at the pagination cap, so `_fetch` can
    #: record that type's coverage as `partial` rather than a clean read. A class-level
    #: default so a collector built without __init__ (tests substituting a fake API) still
    #: has it.
    _page_capped = False
    #: `metadata.remainingItemCount` from the last page read, when the API supplied it.
    #: None means the cluster did not say, which is reported as an unknown rather than
    #: being filled in with a plausible-looking number.
    _page_remaining = None

    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        super().__init__()
        try:
            from kubernetes import client, config  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Live scanning requires the 'kubernetes' package. "
                "Install it (`pip install kubernetes`) or use --mock."
            ) from exc
        if kubeconfig or context:
            # User explicitly pointed us at a kubeconfig/context, a failure here is a
            # real, specific problem (bad path, unknown context) and must not be masked
            # by a confusing in-cluster-config fallback error.
            try:
                config.load_kube_config(config_file=kubeconfig, context=context)
            except Exception as exc:
                raise RuntimeError(
                    f"Could not load kubeconfig (file={kubeconfig!r}, "
                    f"context={context!r}): {exc}\n"
                    f"Run `kubectl config get-contexts` to see valid context names."
                ) from exc
        else:
            try:
                config.load_kube_config()
            except Exception:
                config.load_incluster_config()
        self._client = client
        self._api = client.ApiClient()
        self._context = context
        self._kubeconfig = kubeconfig
        # Resolve the active context name once, so a scan run without an explicit --context
        # still records WHICH cluster it hit (the federation view groups by this).
        self._active_context = context
        if not self._active_context:
            try:
                _all, active = config.list_kube_config_contexts(config_file=kubeconfig)
                self._active_context = (active or {}).get("name")
            except Exception:
                self._active_context = None
        #: The real reason authentication is broken, when we could recover it.
        self._auth_detail: Optional[str] = None
        if not _has_credentials(client):
            # No credentials at all after loading: if the kubeconfig authenticates via an
            # exec plugin, that plugin is why. Fail here with its own error rather than
            # letting it surface as an anonymous 401 further down.
            self._auth_detail = self._credential_error()
            if self._auth_detail:
                raise self._auth_failed(self._auth_detail)
        self._preflight()

    def cluster_label(self) -> str:
        return self._active_context or "live-cluster"

    #: Label selectors a Falco DaemonSet is found by, the helm-chart canonical label first,
    #: then the legacy `app=falco` some older installs still use.
    _FALCO_SELECTORS = ("app.kubernetes.io/name=falco", "app=falco")

    def collect_runtime_events(self, *, namespace: str = "falco",
                               since_seconds: int = 3600,
                               tail_lines: int = 2000) -> list[dict]:
        """Read recent Falco alerts from the DaemonSet's pod logs (json_output=true) using
        the same authenticated client the scan already loaded. Best-effort: any failure is
        recorded as a warning and returns whatever was read, never aborting the scan."""
        from .falco_feed import parse_falco_log

        core = self._client.CoreV1Api(self._api)
        items = []
        for selector in self._FALCO_SELECTORS:
            try:
                pods = core.list_namespaced_pod(
                    namespace, label_selector=selector,
                    _request_timeout=self._REQUEST_TIMEOUT)
            except Exception as exc:
                self.warnings.append(
                    f"Falco feed: could not list pods in ns/{namespace}: "
                    f"{_short_api_error(exc)}")
                return []
            items = getattr(pods, "items", []) or []
            if items:
                break
        if not items:
            self.warnings.append(
                f"Falco feed: no Falco pods in ns/{namespace}, install Falco to see live "
                f"correlation (the deploy_falco tool prints the helm commands)")
            return []

        events: list[dict] = []
        read_any = False
        for pod in items:
            log = self._read_falco_pod_log(core, pod.metadata.name, namespace,
                                           since_seconds, tail_lines)
            if log is None:
                continue
            read_any = True
            events.extend(parse_falco_log(log))
        if read_any and not events:
            self.warnings.append(
                "Falco feed: Falco is running but produced no JSON events in the window, "
                "enable JSON output (helm --set falco.json_output=true) and confirm there "
                "is cluster activity to alert on")
        return events

    def _read_falco_pod_log(self, core, name: str, namespace: str,
                            since_seconds: int, tail_lines: int):
        """Read one Falco pod's log. Falco pods often run several containers
        (falco, falcosidekick); the alerts are on the 'falco' container, so try it first
        and fall back to the pod default if that container name isn't present."""
        last_exc = None
        for container in ("falco", None):
            try:
                return core.read_namespaced_pod_log(
                    name, namespace, container=container, since_seconds=since_seconds,
                    tail_lines=tail_lines, timestamps=False,
                    _request_timeout=self._REQUEST_TIMEOUT)
            except Exception as exc:
                last_exc = exc
                if container == "falco" and _http_status(exc) == 400:
                    continue  # multi-container pod without a 'falco' container, retry default
                break
        self.warnings.append(
            f"Falco feed: could not read logs for pod/{name}: {_short_api_error(last_exc)}")
        return None

    def _credential_error(self) -> Optional[str]:
        """The exec credential plugin's real failure, resolved at most once. Also covers
        the case where a *stale* cached token loaded fine but the cluster rejects it, 
        re-running the plugin is exactly what surfaces an expired/misconfigured profile."""
        if self._auth_detail is None:
            self._auth_detail = _credential_failure(self._kubeconfig, self._context)
        return self._auth_detail

    def _unreachable(self, exc: BaseException) -> RuntimeError:
        """A clear, actionable error for 'the API server can't be reached', the common
        live-scan failure (cluster stopped, wrong endpoint), instead of a raw traceback."""
        ctx = self._context or "(current-context)"
        detail = (str(exc).splitlines() or [""])[0][:200] or type(exc).__name__
        hint_ctx = self._context or "<name>"
        return RuntimeError(
            f"Cannot reach the Kubernetes API server for context {ctx!r}.\n"
            f"  → {type(exc).__name__}: {detail}\n"
            f"The cluster may be stopped, or the context may point at the wrong endpoint.\n"
            f"Verify it is running:  kubectl --context {hint_ctx} cluster-info\n"
            f"Or scan the bundled sample cluster instead:  add --mock")

    def _auth_failed(self, detail: Optional[str] = None) -> RuntimeError:
        """The cluster is reachable but our credentials are missing or rejected.

        This is fatal on purpose. Treating it as a per-resource warning is what produced
        the empty "0 findings / Excellent" scan of a cluster the tool never read."""
        ctx = self._context or "(current-context)"
        lines = [f"Kubernetes API authentication failed for context {ctx!r}, the "
                 f"kubeconfig loaded, but no valid credentials could be obtained."]
        if detail:
            lines.append(f"  → {detail}")
        lines += [
            "The kubeconfig's credential plugin could not issue a token. Check the "
            "cloud profile it depends on:",
            "  * AWS / EKS  , the AWS profile named in the kubeconfig is not configured "
            "on this machine.",
            "                  Verify: aws configure list-profiles  ·  "
            "AWS_PROFILE=<name> aws sts get-caller-identity",
            "  * GCP / GKE  , gcloud auth login, and install gke-gcloud-auth-plugin.",
            "  * Azure / AKS, az login (kubelogin).",
            "Refusing to save a scan of a cluster that could not be read, an empty "
            "result would look like a clean cluster.",
            "To scan the bundled sample cluster instead:  add --mock",
        ]
        return RuntimeError("\n".join(lines))

    def _preflight(self) -> None:
        """Probe the API server once up front so an unreachable or unauthenticated
        cluster fails fast with a clear message. A *connection* failure and a 401 are both
        fatal, neither leaves anything scannable. A 403 on /version is not: some clusters
        gate that endpoint while real resources stay readable, so per-resource fetches
        handle their own authorization."""
        try:
            self._api.call_api("/version", "GET", auth_settings=["BearerToken"],
                               _preload_content=False,
                               _request_timeout=self._PREFLIGHT_TIMEOUT)
        except Exception as exc:
            if _is_connection_error(exc):
                raise self._unreachable(exc) from exc
            if _http_status(exc) == 401:
                raise self._auth_failed(
                    self._credential_error() or _short_api_error(exc)) from exc

    #: Objects per page, and a hard page cap. On a large cluster a single unpaginated LIST
    #: can time out or blow memory; paging in bounded chunks (each with its OWN per-request
    #: timeout) makes a big cluster degrade, read what we can, warn about the rest, instead
    #: of aborting the whole scan. 500 × 200 = 100k objects before the cap trips.
    _PAGE_LIMIT = 500
    _MAX_PAGES = 200

    def _get_json(self, path: str) -> list[dict]:
        """Call the REST path (paginated) and parse the raw JSON ourselves (camelCase kept).

        `_preload_content=False` returns the underlying HTTP response without the client
        trying to deserialize it into a typed model, so this stays compatible across
        kubernetes-client versions, the older `response_type=` kwarg was removed in v33+
        (renamed to `response_types_map`), which otherwise breaks live scanning on a
        modern client even though pyproject only requires `kubernetes>=28`.

        Follows the Kubernetes `metadata.continue` chunk token so a cluster with more objects
        than one page still returns fully; each page carries its own `_request_timeout`, so a
        slow/huge list degrades page-by-page rather than as one all-or-nothing call.
        """
        items: list[dict] = []
        cont = ""
        for page in range(self._MAX_PAGES):
            sep = "&" if "?" in path else "?"
            p = f"{path}{sep}limit={self._PAGE_LIMIT}"
            if cont:
                p += f"&continue={cont}"
            resp = self._api.call_api(
                p, "GET", auth_settings=["BearerToken"],
                _preload_content=False, _request_timeout=self._REQUEST_TIMEOUT,
            )
            raw = resp[0] if isinstance(resp, tuple) else resp
            body = getattr(raw, "data", raw)
            if isinstance(body, (bytes, bytearray)):
                body = body.decode("utf-8")
            data = json.loads(body) if body else {}
            if not isinstance(data, dict):
                break
            items.extend(data.get("items", []) or [])
            meta = data.get("metadata") or {}
            cont = meta.get("continue") or ""
            # Kubernetes reports how many objects are still unread when it knows, which is
            # the difference between estimating coverage and guessing it.
            remaining = meta.get("remainingItemCount")
            self._page_remaining = int(remaining) if isinstance(remaining, int) else None
            if not cont:
                return items
        # Hit the page cap with a continue token still outstanding, partial, and we say so
        # rather than silently under-reporting a very large cluster.
        self._page_capped = True
        self.warnings.append(
            f"{path}: read first {len(items)} objects then stopped at the pagination cap "
            f"({self._MAX_PAGES} pages), results for this type are partial")
        return items

    _PATHS = {
        "pods": "/api/v1/pods",
        "services": "/api/v1/services",
        "secrets": "/api/v1/secrets",
        "configmaps": "/api/v1/configmaps",
        "namespaces": "/api/v1/namespaces",
        "nodes": "/api/v1/nodes",
        "serviceaccounts": "/api/v1/serviceaccounts",
        "deployments": "/apis/apps/v1/deployments",
        "daemonsets": "/apis/apps/v1/daemonsets",
        "statefulsets": "/apis/apps/v1/statefulsets",
        "replicasets": "/apis/apps/v1/replicasets",
        "jobs": "/apis/batch/v1/jobs",
        "cronjobs": "/apis/batch/v1/cronjobs",
        "networkpolicies": "/apis/networking.k8s.io/v1/networkpolicies",
        "ingresses": "/apis/networking.k8s.io/v1/ingresses",
        "roles": "/apis/rbac.authorization.k8s.io/v1/roles",
        "rolebindings": "/apis/rbac.authorization.k8s.io/v1/rolebindings",
        "clusterroles": "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        "clusterrolebindings": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "mutatingwebhookconfigurations":
            "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
        "validatingwebhookconfigurations":
            "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
    }

    def _fetch(self, kind: str, bucket: str) -> list[dict]:
        if bucket == "componentconfig":
            # Mitigation Layer 1/2: build ComponentConfig from kube-system static-pod specs.
            return self._build_component_config()
        path = self._PATHS.get(bucket)
        if not path:
            # Synthetic buckets (cloudiam) have no K8s API path and need an external
            # adapter. Report them as unread rather than as an empty, clean result.
            self._record(kind, "skipped", 0,
                         "no Kubernetes API path; needs an external evidence adapter")
            return []
        try:
            items = self._get_json(path)
        except Exception as exc:
            if _is_connection_error(exc):
                # The cluster went unreachable mid-scan, nothing more is scannable.
                raise self._unreachable(exc) from exc
            if _http_status(exc) == 401:
                # Credentials are missing/expired: no resource type is readable, so this
                # is fatal too. Downgrading it to a warning is what let an unauthenticated
                # scan report zero findings and a passing score.
                raise self._auth_failed(
                    self._credential_error() or _short_api_error(exc)) from exc
            # RBAC-forbidden, missing API group, or a transient error for THIS resource
            # type only: skip it, record why, and keep scanning everything else. Honest
            # partial coverage beats aborting the whole scan over one resource type.
            reason = _short_api_error(exc)
            self.warnings.append(f"{kind}: skipped ({reason})")
            self._record(kind, "skipped", 0, reason)
            return []
        if self._page_capped:
            self._page_capped = False
            remaining, self._page_remaining = self._page_remaining, None
            if remaining is not None and (len(items) + remaining) > 0:
                total = len(items) + remaining
                self._record(kind, "partial", len(items),
                             f"hit the pagination cap; read {len(items)} of ~{total} "
                             f"objects the API reported",
                             estimated=round(len(items) / total, 3), basis="estimated")
            else:
                self._record(kind, "partial", len(items),
                             "hit the pagination cap; the API did not report how many "
                             "objects remain, so the read fraction is not known",
                             estimated=None, basis="unknown")
        self.fetched_ok = True
        for it in items:
            it.setdefault("kind", kind)
        return items

    def _build_component_config(self) -> list[dict]:
        """Parse control-plane component flags from their kube-system static Pods.

        On self-managed (kubeadm/k3s) clusters the API server, controller-manager,
        scheduler and etcd run as static Pods whose --flags are visible in the Pod spec.
        This recovers ~38 CIS 'process flag' controls with NO node access.
        """
        try:
            pods = self._get_json("/api/v1/namespaces/kube-system/pods")
        except Exception as exc:
            reason = _short_api_error(exc)
            self.warnings.append(
                f"ComponentConfig: control-plane flags unavailable "
                f"({reason}), control-plane checks were not evaluated")
            self._record("ComponentConfig", "skipped", 0, reason)
            return []
        config = build_component_config(pods)
        # No component sections means no control-plane static Pods were visible, the
        # normal case on a managed cluster (EKS/GKE/AKS), where the control plane is
        # provider-owned. The flag rules correctly stay silent; say so, so an operator
        # reads "not applicable" rather than assuming those checks passed.
        if not any(k != "version" for k in (config.get("spec") or {})):
            self.warnings.append(
                "ComponentConfig: no control-plane static Pods visible in kube-system, "
                "the control plane is provider-managed (EKS/GKE/AKS) or runs outside the "
                "cluster, so API server / etcd / kubelet flag checks were not applicable")
        return [config]


def build_component_config(pods: list[dict]) -> dict:
    """Turn kube-system control-plane Pods into a ComponentConfig evidence object."""
    name_to_comp = {
        "kube-apiserver": "apiServer",
        "kube-controller-manager": "controllerManager",
        "kube-scheduler": "scheduler",
        "etcd": "etcd",
    }
    spec: dict = {"version": None}
    for pod in pods:
        pname = (pod.get("metadata", {}) or {}).get("name", "")
        comp = next((c for prefix, c in name_to_comp.items()
                     if pname.startswith(prefix)), None)
        if not comp:
            continue
        containers = (pod.get("spec", {}) or {}).get("containers", []) or []
        tokens: list[str] = []
        for c in containers:
            tokens += (c.get("command", []) or []) + (c.get("args", []) or [])
        flags = _parse_flags(tokens)
        entry = spec.setdefault(comp, {})
        entry["flags"] = flags
        if comp == "apiServer":
            entry["anonymousAuth"] = flags.get("anonymous-auth") == "true"
            entry["insecurePort"] = int(flags.get("insecure-port", 0) or 0)
            entry["auditLogPath"] = flags.get("audit-log-path", "")
            entry["encryptionProvider"] = flags.get("encryption-provider-config", "")
        elif comp == "etcd":
            entry["clientCertAuth"] = flags.get("client-cert-auth") == "true"
    return {"kind": "ComponentConfig", "metadata": {"name": "control-plane"}, "spec": spec}


def _parse_flags(tokens: list[str]) -> dict:
    """Parse ['--k=v', '--flag', 'value'] into {k: v}."""
    flags: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if isinstance(tok, str) and tok.startswith("--"):
            body = tok[2:]
            if "=" in body:
                k, v = body.split("=", 1)
                flags[k] = v
            else:
                nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
                if isinstance(nxt, str) and not nxt.startswith("--"):
                    flags[body] = nxt
                    i += 1
                else:
                    flags[body] = "true"
        i += 1
    return flags


# --------------------------------------------------------------------------- #
# Provider detection, which cloud/distro, so callers pick the right CIS profile
# (and, later, the right cloud-IAM API). Core K8s API paths are identical across
# providers, so scanning itself needs no per-cloud branch; only the managed-control-
# plane question (CIS sections 1-3) and cloud-IAM evidence do.
# --------------------------------------------------------------------------- #
#: A managed-service node label is authoritative for "this is GKE/EKS/AKS", its
#: presence means the control plane is provider-owned (CIS profile => NA sections 1-3).
_MANAGED_NODE_LABELS = {
    "cloud.google.com/gke-nodepool": "gke",
    "eks.amazonaws.com/nodegroup": "eks",
    "kubernetes.azure.com/cluster": "aks",
}
#: providerID scheme names the IaaS. A cloud VM WITHOUT a managed label is
#: self-managed K8s on that cloud, control plane is still inspectable, so its CIS
#: profile stays 'self-managed'; only `cloud` reflects the IaaS (for cloud-IAM APIs).
_PROVIDERID_CLOUD = {"gce": "gcp", "aws": "aws", "azure": "azure"}


def detect_provider(nodes: list[dict]) -> dict:
    """Best-effort cluster provider from Node objects. Returns:
        cloud  , 'gcp' | 'aws' | 'azure' | 'local'   (which IaaS; picks cloud-IAM API)
        managed, True if a managed offering owns the control plane (GKE/EKS/AKS)
        profile, 'gke' | 'eks' | 'aks' | 'self-managed'   (feed straight to CIS)
    Managed-service node labels are authoritative for `managed`/`profile`; providerID
    only names the cloud. Empty/kind/k3s nodes => local, self-managed."""
    cloud = "local"
    for node in nodes:
        pid = (node.get("spec", {}) or {}).get("providerID", "") or ""
        scheme = pid.split(":", 1)[0].lower()
        if scheme in _PROVIDERID_CLOUD:
            cloud = _PROVIDERID_CLOUD[scheme]
            break
    profile = None
    for node in nodes:
        labels = (node.get("metadata", {}) or {}).get("labels", {}) or {}
        profile = next((p for lbl, p in _MANAGED_NODE_LABELS.items() if lbl in labels), None)
        if profile:
            break
    return {"cloud": cloud, "managed": profile is not None,
            "profile": profile or "self-managed"}


def default_fixture_path() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "data", "fixtures", "mock_cluster.json")
