"""Build Kubernetes manifests and a Helm chart from a list of components, no YAML by hand.

An engineer drops components on a canvas (workload, service, ingress, network policy, ...)
and fills in a few plain fields. This module turns that spec into:

  * `manifests(spec)`   , plain, ready-to-apply YAML documents (used for preview and checking),
  * `chart_files(spec)` , a real Helm chart whose templates read the same values, and
  * `check(spec)`       , the scanner's own rules run on what was just built.

Every component starts from the hardened defaults the scanner would otherwise ask for
(non-root, read-only root filesystem, no extra capabilities, resource limits, seccomp, no
token mount, default-deny networking). A person can loosen a default on purpose; the live check
then says what that costs. The tool still never applies anything: it hands over files and
the `helm install` line.
"""
from __future__ import annotations

import io
import re
import tarfile
from typing import Optional

TYPES = ("namespace", "workload", "service", "ingress", "serviceaccount", "networkpolicy",
         "configmap", "pdb", "hpa", "role", "secret", "storage", "certificate")
_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,40}[a-z0-9])?$")
_HOST = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,200}[a-z0-9])?$")
_IMAGE = re.compile(r"^[A-Za-z0-9._/:@-]{1,200}$")

DEFAULTS = {
    "workload": {"image": "nginxinc/nginx-unprivileged:1.27.2-alpine", "port": 8080, "replicas": 2,
                 "cpu": "250m", "memory": "256Mi", "serviceAccount": "", "env": [],
                 "writableRoot": False, "runAsRoot": False, "probes": True, "secretEnv": [], "reason": "",
                 "kind": "Deployment", "schedule": "0 2 * * *", "storage": "5Gi"},
    "service": {"port": 80, "kind": "ClusterIP", "target": "", "sourceRanges": [], "reason": ""},
    "ingress": {"host": "app.example.com", "tls": True, "target": "", "reason": ""},
    "serviceaccount": {"readsApi": False, "reason": ""},
    "networkpolicy": {"mode": "default-deny", "target": "", "from": "", "to": "", "port": "", "cidr": "",
                      "fromPod": "", "toPod": ""},
    "configmap": {"data": {}},
    "pdb": {"target": "", "minAvailable": 1},
    "hpa": {"target": "", "minReplicas": 2, "maxReplicas": 6, "cpuPercent": 70},
    "secret": {"store": "cluster-secret-store", "keys": [], "reason": ""},
    "storage": {"target": "", "size": "10Gi", "path": "/data", "storageClass": ""},
    "certificate": {"target": "", "issuer": "letsencrypt-prod"},
    "role": {"serviceAccount": "", "preset": "read-config",
             "rules": [{"resources": ["configmaps"], "verbs": ["get", "list", "watch"]}], "reason": ""},
    "namespace": {"psa": "restricted", "quotaCpu": "4", "quotaMemory": "8Gi", "reason": ""},
}

# What a service account may be granted, by the plain name a person knows. Each resource maps to
# its API group; anything not listed is refused, so a typo cannot silently become a wildcard.
_API_GROUPS = {
    **dict.fromkeys(("configmaps", "secrets", "pods", "pods/log", "pods/exec", "services", "endpoints",
                     "persistentvolumeclaims", "events", "serviceaccounts"), ""),
    **dict.fromkeys(("deployments", "statefulsets", "daemonsets", "replicasets"), "apps"),
    **dict.fromkeys(("jobs", "cronjobs"), "batch"),
    **dict.fromkeys(("ingresses", "networkpolicies"), "networking.k8s.io"),
    **dict.fromkeys(("roles", "rolebindings"), "rbac.authorization.k8s.io"),
    "leases": "coordination.k8s.io",
}
_VERBS = ("get", "list", "watch", "create", "update", "patch", "delete")
_READ = ("get", "list", "watch")
ROLE_PRESETS = {
    "read-config": {"label": "Read its ConfigMaps", "rules": [{"resources": ["configmaps"], "verbs": list(_READ)}]},
    "read-pods": {"label": "Read pods and services (discovery)", "rules": [
        {"resources": ["pods", "services", "endpoints"], "verbs": list(_READ)}]},
    "leader-election": {"label": "Leader election (leases)", "rules": [
        {"resources": ["leases"], "verbs": ["get", "list", "watch", "create", "update"]}]},
    "read-secrets": {"label": "Read Secrets (sensitive)", "rules": [{"resources": ["secrets"], "verbs": list(_READ)}]},
    "manage-workloads": {"label": "Manage Deployments (powerful)", "rules": [
        {"resources": ["deployments"], "verbs": list(_READ) + ["create", "update", "patch", "delete"]}]},
}
_SENSITIVE_RES = {"secrets", "pods/exec", "roles", "rolebindings", "serviceaccounts"}


def role_risks(c: dict) -> list[str]:
    """Why a role is more than least privilege, in a phrase a reviewer can read."""
    out = []
    for r in c.get("rules") or []:
        res, verbs = set(r.get("resources") or []), set(r.get("verbs") or [])
        if res & _SENSITIVE_RES and (verbs & set(_READ) or verbs - set(_READ)):
            out.append("reaches " + ", ".join(sorted(res & _SENSITIVE_RES)))
        if verbs - set(_READ):
            out.append("can change " + ", ".join(sorted(res)))
    return sorted(set(out))


WORKLOAD_KINDS = ("Deployment", "StatefulSet", "CronJob", "Job", "DaemonSet")
SERVING = ("Deployment", "StatefulSet")           # kinds that run continuously and can take traffic
_CRON = re.compile(r"^(\S+\s+){4}\S+$")
_SIZE = re.compile(r"^[1-9][0-9]{0,5}(Mi|Gi|Ti)$")

_S, _N = "s", "n"          # value kinds inside a chart: quoted string, bare number/bool


class BuildError(ValueError):
    """A sentence a person can act on; `component` names the card on the canvas to fix."""

    def __init__(self, message: str, component: str = ""):
        super().__init__(message)
        self.component = component


def _yaml():
    try:
        import yaml
        return yaml
    except ImportError as exc:                                  # pragma: no cover
        raise BuildError("The builder needs PyYAML: pip install pyyaml") from exc


def _norm(spec: dict, lenient: bool = False) -> dict:
    """Validate and fill defaults. Strict: raises BuildError with a sentence a new engineer can act on.
    Lenient: never raises. A bad field is replaced by its default and a bad component is skipped, and each
    is reported in `problems`, so the protections can be shown while the design is still half-built."""
    if not lenient:
        out = _norm_strict(spec)
        out["problems"] = []
        return out
    base = {k: v for k, v in (spec or {}).items() if k != "components"}
    problems: list = []
    fixes = (("app name", {"app": "my-app"}), ("namespace", {"namespace": ""}), ("registry", {"registries": ""}), ("pull secret", {"pullSecret": ""}),
             ("signing key", {"signing": {}}), ("Guardrails", {"guardrails": "warn"}), ("service mesh", {"transport": {}}), ("Encryption between", {"transport": {}}),
             ("issuer", {"transport": {}}))
    for _ in range(8):
        try:
            _norm_strict({**base, "components": []})
            break
        except BuildError as exc:
            problems.append({"component": "", "message": str(exc)})
            fixed = next((f for k, f in fixes if k in str(exc)), None)
            base.update(fixed or {"registries": "", "pullSecret": "", "signing": {}, "guardrails": "warn", "transport": {}})
    good: list = []
    for raw in (spec or {}).get("components") or []:
        try:
            _norm_strict({**base, "components": good + [raw]})
            good.append(raw)
        except BuildError as exc:
            problems.append({"component": getattr(exc, "component", "") or str((raw or {}).get("name", "")), "message": str(exc)})
        except (AttributeError, TypeError, KeyError):
            continue
    out = _norm_strict({**base, "components": good})
    out["problems"] = problems
    return out


def _norm_strict(spec: dict) -> dict:
    app = str(spec.get("app") or "my-app").strip()
    if not _NAME.match(app):
        raise BuildError("The app name must be lowercase letters, numbers and dashes (e.g. shop-api).")
    ns = str(spec.get("namespace") or app).strip()
    if not _NAME.match(ns):
        raise BuildError("The namespace must be lowercase letters, numbers and dashes.")
    comps, names = [], set()
    for raw in spec.get("components") or []:
        t = raw.get("type")
        if t not in TYPES:
            raise BuildError(f"Unknown component type '{t}'.")
        c = {**DEFAULTS[t], **{k: v for k, v in raw.items() if v is not None}}
        c["type"] = t
        c["name"] = str(c.get("name") or (app if t == "workload" else f"{app}-{t}")).strip()
        if not _NAME.match(c["name"]):
            raise BuildError(f"'{c['name']}': names use lowercase letters, numbers and dashes.")
        if t == "namespace":
            c["name"] = ns
        if t == "storage":
            if not _SIZE.match(str(c["size"])):
                raise BuildError(f"'{c['name']}': size looks like 10Gi or 500Mi.", c["name"])
            if not str(c["path"]).startswith("/") or ".." in str(c["path"]) or len(str(c["path"])) > 120:
                raise BuildError(f"'{c['name']}': the mount path is a folder inside the container, like /data.", c["name"])
        if t == "secret":
            for k in c.get("keys") or []:
                if not re.match(r"^[A-Za-z_][A-Za-z0-9_.-]{0,60}$", str(k.get("name", ""))) or not str(k.get("remote", "")).strip():
                    raise BuildError(f"The secret '{c['name']}': each key needs a name (like DB_PASSWORD) and the path in your secret store.", c["name"])
        if t == "role":
            for r in c.get("rules") or []:
                bad = [x for x in (r.get("resources") or []) if x not in _API_GROUPS]
                if bad or not r.get("resources"):
                    raise BuildError(f"The role '{c['name']}' names a resource we do not know ({', '.join(bad) or 'none given'}). "
                                     f"Use: {', '.join(sorted(_API_GROUPS))}. Wildcards are not allowed.", c["name"])
                badv = [v for v in (r.get("verbs") or []) if v not in _VERBS]
                if badv or not r.get("verbs"):
                    raise BuildError(f"The role '{c['name']}' uses a verb we do not allow ({', '.join(badv) or 'none given'}). "
                                     f"Use: {', '.join(_VERBS)}. Wildcards are not allowed.", c["name"])
        key = (t, c["name"])
        if key in names:
            raise BuildError(f"There are two {t} components called '{c['name']}'. Rename one.")
        names.add(key)
        if t == "workload":
            if c["kind"] not in WORKLOAD_KINDS:
                raise BuildError(f"'{c['name']}': a workload is a {', '.join(WORKLOAD_KINDS)}.", c["name"])
            if c["kind"] == "CronJob" and not _CRON.match(str(c["schedule"]).strip()):
                raise BuildError(f"'{c['name']}': a schedule has five parts, like 0 2 * * * (2am every day).", c["name"])
            if c["kind"] == "StatefulSet" and not _SIZE.match(str(c["storage"])):
                raise BuildError(f"'{c['name']}': storage looks like 5Gi or 500Mi.", c["name"])
            if c["kind"] not in SERVING:
                c["probes"] = False
            if not _IMAGE.match(str(c["image"])):
                raise BuildError(f"'{c['image']}' is not a valid image reference.")
            for k, lo, hi in (("port", 1, 65535), ("replicas", 1, 50)):
                try:
                    c[k] = int(c[k])
                except (TypeError, ValueError):
                    raise BuildError(f"{k} must be a number.")
                if not lo <= c[k] <= hi:
                    raise BuildError(f"{k} must be between {lo} and {hi}.")
        if t == "service":
            try:
                c["port"] = int(c["port"])
            except (TypeError, ValueError):
                raise BuildError("The service port must be a number.")
        if t == "ingress" and not _HOST.match(str(c["host"]).lower()):
            raise BuildError(f"'{c['host']}' is not a valid host name.")
        comps.append(c)
    regs = spec.get("registries") or []
    if isinstance(regs, str):
        regs = [x.strip() for x in regs.split(",")]
    regs = [x for x in regs if x]
    for r in regs:
        if not _IMAGE.match(r):
            raise BuildError(f"'{r}' is not a registry like registry.example.com/team.")
    g = spec.get("guardrails") or "warn"
    if g not in ("off", "warn", "deny"):
        raise BuildError("Guardrails must be off, warn or deny.")
    tr = spec.get("transport") or {}
    if isinstance(tr, str):
        tr = {"mode": tr}
    mode = str(tr.get("mode") or "")
    if mode not in ("", "mesh", "certs", "none"):
        raise BuildError("Encryption between services must be mesh, certs or none.")
    mesh = str(tr.get("mesh") or "linkerd")
    if mesh not in ("linkerd", "istio"):
        raise BuildError("The service mesh must be linkerd or istio.")
    issuer = str(tr.get("issuer") or "internal-ca")
    if not _NAME.match(issuer):
        raise BuildError("The certificate issuer name uses lowercase letters, numbers and dashes.")
    transport = {"mode": mode, "mesh": mesh, "issuer": issuer, "reason": str(tr.get("reason") or "").strip()}
    pull = str(spec.get("pullSecret") or "").strip()
    if pull and not _NAME.match(pull):
        raise BuildError("The image pull secret is a Secret name: lowercase letters, numbers and dashes.")
    sg = spec.get("signing") or {}
    key = str((sg if isinstance(sg, str) else sg.get("publicKey")) or "").strip()
    if key and not (key.startswith("-----BEGIN PUBLIC KEY-----") and key.endswith("-----END PUBLIC KEY-----") and len(key) < 2000):
        raise BuildError("The signing key must be a PEM public key (-----BEGIN PUBLIC KEY-----).")
    locks = [str(x) for x in (spec.get("locks") or [])]
    appr = {str(k): v for k, v in (spec.get("approvals") or {}).items() if isinstance(v, dict)}
    return {"app": app, "namespace": ns, "components": comps, "registries": regs, "guardrails": g,
            "locks": locks, "approvals": appr, "transport": transport, "pullSecret": pull, "signing": key}


def _loosens(c: dict) -> bool:
    """True when this component turns a safe default off on purpose."""
    t = c["type"]
    return bool((t == "namespace" and c.get("psa") != "restricted")
                or (t == "workload" and (c.get("runAsRoot") or c.get("writableRoot")))
                or (t == "service" and c.get("kind") != "ClusterIP")
                or (t == "ingress" and not c.get("tls"))
                or (t == "serviceaccount" and c.get("readsApi"))
                or (t == "role" and bool(role_risks(c))))


def _peer(c: dict, who: str, comps: list, pod_label: str) -> dict:
    """A policy peer: a pod on the canvas, or a namespace, optionally narrowed to one pod label
    inside it so the whole namespace is not trusted."""
    if any(x["type"] == "workload" and x["name"] == who for x in comps):
        return {"podSelector": {"matchLabels": {"app.kubernetes.io/name": who}}}
    peer = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": who}}}
    pod_label = str(pod_label or "").strip()
    if pod_label:
        if not _NAME.match(pod_label):
            raise BuildError(f"'{c['name']}': a pod label value uses lowercase letters, numbers and dashes.", c["name"])
        peer["podSelector"] = {"matchLabels": {"app.kubernetes.io/name": pod_label}}
    return peer


def _ports(c: dict):
    """The `ports:` list for an allow rule; empty means every port, which the layers call out."""
    raw = str(c.get("port") or "").strip()
    if not raw:
        return None
    out = []
    for part in raw.replace(" ", "").split(","):
        proto, _, num = part.rpartition("/")
        if not num.isdigit() or not 1 <= int(num) <= 65535 or proto.upper() not in ("", "TCP", "UDP"):
            raise BuildError(f"'{c['name']}': a port looks like 5432 or 53/UDP, not '{part}'.", c["name"])
        out.append({"protocol": (proto or "TCP").upper(), "port": int(num)})
    return out


def _ref(c: dict, kind: str, specs: list) -> str:
    """The component a Service / Ingress / policy points at; the only one of its kind if blank."""
    of = [x["name"] for x in specs if x["type"] == kind]
    t = c.get("target") or (of[0] if len(of) == 1 else "")
    if not t or t not in of:
        raise BuildError(f"The {c['type']} '{c['name']}' needs to point at one of your "
                         f"{'workloads' if kind == 'workload' else kind + 's'}; pick one.", c["name"])
    return t


def _labels(app: str, name: str) -> dict:
    return {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": app}


class _V:
    """Collects chart values as manifests are built; `v()` returns either the literal (for plain
    manifests) or a sentinel the chart writer turns into a `{{ .Values... }}` expression."""

    def __init__(self, chart: bool):
        self.chart, self.values = chart, {}

    def v(self, comp: str, field: str, value, kind=_S):
        self.values.setdefault(comp, {})[field] = value
        return f"@@{kind}:{comp}.{field}@@" if self.chart else value


def _build(spec: dict, chart: bool) -> tuple[list[dict], dict]:
    s = _norm(spec)
    app, ns, comps = s["app"], s["namespace"], s["components"]
    V = _V(chart)
    docs = []
    ns_label = "{{ .Release.Namespace }}" if chart else ns
    for c in comps:
        t, n = c["type"], c["name"]
        meta = {"name": n, "namespace": ns_label, "labels": _labels(app, n)}
        why = str(c.get("reason") or "").strip()
        if why and _loosens(c):
            meta["annotations"] = {"k8smatrixwarden.io/exception": why[:300]}
        if t == "namespace":
            nsmeta = {"name": n, "labels": {"pod-security.kubernetes.io/enforce": V.v(n, "psa", c["psa"]),
                                            "pod-security.kubernetes.io/warn": V.v(n, "psa", c["psa"]),
                                            "pod-security.kubernetes.io/audit": V.v(n, "psa", c["psa"]),
                                            "team": app}}
            if "annotations" in meta:
                nsmeta["annotations"] = dict(meta["annotations"])
            tr = s["transport"]
            if tr["mode"] == "mesh" and tr["mesh"] == "linkerd":
                nsmeta.setdefault("annotations", {}).update({
                    "linkerd.io/inject": "enabled", "config.linkerd.io/default-inbound-policy": "all-authenticated"})
            elif tr["mode"] == "mesh" and tr["mesh"] == "istio":
                nsmeta["labels"]["istio.io/dataplane-mode"] = "ambient"
            docs.append({"apiVersion": "v1", "kind": "Namespace", "metadata": nsmeta})
            docs.append({"apiVersion": "v1", "kind": "LimitRange",
                         "metadata": {"name": f"{n}-defaults", "namespace": n},
                         "spec": {"limits": [{"type": "Container",
                                              "default": {"cpu": "500m", "memory": "512Mi"},
                                              "defaultRequest": {"cpu": "50m", "memory": "64Mi"}}]}})
            docs.append({"apiVersion": "v1", "kind": "ResourceQuota",
                         "metadata": {"name": f"{n}-quota", "namespace": n},
                         "spec": {"hard": {"requests.cpu": V.v(n, "quotaCpu", str(c["quotaCpu"])),
                                           "requests.memory": V.v(n, "quotaMemory", str(c["quotaMemory"])),
                                           "limits.cpu": V.v(n, "quotaCpu", str(c["quotaCpu"])),
                                           "limits.memory": V.v(n, "quotaMemory", str(c["quotaMemory"]))}}})
        elif t == "workload":
            sa = c.get("serviceAccount")
            if sa and sa not in [x["name"] for x in comps if x["type"] == "serviceaccount"]:
                raise BuildError(f"'{n}' runs as service account '{sa}', which is not on the canvas. "
                                 "Add it, or clear the field.")
            if not sa:
                # Its own identity, with no token: a permission granted to the namespace's `default`
                # account (by anyone, ever) can never be inherited by this app.
                sa = n
                if not any(x["type"] == "serviceaccount" and x["name"] == n for x in comps):
                    docs.append({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": dict(meta),
                                 "automountServiceAccountToken": False})
            reads_api = bool(sa) and any(x["name"] == sa and x.get("readsApi") for x in comps
                                         if x["type"] == "serviceaccount")
            sc = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": not c["writableRoot"],
                  "capabilities": {"drop": ["ALL"]}}
            pod_sc = {"runAsNonRoot": not c["runAsRoot"], "seccompProfile": {"type": "RuntimeDefault"}}
            if not c["runAsRoot"]:
                pod_sc["runAsUser"] = 10001
            kind = c["kind"]
            serving = kind in SERVING
            container = {
                "name": "app", "image": V.v(n, "image", c["image"]),
                **({"ports": [{"containerPort": V.v(n, "port", c["port"], _N)}]} if serving else {}),
                "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                              "limits": {"cpu": V.v(n, "cpu", c["cpu"]), "memory": V.v(n, "memory", c["memory"])}},
                "securityContext": sc,
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]
                                + ([{"name": "data", "mountPath": "/data"}] if kind == "StatefulSet" else []),
            }
            env = [{"name": str(e["name"]), "value": str(e.get("value", ""))}
                   for e in c.get("env") or [] if e.get("name")]
            for e in c.get("secretEnv") or []:
                if e.get("name") and e.get("secret"):
                    env.append({"name": str(e["name"]), "valueFrom": {"secretKeyRef": {
                        "name": str(e["secret"]), "key": str(e.get("key") or e["name"])}}})
            tr = s["transport"]
            vols_extra = []
            if tr["mode"] == "certs" and serving:
                env += [{"name": "TLS_CERT_FILE", "value": "/etc/tls/tls.crt"}, {"name": "TLS_KEY_FILE", "value": "/etc/tls/tls.key"},
                        {"name": "TLS_CA_FILE", "value": "/etc/tls/ca.crt"}]
                container["volumeMounts"].append({"name": "tls", "mountPath": "/etc/tls", "readOnly": True})
                vols_extra.append({"name": "tls", "secret": {"secretName": f"{n}-internal-tls", "defaultMode": 0o440}})
                hosts = sorted({f"{x['name']}.{ns_label}.svc{suf}" for x in comps if x["type"] == "service" and x.get("target") == n
                                for suf in ("", ".cluster.local")} | ({f"{n}-headless.{ns_label}.svc", f"{n}-headless.{ns_label}.svc.cluster.local"} if kind == "StatefulSet" else set()))
                docs.append({"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
                             "metadata": {"name": f"{n}-internal", "namespace": ns_label, "labels": _labels(app, n)},
                             "spec": {"secretName": f"{n}-internal-tls", "dnsNames": hosts or [f"{n}.{ns_label}.svc"],
                                      "privateKey": {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"},
                                      "duration": "720h", "renewBefore": "240h",
                                      "issuerRef": {"name": tr["issuer"], "kind": "ClusterIssuer"}}})
            if env:
                container["env"] = env
            if c.get("probes"):
                probe = {"tcpSocket": {"port": V.v(n, "port", c["port"], _N)}, "periodSeconds": 10}
                container["readinessProbe"] = dict(probe, initialDelaySeconds=3)
                container["livenessProbe"] = dict(probe, initialDelaySeconds=15)
            pod = {"serviceAccountName": sa or None, "automountServiceAccountToken": reads_api,
                   "imagePullSecrets": [{"name": s["pullSecret"]}] if s["pullSecret"] else None,
                   "securityContext": pod_sc, "containers": [container],
                   "volumes": [{"name": "tmp", "emptyDir": {}}]}
            pod = {k: v for k, v in pod.items() if v is not None}
            for st in [x for x in comps if x["type"] == "storage" and x.get("target") == n]:
                pod["volumes"].append({"name": st["name"], "persistentVolumeClaim": {"claimName": st["name"]}})
                container["volumeMounts"].append({"name": st["name"], "mountPath": str(st["path"])})
            if serving and c["replicas"] > 1:
                pod["topologySpreadConstraints"] = [{"maxSkew": 1, "topologyKey": "kubernetes.io/hostname",
                                                      "whenUnsatisfiable": "ScheduleAnyway",
                                                      "labelSelector": {"matchLabels": {"app.kubernetes.io/name": n}}}]
            pod["volumes"] += vols_extra
            tmeta = {"labels": _labels(app, n)}
            if tr["mode"] == "mesh" and tr["mesh"] == "linkerd":
                # The injected proxy must meet the same limits the guardrail demands of every container.
                tmeta["annotations"] = {"config.linkerd.io/proxy-cpu-limit": "500m", "config.linkerd.io/proxy-memory-limit": "256Mi",
                                        "config.linkerd.io/proxy-cpu-request": "50m", "config.linkerd.io/proxy-memory-request": "64Mi"}
            tmpl = {"metadata": tmeta, "spec": pod}
            sel = {"matchLabels": {"app.kubernetes.io/name": n}}
            if kind == "Deployment":
                docs.append({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta,
                             "spec": {"replicas": V.v(n, "replicas", c["replicas"], _N), "selector": sel, "template": tmpl}})
            elif kind == "StatefulSet":
                docs.append({"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": meta,
                             "spec": {"replicas": V.v(n, "replicas", c["replicas"], _N), "selector": sel,
                                      "serviceName": f"{n}-headless", "template": tmpl,
                                      "volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {
                                          "accessModes": ["ReadWriteOnce"],
                                          "resources": {"requests": {"storage": V.v(n, "storage", c["storage"])}}}}]}})
                docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {**meta, "name": f"{n}-headless"},
                             "spec": {"clusterIP": "None", "selector": {"app.kubernetes.io/name": n},
                                      "ports": [{"port": V.v(n, "port", c["port"], _N)}]}})
            elif kind == "DaemonSet":
                docs.append({"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": meta,
                             "spec": {"selector": sel, "template": tmpl}})
            else:
                pod["restartPolicy"] = "OnFailure" if kind == "CronJob" else "Never"
                job = {"backoffLimit": 2, "ttlSecondsAfterFinished": 3600, "template": tmpl}
                if kind == "Job":
                    docs.append({"apiVersion": "batch/v1", "kind": "Job", "metadata": meta, "spec": job})
                else:
                    docs.append({"apiVersion": "batch/v1", "kind": "CronJob", "metadata": meta,
                                 "spec": {"schedule": V.v(n, "schedule", str(c["schedule"]).strip()),
                                          "concurrencyPolicy": "Forbid", "successfulJobsHistoryLimit": 3,
                                          "failedJobsHistoryLimit": 3, "jobTemplate": {"spec": job}}})
        elif t == "serviceaccount":
            docs.append({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta,
                         "automountServiceAccountToken": bool(c["readsApi"])})
        elif t == "service":
            tgt = _ref(c, "workload", comps)
            w = next(x for x in comps if x["type"] == "workload" and x["name"] == tgt)
            if w["kind"] not in SERVING:
                raise BuildError(f"The service '{n}' points at '{tgt}', which is a {w['kind']}. A Service needs an app that keeps running (Deployment or StatefulSet).", n)
            if c["kind"] not in ("ClusterIP", "LoadBalancer", "NodePort"):
                raise BuildError("Service type must be ClusterIP, LoadBalancer or NodePort.")
            docs.append({"apiVersion": "v1", "kind": "Service", "metadata": meta,
                         "spec": {"type": c["kind"], "selector": {"app.kubernetes.io/name": tgt},
                                  **({"loadBalancerSourceRanges": [str(x) for x in c["sourceRanges"]]}
                                     if c["kind"] == "LoadBalancer" and c.get("sourceRanges") else {}),
                                  "ports": [{"port": V.v(n, "port", c["port"], _N),
                                             "targetPort": V.v(tgt, "port", w["port"], _N)}]}})
        elif t == "ingress":
            svc = _ref(c, "service", comps)
            ing = {"rules": [{"host": V.v(n, "host", c["host"]),
                              "http": {"paths": [{"path": "/", "pathType": "Prefix",
                                                  "backend": {"service": {"name": svc, "port": {"number": next(
                                                      x["port"] for x in comps if x["type"] == "service" and x["name"] == svc)}}}}]}}]}
            if c["tls"]:
                ing["tls"] = [{"hosts": [V.v(n, "host", c["host"])], "secretName": f"{n}-tls"}]
            docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": meta, "spec": ing})
        elif t == "networkpolicy":
            mode = c["mode"]
            if mode == "default-deny":
                spec_ = {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
            elif mode == "allow-dns":
                spec_ = {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{
                    "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                    "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}]}
            elif mode == "allow-to":
                tgt = _ref(c, "workload", comps)
                dst = c.get("to") or ""
                if not dst:
                    raise BuildError(f"'{n}': say which workload or namespace '{tgt}' may call.")
                peer = _peer(c, dst, comps, c.get("toPod"))
                rule = {"to": [peer]}
                if _ports(c):
                    rule["ports"] = _ports(c)
                spec_ = {"podSelector": {"matchLabels": {"app.kubernetes.io/name": tgt}},
                         "policyTypes": ["Egress"], "egress": [rule]}
            elif mode == "allow-egress-cidr":
                tgt = _ref(c, "workload", comps)
                cidr = str(c.get("cidr") or "").strip()
                import ipaddress
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    raise BuildError(f"'{n}': '{cidr}' is not an address range like 203.0.113.0/24.", n)
                if net.prefixlen == 0:
                    raise BuildError(f"'{n}': 0.0.0.0/0 is the whole internet; name the range the app really calls.", n)
                rule = {"to": [{"ipBlock": {"cidr": str(net)}}]}
                if _ports(c):
                    rule["ports"] = _ports(c)
                spec_ = {"podSelector": {"matchLabels": {"app.kubernetes.io/name": tgt}},
                         "policyTypes": ["Egress"], "egress": [rule]}
            elif mode == "allow-from":
                tgt = _ref(c, "workload", comps)
                frm = c.get("from") or ""
                if not frm:
                    raise BuildError(f"'{n}': say which workload or namespace may reach '{tgt}'.")
                peer = _peer(c, frm, comps, c.get("fromPod"))
                rule = {"from": [peer]}
                if _ports(c):
                    rule["ports"] = _ports(c)
                spec_ = {"podSelector": {"matchLabels": {"app.kubernetes.io/name": tgt}},
                         "policyTypes": ["Ingress"], "ingress": [rule]}
            else:
                raise BuildError(f"'{n}': unknown network rule '{mode}'.")
            docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta,
                         "spec": spec_})
        elif t == "configmap":
            docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta,
                         "data": {str(k): str(v) for k, v in (c.get("data") or {}).items()}})
        elif t == "hpa":
            tgt = _ref(c, "workload", comps)
            docs.append({"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": meta,
                         "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": next(x["kind"] for x in comps if x["type"] == "workload" and x["name"] == tgt), "name": tgt},
                                  "minReplicas": V.v(n, "minReplicas", int(c["minReplicas"]), _N),
                                  "maxReplicas": V.v(n, "maxReplicas", int(c["maxReplicas"]), _N),
                                  "metrics": [{"type": "Resource", "resource": {"name": "cpu", "target": {
                                      "type": "Utilization", "averageUtilization": V.v(n, "cpuPercent", int(c["cpuPercent"]), _N)}}}]}})
        elif t == "storage":
            tgt = _ref(c, "workload", comps)
            w = next(x for x in comps if x["type"] == "workload" and x["name"] == tgt)
            if w["kind"] in ("StatefulSet", "CronJob", "Job", "DaemonSet"):
                raise BuildError(f"The storage '{n}' points at '{tgt}', a {w['kind']}. Attach storage to a Deployment; a StatefulSet already gets its own disk.", n)
            pvc = {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": V.v(n, "size", c["size"])}}}
            if c.get("storageClass"):
                pvc["storageClassName"] = str(c["storageClass"])
            docs.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": meta, "spec": pvc})
        elif t == "certificate":
            ing = _ref(c, "ingress", comps)
            host = next(x["host"] for x in comps if x["type"] == "ingress" and x["name"] == ing)
            docs.append({"apiVersion": "cert-manager.io/v1", "kind": "Certificate", "metadata": meta,
                         "spec": {"secretName": f"{ing}-tls", "dnsNames": [str(host)],
                                  "issuerRef": {"name": V.v(n, "issuer", str(c["issuer"])), "kind": "ClusterIssuer"}}})
        elif t == "secret":
            if not c.get("keys"):
                raise BuildError(f"The secret '{n}' lists no keys; add at least one.", n)
            docs.append({"apiVersion": "external-secrets.io/v1beta1", "kind": "ExternalSecret", "metadata": meta,
                         "spec": {"refreshInterval": "1h",
                                  "secretStoreRef": {"name": c["store"], "kind": "ClusterSecretStore"},
                                  "target": {"name": n, "creationPolicy": "Owner"},
                                  "data": [{"secretKey": str(k["name"]), "remoteRef": {"key": str(k["remote"]).strip()}}
                                           for k in c["keys"]]}})
        elif t == "role":
            sa = c.get("serviceAccount") or ""
            if sa not in [x["name"] for x in comps if x["type"] == "serviceaccount"]:
                raise BuildError(f"The role '{n}' needs a service account on the canvas to give permissions to; pick one.", n)
            rules = [{"apiGroups": [_API_GROUPS[res]], "resources": [res], "verbs": list(r["verbs"])}
                     for r in c["rules"] for res in r["resources"]]
            docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta, "rules": rules})
            docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                         "metadata": {**meta, "name": f"{n}-binding"},
                         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": n},
                         "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": ns_label}]})
        elif t == "pdb":
            tgt = _ref(c, "workload", comps)
            docs.append({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": meta,
                         "spec": {"minAvailable": V.v(n, "minAvailable", int(c["minAvailable"]), _N),
                                  "selector": {"matchLabels": {"app.kubernetes.io/name": tgt}}}})
    docs += _signing_docs(s, ns_label)
    docs += _mesh_docs(s, ns_label)
    docs += _guardrails(s, ns_label)
    return docs, V.values


def _signing_docs(s: dict, ns_label) -> list[dict]:
    """A Kyverno policy that refuses any image in the namespace not signed with your cosign key.
    Artifactory stores the signatures next to the image; the cluster checks them at admission."""
    if not s["signing"]:
        return []
    refs = [f"{r.rstrip('/')}/*" for r in s["registries"]] or ["*"]
    return [{"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy", "metadata": {"name": f"{s['namespace']}-verify-images"},
             "spec": {"validationFailureAction": "Enforce", "webhookTimeoutSeconds": 30, "rules": [{
                 "name": "verify-signature",
                 "match": {"any": [{"resources": {"kinds": ["Pod"], "namespaces": [ns_label]}}]},
                 "verifyImages": [{"imageReferences": refs, "mutateDigest": True,
                                   "attestors": [{"entries": [{"keys": {"publicKeys": s["signing"]}}]}]}]}]}}]


def _mesh_docs(s: dict, ns_label) -> list[dict]:
    """Istio ambient: every call between pods in the namespace is mutual TLS, and each allow rule
    becomes an identity rule (this service account, not "anything with the right label")."""
    tr = s["transport"]
    if tr["mode"] != "mesh" or tr["mesh"] != "istio":
        return []
    comps = s["components"]
    out = [{"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication",
            "metadata": {"name": "default", "namespace": ns_label}, "spec": {"mtls": {"mode": "STRICT"}}}]
    wl = {c["name"]: c for c in comps if c["type"] == "workload"}
    sa_of = lambda w: w.get("serviceAccount") or w["name"]                     # noqa: E731
    for c in comps:
        if c["type"] != "networkpolicy" or c["mode"] != "allow-from" or c.get("target") not in wl:
            continue
        src = c.get("from") or ""
        if src in wl:
            source = {"principals": [f"cluster.local/ns/{ns_label}/sa/{sa_of(wl[src])}"]}
        else:
            source = {"namespaces": [src]}
        rule = {"from": [{"source": source}]}
        if _ports(c):
            rule["to"] = [{"operation": {"ports": [str(p["port"]) for p in _ports(c)]}}]
        out.append({"apiVersion": "security.istio.io/v1", "kind": "AuthorizationPolicy",
                    "metadata": {"name": c["name"], "namespace": ns_label},
                    "spec": {"selector": {"matchLabels": {"app.kubernetes.io/name": c["target"]}},
                             "action": "ALLOW", "rules": [rule]}})
    return out


def _guardrails(s: dict, ns_label) -> list[dict]:
    """A ValidatingAdmissionPolicy built from THIS design, so the cluster itself refuses a pod that
    drops a control the design promised. Same idea as a per-workload request validator: the safe
    fields are pinned, and a control the design loosened on purpose is left out of the policy."""
    mode = s["guardrails"]
    if mode == "off":
        return []
    wl = [c for c in s["components"] if c["type"] == "workload"]
    root = any(c["runAsRoot"] for c in wl)
    writable = any(c["writableRoot"] for c in wl)
    def over(body: str, ephemeral: bool = False) -> str:
        """The same test on every kind of container a pod can carry, so a hostile init or debug
        container cannot do what the main container is forbidden to."""
        parts = [f"object.spec.containers.all(c, {body})",
                 f"(!has(object.spec.initContainers) || object.spec.initContainers.all(c, {body}))"]
        if ephemeral:
            parts.append(f"(!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, {body}))")
        return " && ".join(parts)

    rules = [
        ("no-privileged", over("!has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false", True),
         "Privileged containers are not allowed."),
        ("no-host-namespaces", "(!has(object.spec.hostNetwork) || !object.spec.hostNetwork) && (!has(object.spec.hostPID) || !object.spec.hostPID) && (!has(object.spec.hostIPC) || !object.spec.hostIPC)",
         "Host network, PID and IPC sharing are not allowed."),
        ("no-host-path", "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))",
         "hostPath volumes are not allowed."),
        ("no-privilege-escalation", over("has(c.securityContext) && has(c.securityContext.allowPrivilegeEscalation) && c.securityContext.allowPrivilegeEscalation == false"),
         "Containers must set allowPrivilegeEscalation: false."),
        ("drop-all-capabilities", over("has(c.securityContext) && has(c.securityContext.capabilities) && has(c.securityContext.capabilities.drop) && 'ALL' in c.securityContext.capabilities.drop"),
         "Containers must drop all Linux capabilities."),
        ("resource-limits", over("has(c.resources) && has(c.resources.limits)"),
         "Containers must set CPU and memory limits."),
        ("fixed-image-tag", over("!c.image.endsWith(':latest') && (c.image.contains('@') || c.image.split('/')[c.image.split('/').size() - 1].contains(':'))", True),
         "Images must use a fixed tag or a digest, never latest."),
    ]
    if not root:
        rules.append(("run-as-non-root", over("(has(c.securityContext) && has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot) || (has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot)"),
                      "Containers must run as a non-root user."))
    if not writable:
        rules.append(("read-only-root", over("has(c.securityContext) && has(c.securityContext.readOnlyRootFilesystem) && c.securityContext.readOnlyRootFilesystem == true"),
                      "Containers must use a read-only root filesystem."))
    if s["registries"]:
        starts = " || ".join(f"c.image.startsWith('{r.rstrip('/')}/')" for r in s["registries"])
        rules.append(("trusted-registry", over(starts, True), "Images must come from a trusted registry."))
    name = f"{s['namespace']}-guardrails"
    return [
        {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
         "metadata": {"name": name, "labels": {"app.kubernetes.io/part-of": s["app"]},
                      "annotations": {"k8smatrixwarden.io/note": "Built from the design. Needs Kubernetes 1.30 or later. "
                                                                 "Loosened controls are left out on purpose."}},
         "spec": {"failurePolicy": "Fail",
                  "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                          "operations": ["CREATE", "UPDATE"], "resources": ["pods", "pods/ephemeralcontainers"]}]},
                  "validations": [{"expression": e, "message": m, "reason": "Invalid"} for _, e, m in rules]}},
        {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
         "metadata": {"name": name, "labels": {"app.kubernetes.io/part-of": s["app"]}},
         "spec": {"policyName": name,
                  "validationActions": ["Deny"] if mode == "deny" else ["Warn", "Audit"],
                  "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns_label}}}}},
    ]


_ORDER = ["Namespace", "LimitRange", "ResourceQuota", "ServiceAccount", "NetworkPolicy", "ExternalSecret",
          "ConfigMap", "PersistentVolumeClaim", "Role", "RoleBinding", "Service", "StatefulSet", "Deployment",
          "DaemonSet", "CronJob", "Job", "Ingress", "Certificate", "PodDisruptionBudget",
          "HorizontalPodAutoscaler", "PeerAuthentication", "AuthorizationPolicy", "ClusterPolicy",
          "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"]


def _in_install_order(docs: list[dict]) -> list[dict]:
    """The namespace and its fences first, workloads after, the guardrail binding last, so a plain
    `kubectl apply -f` works in file order the same way Helm's own ordering does."""
    rank = {k: i for i, k in enumerate(_ORDER)}
    return sorted(docs, key=lambda d: rank.get(d["kind"], len(_ORDER)))


def _dump(doc: dict) -> str:
    """YAML with every value written out: no `&id001` / `*id001` aliases for a shared dict."""
    y = _yaml()

    class _Plain(y.SafeDumper):
        def ignore_aliases(self, data):
            return True
    return y.dump(doc, Dumper=_Plain, sort_keys=False, default_flow_style=False)


def manifests(spec: dict) -> list[dict]:
    return _in_install_order(_build(spec, chart=False)[0])


def manifests_yaml(spec: dict) -> str:
    y = _yaml()
    return "---\n".join(_dump(d) for d in manifests(spec))


_SENT = re.compile(r"""['"]?@@([sn]):([^@]+)@@['"]?""")


def chart_files(spec: dict) -> dict[str, str]:
    """A Helm chart: Chart.yaml, values.yaml, one template per component, NOTES.txt."""
    y = _yaml()
    s = _norm(spec)
    docs, values = _build(spec, chart=True)
    files = {
        "Chart.yaml": y.safe_dump({"apiVersion": "v2", "name": s["app"], "version": "0.1.0",
                                   "appVersion": "1.0.0", "type": "application",
                                   "description": f"{s['app']}: built with K8sMatrixWarden's builder"},
                                  sort_keys=False),
        "values.yaml": "# Change these, not the templates.\n" + y.safe_dump(values, sort_keys=False),
    }
    for d in docs:
        kind, name = d["kind"], d["metadata"]["name"]
        text = _dump(d)
        text = _SENT.sub(lambda m: "{{ .Values.%s%s }}" % (
            ".".join(m.group(2).split(".")), " | quote" if m.group(1) == _S else ""), text)
        text = text.replace("'{{ .Release.Namespace }}'", "{{ .Release.Namespace }}")
        files[f"templates/{kind.lower()}-{name}.yaml"] = text
    files["templates/NOTES.txt"] = (f"Installed {s['app']}.\n  kubectl -n {{{{ .Release.Namespace }}}} get all\n")
    return files


def chart_tgz(spec: dict) -> bytes:
    s = _norm(spec)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, text in chart_files(spec).items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(f"{s['app']}/{path}")
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def install_command(spec: dict) -> str:
    s = _norm(spec)
    has_ns = any(c["type"] == "namespace" for c in s["components"])
    return (f"helm lint ./{s['app']}\n"
            f"helm install {s['app']} ./{s['app']} --namespace {s['namespace']} --create-namespace"
            + ("" if not has_ns else "   # the chart also creates the namespace; drop --create-namespace if that conflicts"))


def _with_pods(docs: list[dict]) -> list[dict]:
    """One pod per controller, so the scanner's network and exposure analysis (which reads pods) sees the
    design. Findings do not double: they group under the owning workload by ownerReference."""
    out = list(docs)
    for d in docs:
        if d["kind"] in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            t = d["spec"]["template"] if d["kind"] != "CronJob" else d["spec"]["jobTemplate"]["spec"]["template"]
            md = d["metadata"]
            out.append({"apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": f"{md['name']}-0", "namespace": md["namespace"], "labels": dict(t["metadata"]["labels"]),
                                     "ownerReferences": [{"kind": d["kind"], "name": md["name"], "controller": True}]},
                        "spec": t["spec"]})
    return out


def analyze(spec: dict, platform):
    """Run the scanner on exactly what the spec produces; the result carries the findings, the risk and the
    evaluated network topology (who can really reach whom once every policy is applied)."""
    from ..agents.scanner import ScannerAgent
    from .manifests import MANIFEST_MODULES, ManifestEvidenceCollector
    from .models import ScanRequest, Selector
    col = ManifestEvidenceCollector.from_docs(_with_pods(manifests(spec)), label="builder")
    return ScannerAgent(platform).scan(ScanRequest(selector=Selector(modules=list(MANIFEST_MODULES))),
                                       col, mode_label="manifests")


def check(spec: dict, platform, result=None) -> dict:
    """Run the scanner's rules on what the spec produces and map findings back to components."""
    from .remediation import fix_for
    result = result or analyze(spec, platform)
    items = []
    for i in sorted(result.workload_issues, key=lambda i: -i.get("score", 0)):
        items.append({"severity": i["severity"], "title": i["title"], "rule": i["rule_id"],
                      "where": i["workload"], "component": i["workload_name"],
                      "score": round(i.get("score", 0), 1), "fix": fix_for(i["rule_id"]).get("how", "")})
    r = result.risk
    return {"rating": r.rating, "risk": r.cluster_risk, "issues": items, "counts": result.counts,
            "ok": not any(i["severity"] in ("CRITICAL", "HIGH") for i in items)}


# ---- threat model: each protection answers one attacker goal ---------------------------------
TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Lateral Movement", "Command and Control", "Impact"]
_THREATS = {
    "ns-fence": ("Privilege Escalation", "Someone with rights in this namespace cannot start privileged pods or reach into other teams' workloads."),
    "quota": ("Impact", "An abused or runaway workload cannot starve the rest of the cluster."),
    "default-deny": ("Lateral Movement", "After one pod is breached, the attacker cannot scan or call the other pods."),
    "dns-egress": ("Impact", "Name lookups keep working, so default-deny does not turn into an outage."),
    "egress-declared": ("Command and Control", "A breached pod cannot phone home, download tools or send data out."),
    "ports-named": ("Lateral Movement", "A permitted caller can reach only the one port it needs."),
    "narrow-peers": ("Lateral Movement", "Only the named pod is trusted, not every pod that will ever run in that namespace."),
    "netpol-enforced": ("Lateral Movement", "The network rules are actually applied by the cluster, not silently ignored."),
    "ingress-path": ("Initial Access", "Only the ingress controller can reach the app; no other pod can probe it."),
    "tls": ("Credential Access", "Logins and sessions cannot be read or altered on the way in."),
    "certificate": ("Impact", "An expired certificate does not take the site down or train users to click through warnings."),
    "no-public-service": ("Initial Access", "The app is not reachable from the internet except through the ingress you designed."),
    "non-root": ("Privilege Escalation", "A break-out lands as an unprivileged user, not root on the node."),
    "read-only-fs": ("Persistence", "An attacker cannot drop tools or change the app's files inside the container."),
    "drop-caps": ("Privilege Escalation", "No extra Linux powers to abuse for a container escape."),
    "seccomp": ("Privilege Escalation", "Dangerous system calls used by kernel exploits are filtered out."),
    "limits": ("Impact", "A bug or attack cannot consume the whole node."),
    "no-token": ("Credential Access", "A stolen pod has no token to talk to the Kubernetes API."),
    "api-role": ("Privilege Escalation", "API access is a named, reviewed list, not an unbounded default."),
    "least-privilege-rbac": ("Privilege Escalation", "A stolen token can do only what the Role lists."),
    "dedicated-identity": ("Privilege Escalation", "Permissions granted to the shared default account are never inherited."),
    "probes": ("Impact", "Hung copies are restarted and kept out of rotation."),
    "secrets": ("Credential Access", "Passwords do not end up in Git, in chart values, or in `kubectl get`."),
    "secrets-managed": ("Credential Access", "Secrets live in your vault with its own access policy and rotation."),
    "image-tag": ("Initial Access", "Tomorrow's deploy is the image you reviewed, not whatever the tag points to."),
    "image-digest": ("Initial Access", "The image cannot be swapped after review, even by someone who controls the registry tag."),
    "private-registry-auth": ("Initial Access", "Images come only from the internal registry, authenticated, not from a public fallback."),
    "image-signed": ("Initial Access", "Only images signed in your pipeline can run, even if the registry itself is tampered with."),
    "trusted-registry": ("Initial Access", "Only images from registries you control or vetted can run."),
    "pdb": ("Impact", "Maintenance or a drain cannot take every copy down at once."),
    "hpa": ("Impact", "A traffic spike, or a flood, scales out instead of causing an outage."),
    "service-encryption": ("Lateral Movement", "Traffic between services cannot be read or changed by something on the network, and a rogue pod cannot pretend to be a service."),
    "guardrails": ("Defense Evasion", "A later edit or a different pipeline cannot quietly remove a control; the cluster refuses the pod."),
}
#: What a design like this cannot do. Shown beside the protections so "secure by design" is not read as "secure".
RESIDUAL = [
    "A vulnerable or malicious application still runs inside the locked box. Scan the image and the app's own dependencies.",
    "Attacks while the app runs are not detected here. Pair this with runtime monitoring such as Falco.",
    "Image signatures are not verified. The registry and the build pipeline are trusted.",
    "Nodes, the Kubernetes API server and cluster administrators are outside this design.",
    "Web-layer protection (login, WAF, rate limiting) is not generated; that belongs at the ingress or in the app.",
    "Secrets are only as safe as the vault and the access policy on it.",
]


#: Which kind of component each protection is about, so the editor can show "security for this component" while it is edited.
_LAYER_TYPES = {
    "ns-fence": ["namespace"], "quota": ["namespace"], "guardrails": ["namespace"],
    "default-deny": ["networkpolicy"], "dns-egress": ["networkpolicy", "workload"], "egress-declared": ["networkpolicy", "workload"],
    "ports-named": ["networkpolicy"], "narrow-peers": ["networkpolicy"], "netpol-enforced": ["networkpolicy"], "ingress-path": ["networkpolicy", "ingress"],
    "tls": ["ingress"], "certificate": ["ingress", "certificate"], "no-public-service": ["service"], "service-encryption": ["service", "workload"],
    "non-root": ["workload"], "read-only-fs": ["workload"], "drop-caps": ["workload"], "seccomp": ["workload"], "limits": ["workload"], "probes": ["workload"],
    "dedicated-identity": ["workload", "serviceaccount"], "no-token": ["serviceaccount", "workload"], "api-role": ["serviceaccount", "role"],
    "least-privilege-rbac": ["role"], "secrets": ["workload", "secret"], "secrets-managed": ["workload", "secret"],
    "image-tag": ["workload"], "image-digest": ["workload"], "trusted-registry": ["workload"], "image-signed": ["workload"], "private-registry-auth": ["workload"],
    "pdb": ["pdb", "workload"], "hpa": ["hpa", "workload"],
}


# ---- security layers: what protects this design, and what is missing -------------------------
_SECRETISH = re.compile(r"(PASS|SECRET|TOKEN|KEY|CREDENTIAL)", re.I)


def layers(spec: dict, env: Optional[dict] = None) -> dict:
    """The security layers a design has, in plain words, each `on`, `off` or `loosened`.
    An `off` layer carries the component that adds it, so one click closes the gap. Never refuses a
    half-built design: what cannot be understood yet comes back in `problems`."""
    s = _norm(spec, lenient=True)
    cs = s["components"]
    of = lambda t: [c for c in cs if c["type"] == t]           # noqa: E731
    wl, pols = of("workload"), of("networkpolicy")
    out = []

    def add(id_, title, why, status, detail="", fix=None, optional=False, group=""):
        out.append({"id": id_, "title": title, "why": why, "status": status, "detail": detail,
                    "add": fix, "optional": optional, "group": group})

    ns = next(iter(of("namespace")), None)
    add("ns-fence", "Fenced-off namespace", "A breach in this app cannot spill into other teams' workloads, and Pod Security refuses risky pods.",
        ("on" if ns and ns["psa"] == "restricted" else "loosened" if ns else "off"),
        (f"Pod Security: {ns['psa']}" if ns else "no Namespace component"), None if ns else {"type": "namespace"}, group="Namespace")
    add("quota", "Resource quota", "One runaway or abused app cannot starve the whole cluster.",
        "on" if ns else "off", "" if ns else "comes with the Namespace component", group="Namespace")

    deny = [p for p in pols if p["mode"] == "default-deny"]
    add("default-deny", "Block all traffic by default", "Nothing can reach your app, or be reached by it, unless you allow it.",
        "on" if deny else "off", "", None if deny else {"type": "networkpolicy", "name": "default-deny", "mode": "default-deny"}, group="Network")
    if deny and wl:
        dns = any(p["mode"] == "allow-dns" for p in pols)
        add("dns-egress", "Allow name lookups (DNS)", "With all outbound traffic blocked, your app cannot even resolve a host name.",
            "on" if dns else "off", "", None if dns else {"type": "networkpolicy", "name": "allow-dns", "mode": "allow-dns"}, group="Network")
    tr = s["transport"]
    if of("service") or any(p["mode"] in ("allow-from", "allow-to") for p in pols):
        e = env or {}
        scanned = bool(e.get("scanned"))
        if e.get("mesh"):
            rec = f"Your cluster already runs {e['mesh']}: using it needs no app changes."
        elif e.get("certmanager"):
            rec = "cert-manager is installed: each app can get its own certificate."
        elif scanned:
            rec = "No service mesh or cert-manager was found in your cluster. The simplest path is Linkerd: it encrypts and authenticates every call between services with no app changes."
        else:
            rec = "Scan your cluster so this can see what it runs. The simplest path is Linkerd: it encrypts and authenticates every call between services with no app changes."
        mode, fix = tr["mode"], None
        if mode == "":
            st, det = "off", "not chosen yet. " + rec
        elif mode == "mesh":
            if ns is None:
                st, det = "off", "a service mesh is switched on per namespace, so add a Namespace component (offered above)"
            elif scanned and e.get("mesh") != tr["mesh"]:
                how = ("linkerd install-cni | kubectl apply -f -  then  linkerd install --crds | kubectl apply -f -  then  linkerd install --linkerd-cni-enabled | kubectl apply -f -"
                       if tr["mesh"] == "linkerd" else "istioctl install --set profile=ambient")
                st, det = "off", f"{tr['mesh']} was not found in your cluster. Install it first: {how}"
            else:
                st = "on"
                det = (f"{tr['mesh']}: every call is mutual TLS" + ("" if scanned else " (assumes it is installed)")
                       + ("; install it with its CNI mode so the Pod Security fence still applies" if tr["mesh"] == "linkerd" else "; ambient mode, no sidecars"))
        elif mode == "certs":
            if scanned and not e.get("certmanager"):
                st, det = "off", ("cert-manager was not found in your cluster. Install it first: helm install cert-manager jetstack/cert-manager "
                                  "-n cert-manager --create-namespace --set crds.enabled=true, then create a ClusterIssuer named " + tr["issuer"])
            else:
                st = "on"
                det = "each app gets its own certificate and must serve HTTPS with it; who may call is limited by the network rules" + ("" if scanned else " (assumes cert-manager is installed)")
        else:
            st, det = "loosened", "traffic between services is not encrypted"
        add("service-encryption", "Calls between services are encrypted", "Without it, anything on the network path (a compromised node or pod) can read or change traffic, and a rogue pod can pretend to be a service.",
            st, det, fix, group="Encryption")
        out[-1]["choices"] = [
            {"label": "Use a service mesh (Linkerd): easiest", "set": {"mode": "mesh", "mesh": "linkerd"}, "recommended": not e.get("mesh") and not e.get("certmanager") or e.get("mesh") == "linkerd"},
            {"label": "Use a service mesh (Istio ambient)", "set": {"mode": "mesh", "mesh": "istio"}, "recommended": e.get("mesh") == "istio"},
            {"label": "Give each app its own certificate (cert-manager)", "set": {"mode": "certs"}, "recommended": bool(e.get("certmanager")) and not e.get("mesh")},
            {"label": "Skip, with a reason", "set": {"mode": "none"}, "recommended": False}]
    if deny and wl:
        callers = [p for p in pols if p["mode"] in ("allow-to", "allow-egress-cidr")]
        silent = [w["name"] for w in wl if not any(p.get("target") == w["name"] for p in callers)]
        add("egress-declared", "Outbound calls are listed", "With outbound blocked, the app can only call what you name here. Anything it needs (database, API) must be declared, or it fails; anything not declared is blocked for an attacker too.",
            "off" if silent else "on", ("nothing declared for " + ", ".join(silent) + " (only DNS works)") if silent else "",
            {"type": "networkpolicy", "name": f"{silent[0]}-egress", "mode": "allow-to", "target": silent[0]} if silent else None,
            optional=True, group="Network")
    if wl:
        add("dedicated-identity", "Each app has its own identity", "A permission someone later grants to the namespace's default account can never be inherited by this app.",
            "on", "", group="App")
    if deny:
        wide = [p["name"] for p in pols if p["mode"] in ("allow-from", "allow-to")
                and not any(x["type"] == "workload" and x["name"] == (p.get("from") if p["mode"] == "allow-from" else p.get("to")) for x in wl)
                and not str(p.get("fromPod" if p["mode"] == "allow-from" else "toPod") or "").strip()]
        add("narrow-peers", "Rules name a pod, not a whole namespace", "Trusting a namespace trusts every pod that will ever run in it.",
            "off" if wide else "on", ("whole namespace: " + ", ".join(wide)) if wide else "", None, optional=True, group="Network")
        cni = (env or {}).get("cni")
        enforcing = cni in ("calico", "cilium", "antrea", "weave", "kube-router")
        add("netpol-enforced", "Your cluster enforces network rules", "A NetworkPolicy does nothing on a network plugin that ignores it, and nothing warns you.",
            "on" if enforcing else "off",
            (f"{cni} enforces them" if enforcing else (f"{cni} does not enforce NetworkPolicy" if cni else "could not confirm which network plugin the cluster uses; scan the cluster, or check Calico/Cilium is installed")),
            None, optional=True, group="Network")
    if deny:
        open_ports = [p["name"] for p in pols if p["mode"] in ("allow-from", "allow-to", "allow-egress-cidr") and not str(p.get("port") or "").strip()]
        add("ports-named", "Rules name a port", "An allow rule without a port opens every port on the target.",
            "off" if open_ports else "on", ("any port: " + ", ".join(open_ports)) if open_ports else "", None, group="Network")
    add("guardrails", "The cluster enforces this design", "An admission policy built from the design refuses pods that drop a control, so a later edit or a different pipeline cannot quietly undo it.",
        "on" if s["guardrails"] != "off" else "off",
        {"deny": "blocks violations", "warn": "warns on violations; switch to deny to block", "off": "turned off"}[s["guardrails"]], group="Enforcement")
    ings = of("ingress")
    if deny and ings:
        svc_to_wl = {x["name"]: x.get("target") for x in of("service")}
        need = sorted({svc_to_wl.get(i.get("target")) for i in ings} - {None, ""})
        wl_names = {w["name"] for w in wl}
        open_for = {p["target"] for p in pols if p["mode"] == "allow-from" and p.get("from") not in wl_names}
        missing = [w for w in need if w not in open_for]
        add("ingress-path", "Let the ingress controller reach the app", "Blocking everything also blocks your own front door; allow only the ingress controller's namespace.",
            "off" if missing else "on", ("missing for " + ", ".join(missing)) if missing else "",
            {"type": "networkpolicy", "name": f"allow-ingress-{missing[0]}", "mode": "allow-from",
             "target": missing[0], "from": "ingress-nginx", "fromPod": "ingress-nginx",
             "port": str(next((w["port"] for w in wl if w["name"] == missing[0]), ""))} if missing else None, group="Network")
    certs = {c.get("target") for c in of("certificate")}
    nocert = [i["name"] for i in ings if i.get("tls") and i["name"] not in certs]
    if ings and any(i.get("tls") for i in ings):
        add("certificate", "Certificate is issued and renewed for you", "A hand-made TLS secret expires and breaks the site; cert-manager renews it before it does.",
            "off" if nocert else "on", ("no certificate for " + ", ".join(nocert)) if nocert else "",
            {"type": "certificate", "name": f"{nocert[0]}-cert", "target": nocert[0]} if nocert else None, optional=True, group="Network")
    if ings:
        notls = [i["name"] for i in ings if not i.get("tls")]
        add("tls", "HTTPS only", "Traffic and logins cannot be read or altered on the way in.",
            "loosened" if notls else "on", ("no HTTPS on " + ", ".join(notls)) if notls else "", group="Network")
    exposed = [x["name"] for x in of("service") if x["kind"] != "ClusterIP"]
    if of("service"):
        add("no-public-service", "Internal-only services", "A Service on a public address is reachable by anyone unless something else stops them.",
            "loosened" if exposed else "on", ("public: " + ", ".join(exposed)) if exposed else "", group="Network")

    sa_api = [x["name"] for x in of("serviceaccount") if x.get("readsApi")]
    if wl or of("serviceaccount"):
        add("no-token", "No cluster API token", "A stolen pod cannot talk to the Kubernetes API.",
            "loosened" if sa_api else "on", ("API access: " + ", ".join(sa_api)) if sa_api else "", group="App")
    roles = of("role")
    sa_with_role = {r.get("serviceAccount") for r in roles}
    lonely = [x["name"] for x in of("serviceaccount") if x.get("readsApi") and x["name"] not in sa_with_role]
    if of("serviceaccount") and sa_api:
        add("api-role", "API access has a named permission list", "A token with no Role is useless; one with a broad Role is dangerous. Grant exactly what the app reads.",
            "off" if lonely else "on", ("no Role for " + ", ".join(lonely)) if lonely else "",
            {"type": "role", "name": f"{lonely[0]}-role", "serviceAccount": lonely[0]} if lonely else None, group="App")
    if roles:
        risky = [r for r in roles if role_risks(r)]
        add("least-privilege-rbac", "Least-privilege permissions", "A stolen token can do only what the Role lists: no wildcards, no secrets or RBAC unless justified.",
            "loosened" if risky else "on",
            "; ".join(f"{r['name']}: {', '.join(role_risks(r))}" for r in risky), group="App")
    srv = [w for w in wl if w["kind"] in SERVING]
    if wl:
        def agg(id_, title, why, bad, detail_fmt, pool=None):
            names = [w["name"] for w in (wl if pool is None else pool) if bad(w)]
            add(id_, title, why, "loosened" if names else "on", detail_fmt.format(", ".join(names)) if names else "", group="App")
        agg("non-root", "Runs as a normal user", "A break-out lands as an unprivileged user, not root.", lambda w: w["runAsRoot"], "root: {}")
        agg("read-only-fs", "Read-only filesystem", "An attacker cannot drop tools or change files inside the container.", lambda w: w["writableRoot"], "writable: {}")
        add("drop-caps", "No extra Linux powers", "All capabilities are dropped and privilege escalation is off.", "on", group="App")
        add("seccomp", "Syscall filter", "The container can only make the system calls ordinary apps need.", "on", group="App")
        add("limits", "CPU and memory limits", "A bug or attack cannot eat the whole node.", "on", group="App")
        if srv:
            agg("probes", "Health checks", "Broken copies are restarted and kept out of rotation.", lambda w: not w.get("probes"), "no probes: {}", srv)
        floating = [w["name"] for w in wl if ":" not in str(w["image"]).split("/")[-1].split("@")[0] and "@" not in str(w["image"])
                    or str(w["image"]).endswith(":latest")]
        add("image-tag", "Fixed image version", "A moving tag like latest means tomorrow's deploy is not the image you reviewed.",
            "off" if floating else "on", ("floating tag: " + ", ".join(floating)) if floating else "", None, group="Supply chain")
        unpinned = [w["name"] for w in wl if "@sha256:" not in str(w["image"])]
        add("image-digest", "Image pinned by digest", "A digest cannot be re-pointed to different contents after review.",
            "off" if unpinned else "on", ("tag only: " + ", ".join(unpinned)) if unpinned else "", None, optional=True, group="Supply chain")
        if s["registries"]:
            outside = [w["name"] for w in wl if not any(str(w["image"]).startswith(r.rstrip("/") + "/") for r in s["registries"])]
            add("trusted-registry", "Images from trusted registries", "Only images from registries you control or have vetted can run.",
                "off" if outside else "on", ("not from " + ", ".join(s["registries"]) + ": " + ", ".join(outside)) if outside else "", None, group="Supply chain")
        if s["registries"]:
            add("private-registry-auth", "Private registry credentials are set", "Pulling from an internal registry (Artifactory) needs a pull secret; without it the first deploy fails with ImagePullBackOff.",
                "on" if s["pullSecret"] else "off", "" if s["pullSecret"] else "set an image pull secret in Designs & settings", None, optional=True, group="Supply chain")
        e_ = env or {}
        add("image-signed", "Only signed images run", "A trusted registry can still be tampered with; a signature made in your pipeline proves the image is the one you built.",
            "on" if s["signing"] else "off",
            ("signatures checked at admission" + ("" if e_.get("kyverno") or not e_.get("scanned") else "; Kyverno was not found in the cluster, install it first")) if s["signing"]
            else "add your cosign public key in Designs & settings", None, optional=True, group="Supply chain")
        secret_names = {x["name"] for x in of("secret")}
        wanted: dict = {}
        for w in wl:
            for e in w.get("secretEnv") or []:
                if e.get("secret") and e["secret"] not in secret_names:
                    wanted.setdefault(e["secret"], []).append({"name": e.get("key") or e["name"], "remote": ""})
        if any(w.get("secretEnv") for w in wl):
            add("secrets-managed", "Secrets come from a secret store", "The password lives in your vault and is synced in; it is not hand-made or copied between clusters.",
                "off" if wanted else "on", ("not managed here: " + ", ".join(sorted(wanted))) if wanted else "",
                {"type": "secret", "name": sorted(wanted)[0], "keys": wanted[sorted(wanted)[0]]} if wanted else None, optional=True, group="Supply chain")
        leaky = [f"{w['name']}.{e['name']}" for w in wl for e in w.get("env") or [] if _SECRETISH.search(str(e.get("name", "")))]
        add("secrets", "Secrets kept out of plain settings", "A password typed into the design ends up in Git and in the chart's values.",
            "loosened" if leaky else "on", ("looks like a secret: " + ", ".join(leaky)) if leaky else "",
            None, group="App")
        pdb_for = {p.get("target") for p in of("pdb")}
        multi = [w["name"] for w in srv if w["replicas"] > 1 and w["name"] not in pdb_for]
        if srv:
          add("pdb", "Survives maintenance", "Draining a node cannot take every copy down at once.",
            "off" if multi else "on", ("no budget for " + ", ".join(multi)) if multi else "",
            {"type": "pdb", "name": f"{multi[0]}-pdb", "target": multi[0]} if multi else None, group="Availability")
        hpa_for = {h.get("target") for h in of("hpa")}
        unscaled = [w["name"] for w in srv if w["name"] not in hpa_for]
        if srv:
          add("hpa", "Scales with load", "Traffic spikes do not turn into an outage.", "off" if unscaled else "on",
            ("fixed size: " + ", ".join(unscaled)) if unscaled else "",
            {"type": "hpa", "name": f"{unscaled[0]}-hpa", "target": unscaled[0]} if unscaled else None, optional=True, group="Availability")
    # A loosened default is allowed for a business reason, but only with the controls that make up
    # for it. Each loosened layer lists them; it is "covered" once a reason is given and they are on.
    state = {x["id"]: x["status"] for x in out}
    ranges_ok = all(x.get("sourceRanges") for x in of("service") if x["kind"] == "LoadBalancer")
    needs = {"service-encryption": ["default-deny", "narrow-peers"],
             "least-privilege-rbac": ["default-deny", "non-root"],
             "ns-fence": ["default-deny", "non-root", "read-only-fs"],
             "non-root": ["read-only-fs", "default-deny", "no-token"],
             "read-only-fs": ["non-root", "default-deny"],
             "no-token": ["default-deny", "non-root"],
             "tls": ["ingress-path"],
             "no-public-service": ["tls", "default-deny", "source-ranges"]}
    titles = {"non-root": "Runs as a normal user", "read-only-fs": "Read-only filesystem",
              "default-deny": "Block all traffic by default"}
    titles.update({x["id"]: x["title"] for x in out})
    titles["source-ranges"] = "Public services limited to known addresses"
    state["source-ranges"] = "on" if ranges_ok else "off"
    reasons = {"service-encryption": [{"name": "this design", "reason": tr["reason"]}] if tr["mode"] == "none" else [],
               "least-privilege-rbac": [c for c in of("role") if role_risks(c)],
               "ns-fence": [c for c in of("namespace") if c["psa"] != "restricted"],
               "non-root": [c for c in wl if c["runAsRoot"]], "read-only-fs": [c for c in wl if c["writableRoot"]],
               "no-token": [c for c in of("serviceaccount") if c.get("readsApi")],
               "tls": [c for c in ings if not c.get("tls")], "no-public-service": [c for c in of("service") if c["kind"] != "ClusterIP"]}
    for x in out:
        if x["status"] != "loosened" or x["id"] not in needs or not reasons[x["id"]]:
            continue
        comps_ = reasons[x["id"]]
        missing_why = [c["name"] for c in comps_ if not str(c.get("reason") or "").strip()]
        comp = []
        for cid in needs[x["id"]]:
            ok = state.get(cid) == "on"
            fix = next((y["add"] for y in out if y["id"] == cid and y["add"]), None)
            if fix is None and not ok and cid in ("non-root", "read-only-fs") and not wl:
                fix = {"type": "workload"}                       # the control needs an app to apply to
            comp.append({"id": cid, "title": titles.get(cid, cid), "status": "on" if ok else "off", "add": fix})
        x["compensating"] = comp
        x["reason"] = "; ".join(f"{c['name']}: {str(c.get('reason')).strip()}" for c in comps_ if str(c.get("reason") or "").strip())
        gaps = [c["title"] for c in comp if c["status"] != "on"]
        if missing_why:
            x["detail"] = (x["detail"] + "; " if x["detail"] else "") + "needs a business reason for " + ", ".join(missing_why)
        elif gaps:
            x["detail"] = (x["detail"] + "; " if x["detail"] else "") + "still needs: " + ", ".join(gaps)
        else:
            x["status"] = "covered"
    import datetime
    today = datetime.date.today().isoformat()
    for x in out:
        x["tactic"], x["threat"] = _THREATS.get(x["id"], ("Impact", x["why"]))
        ap = s["approvals"].get(x["id"]) or {}
        locked = x["id"] in s["locks"]
        x["locked"] = locked
        x["approval"] = {"by": str(ap.get("by") or ""), "ticket": str(ap.get("ticket") or ""), "expires": str(ap.get("expires") or "")}
        if x["status"] not in ("loosened", "covered"):
            continue
        expired = bool(x["approval"]["expires"]) and x["approval"]["expires"] < today
        approved = bool(x["approval"]["by"]) and not expired
        if expired:
            x["status"] = "loosened"
            x["detail"] = (x["detail"] + "; " if x["detail"] else "") + f"exception expired on {x['approval']['expires']}"
        elif locked and not approved:
            x["status"] = "blocked"
            x["detail"] = (x["detail"] + "; " if x["detail"] else "") + "locked by this baseline: needs a named approver"
    counted = [x for x in out if not x["optional"]]
    by_tactic = []
    for tac in TACTICS:
        items = [x for x in out if x["tactic"] == tac]
        if items:
            good = sum(1 for x in items if x["status"] in ("on", "covered"))
            by_tactic.append({"tactic": tac, "covered": good, "total": len(items),
                              "items": [{"id": x["id"], "title": x["title"], "threat": x["threat"], "status": x["status"]} for x in items]})
    for x in out:
        x["types"] = _LAYER_TYPES.get(x["id"], [])
    return {"problems": s["problems"], "threats": by_tactic, "residual": RESIDUAL, "layers": out, "on": sum(1 for x in counted if x["status"] == "on"), "total": len(counted),
            "covered": sum(1 for x in counted if x["status"] == "covered"),
            "loosened": sum(1 for x in counted if x["status"] in ("loosened", "blocked")), "off": sum(1 for x in counted if x["status"] == "off")}


# ---- saved designs: build a secure design once, start from it every time ---------------------
_BP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,60}$")


def _bp_dir(base: str) -> str:
    import os
    return os.path.join(base, "designs")


def blueprint_save(base: str, name: str, spec: dict) -> dict:
    import datetime
    import json
    import os
    name = str(name or "").strip()
    if not _BP_NAME.match(name):
        raise BuildError("Name a design with letters, numbers, spaces, dots, dashes or underscores.")
    s = _norm(spec)                                  # refuse to save something that cannot build
    os.makedirs(_bp_dir(base), exist_ok=True)
    meta = {"name": name, "saved": datetime.datetime.now().isoformat(timespec="seconds"),
            "spec": {"app": s["app"], "namespace": s["namespace"], "registries": s["registries"],
                     "components": spec.get("components") or [],
                     **{k: spec[k] for k in ("locks", "approvals", "guardrails", "transport", "pullSecret", "signing") if k in spec}}}
    with open(os.path.join(_bp_dir(base), re.sub(r"[ ]", "_", name) + ".json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    return {"name": name}


def blueprint_list(base: str) -> list:
    import json
    import os
    out = []
    d = _bp_dir(base)
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        try:
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                m = json.load(fh)
            out.append({"name": m["name"], "saved": m.get("saved", ""), "app": m["spec"]["app"],
                        "components": len(m["spec"].get("components") or [])})
        except (OSError, ValueError, KeyError):
            continue
    return out


def blueprint_load(base: str, name: str) -> dict:
    import json
    import os
    if not _BP_NAME.match(str(name or "")):
        raise BuildError("No such design.")
    path = os.path.join(_bp_dir(base), re.sub(r"[ ]", "_", name) + ".json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)["spec"]
    except (OSError, ValueError, KeyError):
        raise BuildError("No such design.")


def blueprint_delete(base: str, name: str) -> bool:
    import os
    if not _BP_NAME.match(str(name or "")):
        return False
    try:
        os.remove(os.path.join(_bp_dir(base), re.sub(r"[ ]", "_", name) + ".json"))
        return True
    except OSError:
        return False


def scan_image(ref: str, runner=None) -> dict:
    """Vulnerabilities in one image, by Grype, for the design's workload form. Returns counts only."""
    ref = str(ref or "").strip()
    if not _IMAGE.match(ref) or ref.startswith("-"):
        raise BuildError(f"'{ref}' is not a valid image reference.")
    from .image_scan import GrypeRunner
    runner = runner or GrypeRunner()
    if not runner.available():
        return {"available": False, "message": "Grype is not installed on this machine (brew install grype), so the image cannot be scanned."}
    res = runner.scan({"image": ref, "digest": ref.partition("@")[2], "target": ref, "pinned": "@sha256:" in ref})
    if "error" in res:
        return {"available": True, "error": res["error"]}
    from collections import Counter
    ms = res.get("matches", [])
    return {"available": True, "total": len(ms), "counts": dict(Counter(m["severity"] for m in ms)),
            "kev": sum(1 for m in ms if m.get("knownExploited")), "fixable": sum(1 for m in ms if m.get("fixState") == "fixed"),
            "dbBuilt": res.get("dbBuilt", "")}


# ---- drift: is the running cluster still the design? -----------------------------------------
def drift(spec: dict, inv: dict) -> dict:
    """Compare the design with a scan's cluster inventory and say where the cluster has moved away."""
    s = _norm(spec)
    sec = (inv or {}).get("sections") or {}
    ns = s["namespace"]
    items = []

    def add(obj, aspect, design, live, sev="bad"):
        items.append({"object": obj, "aspect": aspect, "design": design, "live": live, "severity": sev})

    nsrow = next((n for n in sec.get("namespaces", []) if n["name"] == ns), None)
    wls = {w["name"]: w for w in sec.get("workloads", []) if w["namespace"] == ns}
    pods = {}
    for p in sec.get("pods", []):
        if p["namespace"] == ns:
            pods.setdefault(p["workload"], []).append(p)
    svcs = {x["name"]: x for x in sec.get("services", []) if x["namespace"] == ns}
    ings = {x["name"]: x for x in sec.get("ingresses", []) if x["namespace"] == ns}
    pols = [x for x in sec.get("policies", []) if x["namespace"] == ns]
    if nsrow is None:
        add(f"Namespace {ns}", "exists", "yes", "not in the last scan (not deployed yet, or out of scope)", "info")
    for c in s["components"]:
        t, n = c["type"], c["name"]
        if t == "namespace" and nsrow is not None and nsrow.get("psa") != c["psa"]:
            add(f"Namespace {ns}", "Pod Security level", c["psa"], nsrow.get("psa") or "none")
        elif t == "workload":
            w = wls.get(n)
            if not w:
                add(f"Workload {n}", "exists", "yes", "not found in the last scan", "info")
                continue
            if w["desired"] is not None and w["desired"] != c["replicas"]:
                add(f"Workload {n}", "replicas", c["replicas"], w["desired"], "warn")
            if c["image"] not in w.get("images", []):
                add(f"Workload {n}", "image", c["image"], ", ".join(w.get("images", [])) or "none", "warn")
            for p in pods.get(w["id"], [])[:1]:
                for ct in p["containers"][:1]:
                    if ct["privileged"]:
                        add(f"Workload {n}", "privileged", "no", "yes")
                    if ct["root"] and not c["runAsRoot"]:
                        add(f"Workload {n}", "runs as", "non-root", "root")
                    if not ct["read_only_fs"] and not c["writableRoot"]:
                        add(f"Workload {n}", "root filesystem", "read-only", "writable")
                    if not ct["limits"]:
                        add(f"Workload {n}", "resource limits", "set", "missing")
                if any(f in ("host-network", "host-pid", "host-ipc", "host-path") for f in p["flags"]):
                    add(f"Workload {n}", "host access", "none", ", ".join(f for f in p["flags"] if f.startswith("host")))
        elif t == "service":
            x = svcs.get(n)
            if not x:
                add(f"Service {n}", "exists", "yes", "not found in the last scan", "info")
            elif x["type"] != c["kind"]:
                add(f"Service {n}", "type", c["kind"], x["type"])
        elif t == "ingress":
            x = ings.get(n)
            if not x:
                add(f"Ingress {n}", "exists", "yes", "not found in the last scan", "info")
            elif bool(c["tls"]) and not x["tls"]:
                add(f"Ingress {n}", "HTTPS", "on", "off")
    if any(c["type"] == "networkpolicy" and c["mode"] == "default-deny" for c in s["components"]) and nsrow is not None \
            and not any("default-deny" in (p.get("effect") or "") for p in pols):
        add(f"Namespace {ns}", "default-deny policy", "present", "missing")
    designed = {c["name"] for c in s["components"] if c["type"] == "workload"}
    for name in sorted(set(wls) - designed):
        add(f"Workload {name}", "in the design", "no", "running in this namespace but not in the design", "warn")
    from collections import Counter
    return {"items": items, "counts": dict(Counter(i["severity"] for i in items)), "checked": bool(sec)}


# ---- exceptions as accepted risks ------------------------------------------------------------
_EXC_RULES = {
    "non-root": ("workload-run-as-root", "workload", lambda c: c.get("runAsRoot")),
    "read-only-fs": ("workload-writable-root-fs", "workload", lambda c: c.get("writableRoot")),
    "no-public-service": ("net-*", "service", lambda c: c["kind"] != "ClusterIP"),
    "tls": ("net-ingress-no-tls", "ingress", lambda c: not c.get("tls")),
    "least-privilege-rbac": ("rbac-*", "role", lambda c: bool(role_risks(c))),
}
_KIND = {"workload": "Deployment", "service": "Service", "ingress": "Ingress", "role": "Role"}


def exceptions(spec: dict, days: int = 90) -> list[dict]:
    """Accepted-risk entries for every loosened control that is fully covered, ready for the
    Accepted risks list. Each one expires, by default 90 days out, so it comes back for review."""
    import datetime
    s = _norm(spec)
    lay = {x["id"]: x for x in layers(spec)["layers"]}
    out = []
    default_exp = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    for lid, (rule, ctype, pred) in _EXC_RULES.items():
        x = lay.get(lid)
        if not x or x["status"] != "covered":
            continue
        for c in s["components"]:
            if c["type"] == ctype and pred(c) and str(c.get("reason") or "").strip():
                ap = x["approval"]
                out.append({"rule": rule, "resource": f"{s['namespace']}/{c.get('kind') if ctype == 'workload' else _KIND[ctype]}/{c['name']}",
                            "reason": f"{c['reason'].strip()} (design {s['app']}, layer {lid})",
                            "owner": ap["by"], "expires": ap["expires"] or default_exp})
    ns = next((c for c in s["components"] if c["type"] == "namespace" and c["psa"] != "restricted"), None)
    if ns and lay.get("ns-fence", {}).get("status") == "covered":
        ap = lay["ns-fence"]["approval"]
        out.append({"rule": "compliance-psa-not-restricted", "resource": f"*/Namespace/{s['namespace']}",
                    "reason": f"{ns['reason'].strip()} (design {s['app']}, layer ns-fence)", "owner": ap["by"],
                    "expires": ap["expires"] or default_exp})
    return out


# ---- threat model per component and data flow (STRIDE) -------------------------------------------
STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure",
          "D": "Denial of service", "E": "Elevation of privilege"}
BOUNDARIES = [
    "Internet to cluster: everything that crosses the ingress is untrusted.",
    "Between apps in the namespace: one breached app must not become every app.",
    "Pod and container: the app is untrusted code inside a locked box.",
    "Node and control plane: outside this design (see 'Not covered').",
]


def threat_model(spec: dict, lay: dict, result=None) -> dict:
    """Elements, data flows and trust boundaries of the design, with the abuse cases STRIDE asks about
    at each, and which protections answer them. Declared flows are checked against the evaluated network
    topology, so a rule that blocks the very call it was written for shows up as a defect."""
    s = _norm(spec)
    cs, ns = s["components"], s["namespace"]
    of = lambda t: [c for c in cs if c["type"] == t]                            # noqa: E731
    st = {x["id"]: ("ok" if x["status"] in ("on", "covered") else "bad") for x in lay["layers"]}
    title = {x["id"]: x["title"] for x in lay["layers"]}
    optional = {x["id"]: x["optional"] for x in lay["layers"]}
    threats, flows, elements = [], [], []

    def threat(where, cat, abuse, ids, residual=""):
        ctl = [{"id": i, "title": title[i], "status": st[i]} for i in ids if i in st]
        need = [x for x in ctl if not optional.get(x["id"]) or x["status"] == "ok"]
        if not ctl:
            status = "residual" if residual else "open"
        elif not need:
            status = "open"
        else:
            good = sum(1 for x in need if x["status"] == "ok")
            status = "mitigated" if good == len(need) else ("partial" if good else "open")
        threats.append({"where": where, "stride": cat, "category": STRIDE[cat], "abuse": abuse,
                        "controls": ctl, "status": status, "residual": residual})

    topo = (getattr(result, "topology", None) or {}) if result is not None else {}
    exposed = set((topo.get("summary") or {}).get("internet_exposed", []))
    edges = {(e["from"], e["to"]) for e in topo.get("edges", []) if e.get("kind") not in ("exposes", "routes-to")}
    wl = {c["name"]: c for c in of("workload")}
    wid = lambda n: f"{ns}/{wl[n]['kind']}/{n}"                                 # noqa: E731
    svc_to_wl = {x["name"]: x.get("target") for x in of("service")}
    deny = any(p["mode"] == "default-deny" for p in of("networkpolicy"))

    for c in cs:
        if c["type"] in ("workload", "ingress", "service", "storage", "secret", "serviceaccount"):
            elements.append({"id": c["name"], "type": c["type"] if c["type"] != "workload" else c["kind"],
                             "zone": "edge" if c["type"] == "ingress" else "namespace"})

    # -- internet -> ingress -> workload
    for ing in of("ingress"):
        w = svc_to_wl.get(ing.get("target"))
        flows.append({"id": f"internet>{ing['name']}", "from": "Internet", "to": f"ingress {ing['name']}", "boundary": BOUNDARIES[0],
                      "declared": True, "verified": None, "label": f"HTTPS requests for {ing['host']}"})
        where = f"Internet to ingress {ing['name']}"
        threat(where, "S", "An attacker presents a fake site, or downgrades the connection, to harvest logins.", ["tls", "certificate"])
        threat(where, "T", "Requests or responses are altered in transit.", ["tls"])
        threat(where, "I", "Sessions and credentials are read in transit.", ["tls"])
        threat(where, "D", "A flood of requests takes the app down.", ["hpa", "limits"],
               "Rate limiting and a web application firewall are not generated; add them at the ingress.")
        threat(where, "E", "A crafted request exploits a flaw in the app itself.", [],
               "Application vulnerabilities are outside this design; scan the image and test the app.")
        if w and w in wl:
            ok = None if not topo else (wid(w) in exposed)
            flows.append({"id": f"{ing['name']}>{w}", "from": f"ingress {ing['name']}", "to": w, "boundary": BOUNDARIES[1],
                          "declared": True, "verified": ok, "label": "traffic from the ingress controller to the app"})
            where = f"Ingress controller to {w}"
            threat(where, "S", "Another pod pretends to be the ingress controller and sends the app requests it should never see.",
                   ["ingress-path", "narrow-peers", "service-encryption"])
            threat(where, "T", "Traffic inside the cluster is changed on its way to the app.", ["service-encryption"])
            threat(where, "I", "Traffic inside the cluster is read by something on the network path.", ["service-encryption"])

    # -- app -> app (declared allow rules)
    for p in of("networkpolicy"):
        if p["mode"] == "allow-from" and p.get("target") in wl and p.get("from") in wl:
            a, b = p["from"], p["target"]
            ok = None if not topo else ((wid(a), wid(b)) in edges)
            flows.append({"id": f"{a}>{b}", "from": a, "to": b, "boundary": BOUNDARIES[1], "declared": True, "verified": ok,
                          "label": f"{a} calls {b}" + (f" on {p['port']}" if p.get("port") else "")})
            where = f"{a} to {b}"
            threat(where, "S", f"A rogue pod pretends to be {a} and calls {b}.", ["service-encryption", "narrow-peers", "default-deny"])
            threat(where, "T", "Calls or responses are altered in transit.", ["service-encryption"])
            threat(where, "I", "Calls carrying user data or tokens are read in transit.", ["service-encryption"])
            threat(where, "E", f"A breached app uses {b}'s port to move sideways.", ["default-deny", "ports-named"])
            if ok is False:
                why = ("the caller has no outbound rule, so default-deny blocks the call before it leaves"
                       if deny and not any(q["mode"] == "allow-to" and q.get("target") == a and q.get("to") == b for q in of("networkpolicy"))
                       else "the policies together do not let this call through")
                threats.append({"where": where, "stride": "D", "category": "Design defect", "abuse": f"The call you meant to allow cannot happen: {why}.",
                                "controls": [], "status": "open", "residual": "Add an outbound rule on the caller for this destination and port."})
    for p in of("networkpolicy"):
        if p["mode"] in ("allow-to", "allow-egress-cidr") and p.get("target") in wl:
            dest = p.get("to") if p["mode"] == "allow-to" else p.get("cidr")
            if p["mode"] == "allow-to" and dest in wl:
                continue
            flows.append({"id": f"{p['target']}>{dest}", "from": p["target"], "to": dest, "boundary": BOUNDARIES[0], "declared": True,
                          "verified": None, "label": f"{p['target']} calls out to {dest}"})
            where = f"{p['target']} to {dest} (outside)"
            threat(where, "I", "A breached app sends data to somewhere other than the one place it may call.", ["egress-declared", "default-deny", "ports-named"])
            threat(where, "S", "The app talks to an impostor of that destination.", [],
                   "Encryption and identity checks toward outside services are the app's job (verify certificates).")

    # -- app -> Kubernetes API / secrets
    for sa in of("serviceaccount"):
        if sa.get("readsApi"):
            threat(f"{sa['name']} to the Kubernetes API", "E", "A stolen token is used to read or change cluster objects beyond what the app needs.",
                   ["api-role", "least-privilege-rbac", "default-deny"])
            threat(f"{sa['name']} to the Kubernetes API", "I", "A stolen token reads Secrets or other apps' configuration.", ["least-privilege-rbac"])

    # -- each workload as a process
    for w in of("workload"):
        n = w["name"]
        threat(f"{n} (the app)", "S", "The app acts as another app, or as the shared default account.", ["dedicated-identity", "no-token"])
        threat(f"{n} (the app)", "T", "The image or its files are replaced or altered.", ["read-only-fs", "image-tag", "image-digest", "trusted-registry", "guardrails"],
               "Image signatures are not verified, so a compromised registry or pipeline is trusted.")
        threat(f"{n} (the app)", "R", "Nobody can tell who did what after an incident.", [],
               "Audit logs live in the API server and the node; turn them on and ship them. This design does not generate them.")
        threat(f"{n} (the app)", "I", "Secrets or tokens leak from the container or its environment.", ["secrets", "secrets-managed", "no-token"])
        threat(f"{n} (the app)", "D", "The app is starved, crashes, or cannot be moved during maintenance.", ["limits", "probes", "pdb", "hpa"])
        threat(f"{n} (the app)", "E", "A compromised process escapes the container or gains root on the node.",
               ["non-root", "drop-caps", "seccomp", "ns-fence", "guardrails"], "Kernel and runtime flaws can still break out; keep nodes patched.")
        if w["kind"] == "StatefulSet":
            threat(f"{n} (data)", "I", "Another app, or an attacker inside the namespace, reads the data store.", ["default-deny", "narrow-peers", "service-encryption"])
            threat(f"{n} (data)", "T", "A compromised caller corrupts stored data.", [], "Database accounts and permissions are inside the database; use one per app, read-only where possible.")
            threat(f"{n} (data)", "D", "The disk is lost or the data cannot be restored.", [], "Backups, snapshots and encryption at rest are not generated; configure them for the storage class.")

    counts = {k: sum(1 for t in threats if t["status"] == k) for k in ("mitigated", "partial", "open", "residual")}
    return {"boundaries": BOUNDARIES, "elements": elements, "flows": flows, "threats": threats, "summary": counts,
            "verified": bool(topo)}


# ---- resolve an image tag to its digest, from the registry that serves it ------------------------
def _registry_parts(ref: str) -> tuple[str, str, str]:
    """(host, repository, tag) of an image reference; Docker Hub's short names get their real host."""
    ref = ref.split("@")[0]
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = "registry-1.docker.io", (ref if "/" in ref else "library/" + ref)
    repo, _, tag = path.rpartition(":") if ":" in path.rsplit("/", 1)[-1] else (path, "", "latest")
    return host, repo or path, tag or "latest"


def resolve_digest(ref: str, opener=None, environ=None) -> dict:
    """Ask the registry for the digest a tag points to, so a design can pin it. Credentials come only from
    the environment (K8SMW_REGISTRY_TOKEN, or K8SMW_REGISTRY_USER and K8SMW_REGISTRY_PASSWORD) or
    from the docker login the user already did for that exact host; they are sent to that host only."""
    import base64
    import json
    import os
    import urllib.error
    import urllib.request
    ref = str(ref or "").strip()
    if not _IMAGE.match(ref) or ref.startswith("-"):
        raise BuildError(f"'{ref}' is not a valid image reference.")
    if "@sha256:" in ref:
        return {"digest": ref.split("@")[1], "pinned": ref, "already": True}
    env = os.environ if environ is None else environ
    host, repo, tag = _registry_parts(ref)
    basic = None
    if env.get("K8SMW_REGISTRY_USER") and env.get("K8SMW_REGISTRY_PASSWORD"):
        basic = base64.b64encode(f"{env['K8SMW_REGISTRY_USER']}:{env['K8SMW_REGISTRY_PASSWORD']}".encode()).decode()
    else:
        try:
            with open(os.path.expanduser("~/.docker/config.json"), encoding="utf-8") as fh:
                basic = ((json.load(fh).get("auths") or {}).get(host) or {}).get("auth")
        except (OSError, ValueError):
            basic = None
    accept = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
                        "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json"])

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):                       # never forward credentials to another host
            return None

    def call(url, auth=None, method="HEAD"):
        req = urllib.request.Request(url, method=method, headers={"Accept": accept, **({"Authorization": auth} if auth else {})})
        return (opener or urllib.request.build_opener(_NoRedirect).open)(req, timeout=15)

    url = f"https://{host}/v2/{repo}/manifests/{tag}"
    auth = f"Bearer {env['K8SMW_REGISTRY_TOKEN']}" if env.get("K8SMW_REGISTRY_TOKEN") else (f"Basic {basic}" if basic else None)
    try:
        try:
            resp = call(url, auth)
        except urllib.error.HTTPError as exc:
            chal = exc.headers.get("WWW-Authenticate", "") if exc.code == 401 else ""
            if not chal.lower().startswith("bearer"):
                raise
            parts = dict(p.strip().split("=", 1) for p in chal[7:].split(",") if "=" in p)
            realm, svc = parts.get("realm", "").strip('"'), parts.get("service", "").strip('"')
            if not realm.startswith("https://"):
                raise
            tok_url = f"{realm}?service={svc}&scope=repository:{repo}:pull"
            tok = json.loads(call(tok_url, f"Basic {basic}" if basic else None, "GET").read().decode())
            resp = call(url, "Bearer " + (tok.get("token") or tok.get("access_token") or ""))
    except urllib.error.HTTPError as exc:
        raise BuildError(f"The registry answered {exc.code} for {host}/{repo}:{tag}. "
                         + ("Log in (docker login " + host + ") or set K8SMW_REGISTRY_TOKEN." if exc.code in (401, 403) else "Check the name and tag."))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise BuildError(f"Could not reach {host}: {str(exc)[:120]}")
    digest = resp.headers.get("Docker-Content-Digest", "")
    if not digest.startswith("sha256:"):
        raise BuildError(f"{host} did not return a digest for {repo}:{tag}.")
    base = ref if ":" in ref.rsplit("/", 1)[-1] else ref + ":latest"
    return {"digest": digest, "pinned": f"{base}@{digest}", "already": False}
