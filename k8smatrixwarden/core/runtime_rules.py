"""Guided runtime rules: describe what to catch in plain fields, get a Falco rule, test it before it ships.

An analyst fills in a few fields (what behaviour, which programs or paths, which namespaces, what is
allowed). This module turns that into a Falco rule, checks it, and replays it against example events so
the rule is proven to fire on what it should and stay quiet on what it should not, before anything is
deployed. The same predicate list renders the Falco condition and evaluates events, so the test and the
shipped rule cannot drift apart. Falco itself has the last word: `validate_with_falco` runs its own
rule loader when Docker is available.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Callable, Optional

PRIORITIES = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"]
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{2,60}$")
_VALUE = re.compile(r'^[^"\\\n\r]{1,200}$')                      # no quote, backslash or newline can reach a condition
_EXC_FIELDS = {"proc.name": "Program name", "proc.pname": "Parent program", "container.image.repository": "Image",
               "k8s.ns.name": "Namespace", "user.name": "User"}

BEHAVIORS = {
    "process": {"title": "A program is started", "source": "syscall", "priority": "WARNING", "tactic": "Execution", "technique": "T1059",
                "help": "Catch a program running inside a container: a shell, a network tool, a miner, a package manager.",
                "fields": [("names", "Program names", "bash, sh, nc", "Any of these running triggers the rule."),
                           ("cmdline_contains", "Command line contains (optional)", "curl http, base64 -d", "Narrow it to command lines containing any of these."),
                           ("parent_names", "Started by (optional)", "nginx, java", "Only when the parent program is one of these.")]},
    "file_read": {"title": "A file is read", "source": "syscall", "priority": "WARNING", "tactic": "Credential Access", "technique": "T1552",
                  "help": "Catch something reading a sensitive file: password files, tokens, keys, cloud credentials.",
                  "fields": [("paths", "Paths (start with)", "/etc/shadow, /root/.aws/", "Any file under these paths."),
                             ("process_names", "Only by these programs (optional)", "cat, python3", "Leave empty for any program.")]},
    "file_write": {"title": "A file is written", "source": "syscall", "priority": "WARNING", "tactic": "Persistence", "technique": "T1546",
                   "help": "Catch a write below a path that should never change: binaries, cron, startup scripts, logs.",
                   "fields": [("paths", "Paths (start with)", "/usr/bin, /etc/cron", "Any write under these paths."),
                              ("process_names", "Only by these programs (optional)", "sh, curl", "Leave empty for any program.")]},
    "network_out": {"title": "A connection goes out", "source": "syscall", "priority": "WARNING", "tactic": "Command and Control", "technique": "T1071",
                    "help": "Catch a container calling somewhere it should not: a metadata service, a mining pool, a country, a port.",
                    "fields": [("destinations", "Destinations (IP or range)", "169.254.169.254, 203.0.113.0/24", "Leave empty to match any address (then give ports)."),
                               ("ports", "Ports", "22, 3333, 4444", "Leave empty to match any port (then give destinations)."),
                               ("process_names", "Only by these programs (optional)", "curl, wget", "Leave empty for any program.")]},
    "k8s_api": {"title": "A Kubernetes API call", "source": "k8s_audit", "priority": "WARNING", "tactic": "Privilege Escalation", "technique": "T1078",
                "help": "Catch an action on the Kubernetes API itself: creating a binding, listing secrets, exec into a pod. Needs the Falco k8s audit plugin.",
                "fields": [("verbs", "Actions", "create, delete, list", "get, list, create, update, patch, delete."),
                           ("resources", "Resources", "secrets, clusterrolebindings, pods/exec", "What the action is on.")]},
}
TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
           "Discovery", "Lateral Movement", "Command and Control", "Impact"]

_OUTPUT = {
    "process": "Program started (user=%user.name proc=%proc.name cmdline=%proc.cmdline parent=%proc.pname pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)",
    "file_read": "File read (user=%user.name proc=%proc.name file=%fd.name pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)",
    "file_write": "File written (user=%user.name proc=%proc.name file=%fd.name pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)",
    "network_out": "Outbound connection (user=%user.name proc=%proc.name dest=%fd.sip:%fd.sport pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)",
    "k8s_api": "Kubernetes API call (user=%ka.user.name verb=%ka.verb resource=%ka.target.resource ns=%ka.target.namespace uri=%ka.uri)",
}


class RuleError(ValueError):
    """A sentence an analyst can act on."""


# ---- the spec -------------------------------------------------------------------------------------
def _list(v) -> list:
    if isinstance(v, str):
        v = [x.strip() for x in v.replace("\n", ",").split(",")]
    return [str(x).strip() for x in (v or []) if str(x).strip()]


def normalize(spec: dict) -> dict:
    """Validate and fill defaults. Raises RuleError with a plain sentence."""
    name = str(spec.get("name") or "").strip()
    if not _NAME.match(name):
        raise RuleError("Give the rule a name of 3 to 60 letters, numbers, spaces, dots or dashes (for example 'Shell in production').")
    b = str(spec.get("behavior") or "")
    if b not in BEHAVIORS:
        raise RuleError("Pick what the rule should catch.")
    meta = BEHAVIORS[b]
    vals = {}
    for key, label, *_ in meta["fields"]:
        vals[key] = _list((spec.get("values") or {}).get(key))
    sc = spec.get("scope") or {}
    scope = {"namespaces": _list(sc.get("namespaces")), "exclude_namespaces": _list(sc.get("exclude_namespaces")),
             "images": _list(sc.get("images")), "containers_only": bool(sc.get("containers_only", True))}
    exceptions = []
    for e in spec.get("exceptions") or []:
        f, v = str(e.get("field") or ""), _list(e.get("values"))
        if f and v:
            if f not in _EXC_FIELDS:
                raise RuleError(f"An exception can be on: {', '.join(_EXC_FIELDS.values())}.")
            exceptions.append({"field": f, "values": v})
    pr = str(spec.get("priority") or meta["priority"]).upper()
    if pr not in PRIORITIES:
        raise RuleError("Priority must be one of " + ", ".join(PRIORITIES) + ".")
    stage = str(spec.get("stage") or "alert")
    if stage not in ("audit", "alert"):
        raise RuleError("Stage is 'audit' (log quietly) or 'alert'.")
    tactic = str(spec.get("tactic") or meta["tactic"])
    if tactic not in TACTICS:
        raise RuleError("Pick a MITRE tactic from the list.")
    tech = str(spec.get("technique") or meta["technique"]).strip()
    if tech and not re.match(r"^T\d{4}(\.\d{3})?$", tech):
        raise RuleError("A technique looks like T1059 or T1552.001.")
    out = {"name": name, "description": str(spec.get("description") or "").strip()[:300], "behavior": b, "values": vals, "scope": scope,
           "exceptions": exceptions, "priority": pr, "stage": stage, "tactic": tactic, "technique": tech,
           "advanced": str(spec.get("advanced") or "").strip()}
    for lst in list(vals.values()) + [scope["namespaces"], scope["exclude_namespaces"], scope["images"]] + [e["values"] for e in exceptions]:
        for v in lst:
            if not _VALUE.match(v):
                raise RuleError(f"'{v[:40]}' has a quote, backslash or line break, which cannot go in a rule. Remove it.")
    # per behaviour requirements
    if b == "process" and not vals["names"] and not vals["cmdline_contains"]:
        raise RuleError("Name at least one program, or part of a command line, to catch.")
    if b in ("file_read", "file_write"):
        if not vals["paths"]:
            raise RuleError("Give at least one path to watch, for example /etc/shadow.")
        for p in vals["paths"]:
            if not p.startswith("/"):
                raise RuleError(f"'{p}' is not a path: start it with a slash, like /etc/shadow.")
    if b == "network_out":
        if not vals["destinations"] and not vals["ports"]:
            raise RuleError("Give a destination, a port, or both. A rule for every connection would drown you.")
        for d in vals["destinations"]:
            try:
                ipaddress.ip_network(d, strict=False)
            except ValueError:
                raise RuleError(f"'{d}' is not an IP address or range (like 169.254.169.254 or 203.0.113.0/24).")
        for p in vals["ports"]:
            if not p.isdigit() or not 1 <= int(p) <= 65535:
                raise RuleError(f"'{p}' is not a port number between 1 and 65535.")
    if b == "k8s_api":
        if not vals["verbs"] or not vals["resources"]:
            raise RuleError("Give at least one action and one resource.")
        bad = [v for v in vals["verbs"] if v not in ("get", "list", "watch", "create", "update", "patch", "delete", "deletecollection")]
        if bad:
            raise RuleError(f"Unknown action: {', '.join(bad)}.")
    return out


# ---- predicates: one definition renders the condition and evaluates events -------------------------
class _P:
    def __init__(self, text: str, fn: Callable[[dict], bool], label: str):
        self.text, self.fn, self.label = text, fn, label


def _q(vs: list) -> str:
    return ", ".join(f'"{v}"' for v in vs)


def _in(field: str, vals: list, label: str, negate: bool = False) -> _P:
    s = set(vals)
    if negate:
        return _P(f"not {field} in ({_q(vals)})", lambda e: str(e.get(field, "")) not in s, label)
    return _P(f"{field} in ({_q(vals)})", lambda e: str(e.get(field, "")) in s, label)


def _any_text(field: str, vals: list, op: str, label: str) -> _P:
    parts = " or ".join(f'{field} {op} "{v}"' for v in vals)
    test = (lambda x, v: x.startswith(v)) if op == "startswith" else (lambda x, v: v in x)
    return _P(f"({parts})" if len(vals) > 1 else parts, lambda e: any(test(str(e.get(field, "")), v) for v in vals), label)


def predicates(spec: dict) -> list[_P]:
    s = normalize(spec)
    b, v, sc = s["behavior"], s["values"], s["scope"]
    out: list[_P] = []
    if b == "process":
        out.append(_P("evt.type in (execve, execveat) and evt.dir=<", lambda e: e.get("evt.type") in ("execve", "execveat") and e.get("evt.dir", "<") == "<", "a program starts"))
    elif b in ("file_read", "file_write"):
        flag = "evt.is_open_read" if b == "file_read" else "evt.is_open_write"
        out.append(_P(f"evt.type in (open, openat, openat2) and {flag}=true and fd.typechar=f and fd.num>=0",
                      lambda e: e.get("evt.type") in ("open", "openat", "openat2") and bool(e.get(flag)), "a file is " + ("read" if b == "file_read" else "written")))
    elif b == "network_out":
        out.append(_P("evt.type=connect and evt.dir=< and fd.typechar in (4, 6)", lambda e: e.get("evt.type") == "connect" and e.get("evt.dir", "<") == "<", "a connection is made"))
    if BEHAVIORS[b]["source"] == "syscall" and sc["containers_only"]:
        out.append(_P("container.id != host", lambda e: e.get("container.id", "host") != "host", "it happens inside a container"))
    if b == "process":
        if v["names"]:
            out.append(_in("proc.name", v["names"], "the program is one of: " + ", ".join(v["names"])))
        if v["cmdline_contains"]:
            out.append(_any_text("proc.cmdline", v["cmdline_contains"], "contains", "the command line contains: " + ", ".join(v["cmdline_contains"])))
        if v["parent_names"]:
            out.append(_in("proc.pname", v["parent_names"], "started by: " + ", ".join(v["parent_names"])))
    elif b in ("file_read", "file_write"):
        out.append(_any_text("fd.name", v["paths"], "startswith", "the path starts with: " + ", ".join(v["paths"])))
        if v["process_names"]:
            out.append(_in("proc.name", v["process_names"], "by: " + ", ".join(v["process_names"])))
    elif b == "network_out":
        ips = [d for d in v["destinations"] if "/" not in d]
        nets = [d for d in v["destinations"] if "/" in d]
        if ips or nets:
            nl = [ipaddress.ip_network(n, strict=False) for n in nets]
            parts = ([f"fd.sip in ({_q(ips)})"] if ips else []) + [f'fd.snet in ("{n}")' for n in nets]
            out.append(_P("(" + " or ".join(parts) + ")" if len(parts) > 1 else parts[0],
                          lambda e: str(e.get("fd.sip", "")) in set(ips) or _in_nets(e.get("fd.sip"), nl), "the destination is: " + ", ".join(v["destinations"])))
        if v["ports"]:
            pset = set(v["ports"])
            out.append(_P(f"fd.sport in ({', '.join(v['ports'])})", lambda e: str(e.get("fd.sport", "")) in pset, "the port is: " + ", ".join(v["ports"])))
        if v["process_names"]:
            out.append(_in("proc.name", v["process_names"], "by: " + ", ".join(v["process_names"])))
    elif b == "k8s_api":
        out.append(_in("ka.verb", v["verbs"], "the action is: " + ", ".join(v["verbs"])))
        out.append(_in("ka.target.resource", v["resources"], "the resource is: " + ", ".join(v["resources"])))
    nsf = "ka.target.namespace" if b == "k8s_api" else "k8s.ns.name"
    if sc["namespaces"]:
        out.append(_in(nsf, sc["namespaces"], "in namespace: " + ", ".join(sc["namespaces"])))
    if sc["exclude_namespaces"]:
        out.append(_in(nsf, sc["exclude_namespaces"], "not in namespace: " + ", ".join(sc["exclude_namespaces"]), True))
    if sc["images"] and BEHAVIORS[b]["source"] == "syscall":
        out.append(_in("container.image.repository", sc["images"], "for image: " + ", ".join(sc["images"])))
    for e in s["exceptions"]:
        out.append(_in(e["field"], e["values"], f"unless {_EXC_FIELDS[e['field']].lower()} is: " + ", ".join(e["values"]), True))
    return out


def _in_nets(ip, nets) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(a in n for n in nets)


def explain(spec: dict) -> list[str]:
    """The rule in plain sentences, one per condition: what must all be true for it to fire."""
    return [p.label for p in predicates(normalize(spec))]


EXAMPLES = [
    {"id": "shell", "title": "A shell in a production container", "spec": {"name": "Shell in production", "behavior": "process", "values": {"names": "bash, sh, zsh"},
     "scope": {"namespaces": "production"}, "tactic": "Execution", "technique": "T1059", "priority": "WARNING", "description": "Nobody should open a shell inside a production container."}},
    {"id": "shadow", "title": "Someone reads the password file", "spec": {"name": "Password file read", "behavior": "file_read", "values": {"paths": "/etc/shadow, /etc/sudoers"},
     "tactic": "Credential Access", "technique": "T1003", "priority": "CRITICAL", "description": "Reading credential files from inside a container."}},
    {"id": "metadata", "title": "A container calls the cloud metadata service", "spec": {"name": "Cloud metadata access", "behavior": "network_out", "values": {"destinations": "169.254.169.254", "ports": "80"},
     "tactic": "Credential Access", "technique": "T1552", "priority": "CRITICAL", "description": "Pods should not ask the node's cloud credentials service for a token."}},
    {"id": "miner", "title": "A container connects to a mining port", "spec": {"name": "Mining pool connection", "behavior": "network_out", "values": {"ports": "3333, 4444, 5555, 14444"},
     "tactic": "Impact", "technique": "T1496", "priority": "ERROR", "description": "Ports used by public mining pools."}},
    {"id": "binwrite", "title": "A program is changed on disk", "spec": {"name": "Binary directory write", "behavior": "file_write", "values": {"paths": "/usr/bin, /usr/sbin, /bin, /sbin"},
     "tactic": "Persistence", "technique": "T1546", "priority": "ERROR", "description": "Container binaries should never change at runtime."}},
    {"id": "secrets", "title": "Secrets are listed through the API", "spec": {"name": "Secret listing", "behavior": "k8s_api", "values": {"verbs": "list", "resources": "secrets"},
     "tactic": "Credential Access", "technique": "T1552", "priority": "WARNING", "description": "Listing every Secret is how a stolen token becomes more credentials."}},
]


def condition(spec: dict) -> str:
    s = normalize(spec)
    return s["advanced"] if s["advanced"] else " and ".join(p.text for p in predicates(s))


# ---- the Falco rule --------------------------------------------------------------------------------
def to_rule(spec: dict) -> dict:
    s = normalize(spec)
    meta = BEHAVIORS[s["behavior"]]
    tags = ["container", "kmw", "mitre_" + s["tactic"].lower().replace(" ", "_")] + ([s["technique"]] if s["technique"] else []) + (["kmw_stage_audit"] if s["stage"] == "audit" else [])
    rule = {"rule": s["name"], "desc": s["description"] or f"{meta['title']}: written with the K8sMatrixWarden rule builder.",
            "condition": condition(s), "output": _OUTPUT[s["behavior"]],
            "priority": "INFORMATIONAL" if s["stage"] == "audit" else s["priority"], "tags": tags}
    if meta["source"] != "syscall":
        rule["source"] = meta["source"]
    return rule


def to_yaml(specs) -> str:
    import yaml
    specs = specs if isinstance(specs, list) else [specs]
    return yaml.safe_dump([to_rule(x) for x in specs], sort_keys=False, default_flow_style=False, width=1000)


# ---- lint: does the rule hold together? -----------------------------------------------------------
_FIELD = re.compile(r"\b(evt|proc|fd|container|k8s|user|ka|thread)\.[a-z_0-9.]+")
_KNOWN = {"evt.type", "evt.dir", "evt.is_open_read", "evt.is_open_write", "proc.name", "proc.cmdline", "proc.pname", "proc.exepath",
          "fd.name", "fd.typechar", "fd.num", "fd.sip", "fd.snet", "fd.sport", "fd.cip", "fd.cport", "container.id", "container.image.repository",
          "container.name", "k8s.ns.name", "k8s.pod.name", "user.name", "user.uid", "ka.verb", "ka.target.resource", "ka.target.namespace",
          "ka.user.name", "ka.uri", "ka.target.name"}


def lint(yaml_text: str) -> dict:
    """Errors stop a rule shipping; warnings are worth reading. Pure: no cluster, no Falco."""
    errors, warnings = [], []
    try:
        import yaml
        docs = yaml.safe_load(yaml_text)
    except Exception as exc:
        return {"errors": ["The rule file is not valid YAML: " + str(exc).splitlines()[0][:140]], "warnings": []}
    if not isinstance(docs, list) or not docs:
        return {"errors": ["A rule file is a list of rules, each starting with '- rule:'."], "warnings": []}
    names = set()
    for i, r in enumerate(docs, 1):
        where = f"rule {i}"
        if not isinstance(r, dict) or "rule" not in r:
            errors.append(f"{where}: missing 'rule:' name.")
            continue
        where = f"'{r['rule']}'"
        if r["rule"] in names:
            errors.append(f"{where}: two rules share a name.")
        names.add(r["rule"])
        for k in ("desc", "condition", "output", "priority"):
            if not r.get(k):
                errors.append(f"{where}: missing '{k}'.")
        cond = str(r.get("condition") or "")
        if cond.count("(") != cond.count(")"):
            errors.append(f"{where}: brackets do not match in the condition.")
        if cond.count('"') % 2:
            errors.append(f"{where}: a quote is not closed in the condition.")
        if str(r.get("priority", "")).upper() not in PRIORITIES:
            errors.append(f"{where}: priority '{r.get('priority')}' is not one of {', '.join(PRIORITIES)}.")
        unknown = sorted({m.group(0) for m in _FIELD.finditer(cond)} - _KNOWN)
        if unknown:
            warnings.append(f"{where}: field(s) {', '.join(unknown)} are not in the guided list; Falco will tell you if they are wrong.")
        if r.get("source") == "k8s_audit":
            warnings.append(f"{where}: this rule reads the Kubernetes audit log, so Falco needs its k8saudit plugin loaded; without it Falco skips the rule.")
        if " and " not in cond and "=" not in cond and " in " not in cond:
            warnings.append(f"{where}: the condition looks very broad.")
        if str(r.get("priority", "")).upper() in ("EMERGENCY", "ALERT", "CRITICAL") and not r.get("tags"):
            warnings.append(f"{where}: a high-priority rule should carry tags so it can be triaged.")
    return {"errors": errors, "warnings": warnings}


def validate_with_falco(yaml_text: str, image: Optional[str] = None, runner=None, which=None) -> dict:
    """Ask Falco's own rule loader. Needs Docker; says so plainly when it is not there."""
    import shutil
    import subprocess
    import tempfile
    which = which or shutil.which
    if not which("docker"):
        return {"available": False, "message": "Docker is not available on this machine, so Falco's own check could not run. The built-in check passed or failed above."}
    image = image or os.environ.get("K8SMW_FALCO_IMAGE", "falcosecurity/falco-no-driver:latest")
    if not re.match(r"^[A-Za-z0-9._/:@-]{1,200}$", image):
        raise RuleError("K8SMW_FALCO_IMAGE is not a valid image reference.")
    runner = runner or subprocess.run
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "kmw.yaml"), "w", encoding="utf-8") as fh:
            fh.write(yaml_text)
        try:
            p = runner(["docker", "run", "--rm", "-v", f"{d}:/rules:ro", image, "falco", "-V", "/rules/kmw.yaml"],
                       capture_output=True, text=True, timeout=240)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"available": True, "ok": False, "output": str(exc)[:300]}
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    return {"available": True, "ok": p.returncode == 0, "output": out[-900:]}


# ---- test: replay events against the rule ---------------------------------------------------------
def evaluate(spec: dict, event: dict) -> dict:
    """Would this rule fire on this event, and if not, which condition stopped it?"""
    s = normalize(spec)
    if s["advanced"]:
        raise RuleError("A hand-written condition cannot be simulated here. Test it with Falco's own check, or clear the advanced box.")
    for p in predicates(s):
        if not p.fn(event):
            return {"fires": False, "stopped_by": p.label}
    return {"fires": True, "stopped_by": ""}


def auto_cases(spec: dict) -> list[dict]:
    """Events that should fire, and near misses that should not: one per condition, so a missing or too
    broad condition shows up as a failed case instead of a surprise in production."""
    s = normalize(spec)
    b, v, sc = s["behavior"], s["values"], s["scope"]
    ns = (sc["namespaces"] or ["default"])[0]
    img = (sc["images"] or ["nginx"])[0]
    base: dict = {"container.id": "3f9c2a1b4d5e", "k8s.ns.name": ns, "container.image.repository": img, "user.name": "root", "evt.dir": "<",
                  "k8s.pod.name": "web-7d9c-abcde"}
    if b == "process":
        base.update({"evt.type": "execve", "proc.name": (v["names"] or ["sh"])[0], "proc.pname": (v["parent_names"] or ["entrypoint"])[0]})
        base["proc.cmdline"] = f"{base['proc.name']} {(v['cmdline_contains'] or [''])[0]}".strip()
    elif b in ("file_read", "file_write"):
        base.update({"evt.type": "openat", ("evt.is_open_read" if b == "file_read" else "evt.is_open_write"): True,
                     "fd.name": v["paths"][0].rstrip("/") + ("/file" if v["paths"][0].endswith("/") else ""), "proc.name": (v["process_names"] or ["cat"])[0]})
    elif b == "network_out":
        ip = next((d for d in v["destinations"] if "/" not in d), None)
        if ip is None and v["destinations"]:
            ip = str(next(ipaddress.ip_network(v["destinations"][0], strict=False).hosts(), ipaddress.ip_network(v["destinations"][0], strict=False).network_address))
        base.update({"evt.type": "connect", "fd.sip": ip or "198.51.100.7", "fd.sport": (v["ports"] or ["443"])[0], "proc.name": (v["process_names"] or ["curl"])[0]})
    else:
        base = {"ka.verb": v["verbs"][0], "ka.target.resource": v["resources"][0], "ka.target.namespace": ns, "ka.user.name": "someone"}
    cases = [("It should fire: a matching event", dict(base), True)]
    mut = lambda **k: {**base, **k}                                                # noqa: E731
    if b == "process" and v["names"]:
        cases.append(("Quiet: a different program", mut(**{"proc.name": "sleep", "proc.cmdline": "sleep 1"}), False))
    if b == "process" and v["cmdline_contains"]:
        cases.append(("Quiet: right program, other arguments", mut(**{"proc.cmdline": f"{base['proc.name']} --version"}), False))
    if b in ("file_read", "file_write"):
        cases.append(("Quiet: a file outside the watched paths", mut(**{"fd.name": "/tmp/harmless.txt"}), False))
    if b == "network_out":
        if v["destinations"]:
            cases.append(("Quiet: a different destination", mut(**{"fd.sip": "192.0.2.77"}), False))
        if v["ports"]:
            cases.append(("Quiet: a different port", mut(**{"fd.sport": "8080" if "8080" not in v["ports"] else "8081"}), False))
    if b == "k8s_api":
        cases.append(("Quiet: a different action", mut(**{"ka.verb": "get" if "get" not in v["verbs"] else "watch"}), False))
        cases.append(("Quiet: a different resource", mut(**{"ka.target.resource": "configmaps"}), False))
    elif sc["containers_only"]:
        cases.append(("Quiet: the host itself, not a container", mut(**{"container.id": "host"}), False))
    if sc["namespaces"]:
        cases.append(("Quiet: a namespace you did not choose", mut(**{("ka.target.namespace" if b == "k8s_api" else "k8s.ns.name"): "unrelated-ns"}), False))
    if sc["exclude_namespaces"]:
        cases.append(("Quiet: an excluded namespace", mut(**{("ka.target.namespace" if b == "k8s_api" else "k8s.ns.name"): sc["exclude_namespaces"][0]}), False))
    if sc["images"] and b != "k8s_api":
        cases.append(("Quiet: an image you did not choose", mut(**{"container.image.repository": "other/image"}), False))
    for e in s["exceptions"]:
        cases.append((f"Quiet: allowed {_EXC_FIELDS[e['field']].lower()} ({e['values'][0]})", mut(**{e["field"]: e["values"][0]}), False))
    out = []
    for label, ev, expected in cases:
        r = evaluate(s, ev)
        out.append({"label": label, "event": ev, "expected": expected, "fires": r["fires"], "stopped_by": r["stopped_by"], "pass": r["fires"] == expected})
    return out


def run_tests(spec: dict, custom: Optional[list] = None) -> dict:
    """Auto cases plus the analyst's own events. A custom event with no expectation just reports."""
    cases = auto_cases(spec)
    for c in custom or []:
        ev = {str(k): _coerce(v) for k, v in (c.get("event") or {}).items()}
        r = evaluate(spec, ev)
        exp = c.get("expected")
        cases.append({"label": c.get("label") or "Your event", "event": ev, "expected": exp, "fires": r["fires"], "stopped_by": r["stopped_by"],
                      "pass": True if exp is None else r["fires"] == bool(exp), "custom": True})
    failed = [c for c in cases if not c["pass"]]
    return {"cases": cases, "passed": len(cases) - len(failed), "failed": len(failed), "ok": not failed}


def _coerce(v):
    if isinstance(v, str):
        if v.lower() in ("true", "false"):
            return v.lower() == "true"
    return v


def parse_event_lines(text: str) -> dict:
    """`proc.name=bash` lines to an event dict, for the 'add your own event' box."""
    ev = {}
    for line in str(text or "").splitlines():
        if "=" in line:
            k, _, val = line.partition("=")
            ev[k.strip()] = val.strip()
    return ev


# ---- the rules already in play --------------------------------------------------------------------
_EXPLAIN = {
    "rt-shell-in-container": ("A shell (bash, sh, zsh) starts inside a container.", "Attackers who get code running in a pod open a shell to look around and download tools. Legitimate containers rarely start one."),
    "rt-metadata-api": ("A connection to 169.254.169.254, the cloud metadata service.", "That address hands out the node's cloud credentials. A pod reaching it is how many cloud break-ins start."),
    "rt-network-recon": ("A scanning tool (nmap, masscan, nc) runs.", "Scanners map what else is reachable from the pod, the step before moving sideways."),
    "rt-crypto-miner": ("A known miner program (xmrig, minerd, cpuminer) runs.", "Stolen compute is a common goal; the miner burns CPU you pay for."),
    "rt-container-escape": ("A write to release_agent or /proc/1/root, or nsenter/chroot runs.", "These are the classic tricks for breaking out of a container onto the node."),
    "rt-log-clear": ("A write to a file under /var/log.", "Wiping logs is how an attacker hides what they did."),
    "rt-new-rolebinding": ("A (Cluster)RoleBinding is created (Kubernetes audit log).", "A new binding can silently grant powerful rights, including cluster-admin."),
    "rt-exec-kube-system": ("Someone execs or attaches into a pod in kube-system (audit log).", "Interactive access to control-plane add-ons is almost never routine."),
    "rt-secret-enum": ("Someone lists Secrets through the API (audit log).", "Listing every Secret is how a stolen token is turned into more credentials."),
    "rt-delete-events": ("Kubernetes Events are deleted (audit log).", "Removing events erases the cluster's own record of what happened."),
    "rt-mass-delete": ("10 or more deletes of the same kind in one burst (audit log).", "A wipe or sabotage attempt looks like this."),
}


def curated_rules() -> list[dict]:
    from ..agents.runtime import RuntimeAgent
    out = []
    for r in RuntimeAgent().catalog():
        w, why = _EXPLAIN.get(r["id"], ("", ""))
        out.append({"id": r["id"], "name": r["title"], "kind": "curated", "engine": "K8sMatrixWarden", "source": r.get("source", ""),
                    "priority": r["severity"], "tactic": r.get("tactic", ""), "technique": r.get("technique_id", ""),
                    "watches": w, "why": why, "enabled": True, "editable": False})
    return out


_DEFAULT_URL = "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml"


def default_rules(cache_dir: str, fetcher: Optional[Callable[[str], str]] = None) -> dict:
    """Falco's own shipped rules, as a reference list. Read from a local cache; fetched once from the
    falcosecurity/rules repository when absent. It is the current upstream list, which can differ from the
    exact version a cluster runs, and the page says so."""
    import yaml
    path = os.path.join(cache_dir, "falco_rules.yaml")
    text = ""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        pass
    if not text:
        try:
            if fetcher:
                text = fetcher(_DEFAULT_URL)
            else:
                import urllib.request
                with urllib.request.urlopen(_DEFAULT_URL, timeout=20) as r:                        # noqa: S310
                    text = r.read().decode("utf-8", "replace")
            os.makedirs(cache_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except Exception as exc:
            return {"rules": [], "error": f"Could not fetch Falco's default rule list ({str(exc)[:100]}). Try again when this machine is online."}
    out = []
    try:
        for item in yaml.safe_load(text) or []:
            if isinstance(item, dict) and "rule" in item:
                tags = [str(t) for t in (item.get("tags") or [])]
                mitre = next((t for t in tags if t.startswith("mitre_")), "")
                out.append({"id": "falco:" + item["rule"], "name": item["rule"], "kind": "default", "engine": "Falco",
                            "source": item.get("source", "syscall"), "priority": str(item.get("priority", "")).upper(),
                            "tactic": mitre.replace("mitre_", "").replace("_", " ").title(), "technique": next((t for t in tags if re.match(r"^T\d{4}", t)), ""),
                            "watches": " ".join(str(item.get("desc", "")).split())[:240], "why": "", "condition": " ".join(str(item.get("condition", "")).split())[:400],
                            "enabled": item.get("enabled", True) is not False, "editable": False, "tags": tags})
    except yaml.YAMLError as exc:
        return {"rules": [], "error": "The cached rule list could not be read: " + str(exc)[:100]}
    return {"rules": out, "error": ""}


# ---- the analyst's saved rules ---------------------------------------------------------------------
def _dir(base: str) -> str:
    return os.path.join(base, "runtime_rules")


def _fname(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name) + ".json"


def save_rule(base: str, spec: dict) -> dict:
    import datetime
    s = normalize(spec)
    os.makedirs(_dir(base), exist_ok=True)
    problems = lint(to_yaml(s))
    if problems["errors"]:
        raise RuleError("; ".join(problems["errors"]))
    path = os.path.join(_dir(base), _fname(s["name"]))
    history, deployed = [], ""
    try:
        with open(path, encoding="utf-8") as fh:
            old = json.load(fh)
        history, deployed = list(old.get("history") or []), old.get("deployed", "")
        if old.get("spec") != s:
            history.insert(0, {"saved": old.get("saved", ""), "deployed": old.get("deployed", ""), "spec": old["spec"]})
    except (OSError, ValueError, KeyError):
        pass
    meta = {"name": s["name"], "saved": datetime.datetime.now().isoformat(timespec="seconds"), "spec": s, "history": history[:20]}
    if deployed:
        meta["deployed"] = deployed
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    return {"name": s["name"]}


def list_saved(base: str) -> list[dict]:
    d, out = _dir(base), []
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        try:
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                m = json.load(fh)
            s = m["spec"]
            out.append({"id": "custom:" + s["name"], "name": s["name"], "kind": "custom", "engine": "Falco (yours)", "source": BEHAVIORS[s["behavior"]]["source"],
                        "priority": "INFORMATIONAL" if s["stage"] == "audit" else s["priority"], "tactic": s["tactic"], "technique": s["technique"],
                        "watches": BEHAVIORS[s["behavior"]]["title"] + ": " + condition(s)[:160], "why": s["description"], "enabled": True, "editable": True,
                        "stage": s["stage"], "saved": m.get("saved", ""), "deployed": m.get("deployed", ""),
                        "changed_since_deploy": bool(m.get("deployed")) and m.get("saved", "") > m.get("deployed", ""), "spec": s})
        except (OSError, ValueError, KeyError, RuleError):
            continue
    return out


def mark_deployed(base: str, names: list) -> None:
    import datetime
    now = datetime.datetime.now().isoformat(timespec="seconds")
    for n in names:
        path = os.path.join(_dir(base), _fname(n))
        try:
            with open(path, encoding="utf-8") as fh:
                m = json.load(fh)
            m["deployed"] = now
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(m, fh, indent=2)
        except (OSError, ValueError):
            continue


def delete_rule(base: str, name: str) -> bool:
    try:
        os.remove(os.path.join(_dir(base), _fname(str(name))))
        return True
    except OSError:
        return False


def history(base: str, name: str) -> list[dict]:
    try:
        with open(os.path.join(_dir(base), _fname(str(name))), encoding="utf-8") as fh:
            m = json.load(fh)
    except (OSError, ValueError):
        return []
    return [{"index": i, "saved": h.get("saved", ""), "deployed": h.get("deployed", ""), "stage": h["spec"].get("stage", ""),
             "priority": h["spec"].get("priority", ""), "condition": condition(h["spec"])[:200]} for i, h in enumerate(m.get("history") or [])]


def restore(base: str, name: str, index: int) -> dict:
    with open(os.path.join(_dir(base), _fname(str(name))), encoding="utf-8") as fh:
        m = json.load(fh)
    try:
        spec = m["history"][int(index)]["spec"]
    except (KeyError, IndexError, ValueError, TypeError):
        raise RuleError("That version does not exist.")
    return save_rule(base, spec)


def export_pack(base: str) -> dict:
    return {"kind": "k8smatrixwarden.rules", "version": 1, "rules": [x["spec"] for x in list_saved(base)]}


def import_pack(base: str, pack, overwrite: bool = False) -> dict:
    rules = pack.get("rules") if isinstance(pack, dict) else pack
    if not isinstance(rules, list) or not rules:
        raise RuleError("That file has no rules. Export a pack from this page and import that.")
    have = {x["name"] for x in list_saved(base)}
    done, skipped, errors = [], [], []
    for r in rules[:200]:
        try:
            s = normalize(r)
            if s["name"] in have and not overwrite:
                skipped.append(s["name"])
                continue
            save_rule(base, s)
            done.append(s["name"])
        except RuleError as exc:
            errors.append(f"{str((r or {}).get('name', '?'))[:40]}: {exc}")
    return {"imported": done, "skipped": skipped, "errors": errors}
