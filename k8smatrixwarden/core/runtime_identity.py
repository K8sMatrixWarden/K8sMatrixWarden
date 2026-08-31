"""
Runtime identity: recovering the Kubernetes resource a runtime event happened in.

Falco enriches most events with `k8s.ns.name` / `k8s.pod.name` from the CRI socket, but not
always: its container cache can start cold (on this validation cluster Falco logged
`libpman: disabled BPF iterators (not running in the root PID namespace)` and produced a
run of events carrying only `container.id`). An event with no resource identity is still a
real observation, and the correlator already refuses to confirm it against a finding, which
is the safe answer. It is not the *complete* answer: the container id is often enough to
recover the Pod from evidence the scan has already fetched.

The recovery is deterministic or it does not happen:

  * The index is built from Pod `containerStatuses` (plus init and ephemeral containers),
    which carry `containerID` as `<runtime>://<64-hex>`. Falco reports the first 12
    characters of that same id.
  * A 12-character prefix must match EXACTLY ONE container. Two matches is `ambiguous` and
    resolves to nothing, because picking either would be a guess.
  * A container the Kubernetes API does not know about resolves to nothing, and says so.

Nothing here matches on name prefixes, substrings or similarity. The only join is a
container id, which Kubernetes itself assigned.

`identity_status` is observability, not permission: it never widens what may be confirmed.
An event enriched to `complete` is confirmable because it now HAS a namespace and pod, by
the same rules any other event is judged by; `partial`, `ambiguous` and `unknown` events
flow on and correlate exactly as they did before, which is to say conservatively.
"""
from __future__ import annotations

from typing import Optional

#: Identity quality of a runtime event, for reporting. Ordered worst-last so a batch can be
#: summarised without a lookup table.
COMPLETE = "complete"
PARTIAL = "partial"
AMBIGUOUS = "ambiguous"
UNKNOWN = "unknown"

#: Falco truncates container ids to 12 characters in `container.id`.
_SHORT_ID = 12


def build_container_index(pods: list) -> dict:
    """{container id (full and 12-char prefix) -> [(namespace, pod, container)]}.

    Built once per feed from Pod evidence the scan already holds; no extra API call, and no
    container-runtime access. A prefix that maps to more than one container is kept with all
    of its matches so the caller can see the ambiguity rather than silently take the first.
    """
    index: dict = {}
    for pod in pods or []:
        if not isinstance(pod, dict):
            continue
        meta = pod.get("metadata") or {}
        ns, name = meta.get("namespace"), meta.get("name")
        status = pod.get("status") or {}
        for key in ("containerStatuses", "initContainerStatuses",
                    "ephemeralContainerStatuses"):
            for cs in status.get(key) or []:
                if not isinstance(cs, dict):
                    continue
                cid = cs.get("containerID") or ""
                if "://" in cid:
                    cid = cid.split("://", 1)[1]
                if not cid:
                    continue
                entry = (ns, name, cs.get("name"))
                index.setdefault(cid, []).append(entry)
                short = cid[:_SHORT_ID]
                if short != cid:
                    index.setdefault(short, []).append(entry)
    return index


def _lookup(container_id: str, index: dict) -> tuple:
    """(matches, key_used) for a container id, trying the full id then the short form."""
    if not container_id:
        return [], ""
    for key in (container_id, container_id[:_SHORT_ID]):
        matches = index.get(key)
        if matches:
            # The same container reached through both keys is one container, not two.
            unique = list(dict.fromkeys(matches))
            return unique, key
    return [], ""


def enrich_event(event: dict, index: dict) -> dict:
    """Return `event` with resource identity recovered where that is unambiguous.

    Adds `identity_status`, and `identity_missing` naming the fields still absent. Sets
    `identity_resolved_by` when the pod/namespace came from the container index rather than
    from the provider, so a reader can tell a recovered identity from a reported one.
    """
    if not isinstance(event, dict):
        return event
    out = dict(event)
    has_ns, has_pod = bool(out.get("namespace")), bool(out.get("pod"))

    if not (has_ns and has_pod):
        matches, _key = _lookup(str(out.get("container_id") or ""), index or {})
        if len(matches) == 1:
            ns, pod, container = matches[0]
            if ns and not has_ns:
                out["namespace"] = ns
            if pod and not has_pod:
                out["pod"] = pod
            if container and not out.get("container"):
                out["container"] = container
            out["identity_resolved_by"] = "container-id"
        elif len(matches) > 1:
            # Several live containers share this id prefix. Choosing one would be the guess
            # this module exists to avoid.
            out["identity_status"] = AMBIGUOUS
            out["identity_missing"] = sorted(
                f for f, present in (("namespace", out.get("namespace")),
                                     ("pod", out.get("pod"))) if not present)
            out["identity_candidates"] = len(matches)
            return out

    missing = [field for field, value in (("namespace", out.get("namespace")),
                                          ("pod", out.get("pod"))) if not value]
    if not missing:
        out["identity_status"] = COMPLETE
    elif len(missing) == 1:
        out["identity_status"] = PARTIAL
    else:
        out["identity_status"] = UNKNOWN
    if missing:
        out["identity_missing"] = missing
        if out.get("container_id"):
            out["identity_reason"] = (
                "container id is not known to the Kubernetes API (the container may have "
                "exited, or belong to no Pod)")
        else:
            out["identity_reason"] = "the provider supplied no container id to resolve"
    return out


def enrich_events(events: list, pods: list) -> tuple:
    """(enriched events, identity coverage) for a whole batch.

    Coverage counts events by identity quality and records how many were recovered here, so
    "Falco saw an event we could not place" is reportable and never looks like "Falco saw
    nothing"."""
    index = build_container_index(pods)
    enriched = [enrich_event(e, index) for e in (events or [])]
    counts = {COMPLETE: 0, PARTIAL: 0, AMBIGUOUS: 0, UNKNOWN: 0}
    recovered = 0
    for e in enriched:
        if not isinstance(e, dict):
            counts[UNKNOWN] += 1
            continue
        counts[e.get("identity_status", UNKNOWN)] = \
            counts.get(e.get("identity_status", UNKNOWN), 0) + 1
        if e.get("identity_resolved_by"):
            recovered += 1
    coverage = {
        "complete": counts[COMPLETE],
        "partial": counts[PARTIAL],
        "ambiguous": counts[AMBIGUOUS],
        "unknown": counts[UNKNOWN],
        # How many of those `complete` entries this module recovered, as opposed to the
        # provider having supplied them.
        "recovered_from_container_id": recovered,
        "containers_indexed": sum(1 for k in index if len(k) > _SHORT_ID),
    }
    return enriched, coverage
