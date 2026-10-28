<h1 align="center">K8sMatrixWarden</h1>

<p align="center">
  <strong>Links static Kubernetes findings to live runtime exploitation</strong><br/>
  <em>Not "here is a weakness". Instead: "this weakness is being exploited right now, and here is the kill chain."</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/deps-zero%20(stdlib%20core)-brightgreen"/>
  <img src="https://img.shields.io/badge/rules-55-orange"/>
  <img src="https://img.shields.io/badge/tests-952%20passing-success"/>
  <img src="https://img.shields.io/badge/license-see%20LICENSE-lightgrey"/>
</p>

<p align="center">
  <a href="GETTING-STARTED.md"><strong>Getting Started</strong></a> ·
  <a href="#proof-kubernetes-goat">Benchmarks</a> ·
  <a href="K8sMatrixWarden-doc.html">Technical Reference</a>
</p>

---

## Demo

| Video | Shows |
|---|---|
| **[Full walkthrough](https://github.com/rohitsoni1209/K8sMatrixWarden/raw/refs/heads/main/K8sMatrixWarden-working.mp4)** | Scan, correlation, attack paths, and dashboard, end to end. |

---

## The problem

A configuration scanner tells you a Pod **can** run privileged. A runtime sensor sees a
syscall only a privileged Pod could make. Nothing connects the two, so every finding arrives
with the same urgency and a team of five triages four hundred of them by hand.

K8sMatrixWarden closes that gap:

> Found 358 static weaknesses. Of those, **4 are being exploited right now**. Here is how the
> attacker chains them.

| | Trivy | kubescape | Falco | kube-bench | **K8sMatrixWarden** |
|---|:---:|:---:|:---:|:---:|:---:|
| Config weaknesses | Yes | Yes | No | Yes | **Yes** |
| Runtime behavior | No | No | Yes | No | **Yes** |
| Correlates both | No | No | No | No | **Yes** |
| Attack path | No | No | No | No | **Yes** |
| Image CVEs | **Yes** | Yes | No | No | No |

Trivy and K8sMatrixWarden are complements, not competitors. Run both.

---

## Quick start

One command, and it tells you what to fix first.

```bash
pip install -e ".[live,manifests]"     # live = real clusters, manifests = YAML and Helm

k8smatrixwarden check                  # the cluster kubectl points at
k8smatrixwarden check ./k8s ./charts   # manifests and Helm charts, before deploy (no cluster)
k8smatrixwarden web                    # dashboard: Issues, Attack paths, Images, Tasks
k8smatrixwarden topology               # who can reach whom (exposure paths)
```

Or without installing Python: `docker build -t k8smatrixwarden .` then
`docker run --rm -v "$PWD/k8s:/work:ro" k8smatrixwarden check /work --fail-on HIGH`.

**In the dashboard (built for someone new).** *Start here* walks through five steps with live
status. *Policy review* explains the six settings that limit damage (network rules, Pod Security,
admin access, quotas, dangerous pod settings, what is open to the internet) in plain words.
*Build an app* is drag-and-drop: drop components on a canvas, keep the safe defaults, watch a
live security check, and download a ready Helm chart. No YAML, no scripts. *What changed* compares two scans (a new internet-facing service, a wider permission, an image change) and flags what made the cluster easier to attack. *Investigate a workload* pulls its status, warnings, changes, risks and attack path onto one page, with an evidence-first containment checklist whose commands you copy and run yourself. *Tasks* runs scans. Press **Ctrl/Cmd+K** (or `/`) anywhere to search issues, workloads, images and pages.
It only reads your cluster and never applies anything.

**What you get.** A ranked list: severity, then whether an attacker can reach it (Internet,
or an identity that reaches secrets), each with the fix. Add `--grype` to scan the running
images for CVEs (needs [Grype](https://github.com/anchore/grype)).

**In CI.** `--fail-on HIGH` exits 1; `--baseline base.json` makes only findings *new in this
change* count; `--comment-file` writes the PR comment; `-o sarif` feeds GitHub code scanning.
A ready workflow is in [examples/ci](examples/ci/github-actions.yml) and a reusable
[action.yml](action.yml).

**Living with findings.** Accept a risk with a reason and an expiry, in
`.k8smatrixwarden-ignore.yaml` or from the dashboard's *Accepted risks* page:

```yaml
suppressions:
  - rule: workload-run-as-root
    resource: "shop/Deployment/web"
    reason: "vendor image, ticket SEC-142"
    owner: alice
    expires: 2026-12-31
```

**For teams.** Issues carry an owner (from the `team` / `owner` label, then the namespace) and
the dashboard filters by it; `k8smatrixwarden notify` posts a summary to Slack. To run it
inside the cluster: `helm install warden ./charts/k8smatrixwarden` (read-only RBAC, scans
every 6 hours, dashboard behind `kubectl port-forward`).

The demo cluster still works with no cluster at all: `k8smatrixwarden scan --mock`.

**New to the product?** The **[Getting Started Guide](GETTING-STARTED.md)** takes you from
zero to a production scan.

---

## What it does

**1. Scan.** 55 rules across 7 domain shards. A shard is the execution boundary: it owns
its rules, its evidence fetch, and its scoped RBAC role.

`workload_pod_security` · `rbac_identity` · `network_security` · `secrets` ·
`compliance` · `attack_surface` · `log_analysis`

Select any of them with `--module <name>`.

**2. Correlate.** Joins findings to live Falco and Kubernetes audit events. A verdict of
`confirmed` means the event named the exact resource the finding sits on. `corroborated`
means same tactic and namespace with no resource link. `runtime-only` means novel behavior.

**3. Prioritize.** Every workload finding is tagged with its live attack vector, computed
from Service and Ingress exposure, NetworkPolicy isolation, and the pod's ServiceAccount
RBAC:

| Tag | Meaning |
|---|---|
| **internet-reachable** | External traffic routes to this pod and no NetworkPolicy isolates it. Fix now. |
| **post-breach only** | Exploitable only by an attacker already inside a pod. |
| **rbac-escalation** | This pod's ServiceAccount can reach cluster-admin. |

This turns a flat list into a queue, for example 368 findings becoming 74 fix-now and 270
deprioritizable, **without ever lowering a severity or hiding a finding**.

**4. Explain.** Attack paths in two layers. The *tactic* chain runs Initial Access through
Impact. The *resource* chain runs Internet, Service, Pod, ServiceAccount, RoleBinding,
ClusterRole, permission, where **every hop is read off a real object** and carries the reason
it exists. Two findings sharing a tactic are never claimed to be connected.

**5. Report.** Seven formats: terminal, text, markdown, JSON, SARIF, HTML, and a ranked
"fix this first" brief. With CIS Benchmark v1.8 (130 controls), MITRE ATT&CK for
Containers, and OWASP Kubernetes Top 10 mapping.

**6. Attest.** Governance audit against PCI DSS v4.0, SOC 2, ISO 27001:2022, and NIST 800-53
rev5, with per-requirement evidence. Auditor-facing, not a finding dump.

**7. Federate.** Cross-cluster blast radius. Flags **shared non-default identities**, the
same custom ClusterRole, ServiceAccount, or cloud IAM role in more than one cluster, as
candidate lateral movement paths to verify.

---

## Proof: Kubernetes Goat

Measured on Docker Desktop Kubernetes, 30 pods, this repository's current build.

| Metric | Result |
|---|---|
| Findings | **489** (28 CRITICAL, 215 HIGH, 246 MEDIUM), risk **9.9/10** |
| Evidence coverage | **95.5 percent**, basis `measured` |
| Attack chain | **9 tactics** reaching Impact, **25 evidence-backed resource routes** |
| Full scan time | **~213 ms**, including RBAC graph and NetworkPolicy evaluation |

The strongest route found was `Internet -> NodePort Service -> Deployment/internal-proxy-deploy`.
Multi-hop RBAC escalation paths are attached to findings by name, for example
`ServiceAccount/local-path-provisioner-service-account -> RoleBinding -> Role -> create-workload`.

Two details that show the reporting is honest rather than flattering:

- The count **includes Falco's own DaemonSet**, which is privileged and mounts host paths by
  design. The scanner reports its own sensor rather than exempting it.
- The missing 4.5 percent of coverage is Cloud IAM, which has no Kubernetes API path on a
  local cluster. It is reported as **unread**, never as clean.

With **Falco 0.44.1** on that cluster, a `cat /etc/shadow` in three Goat pods produced 4
`confirmed` correlations under Credential Access. Each marked only the node the event named,
never the whole path.

---

## Design

One idea drives the whole tool: **domain shards are the execution boundary (vertical), MITRE
tactics are cross-cutting tags (horizontal), and the two are orthogonal.**

A rule like `hostPath mount` lives in exactly one shard but carries three tactics. Every way
of asking for a scan (resource, tactic, technique, module, rule, alias, framework) resolves
through one registry index to a set of rule ids, then runs against **one shared read** of the
cluster.

```
Orchestrator (intent, scope, selector)
  -> Registry.resolve(selector)          rule_id set
  -> Evidence Collector                  fetch ONCE, scope-constrained
  -> Detection Engine                    parallel, per-rule isolation
  -> Aggregator                          dedupe, merge tags
  -> Risk Scoring                        attack-path aware
  -> Reporting                           8 formats
```

Key modules:

| Concern | Code |
|---|---|
| RBAC graph, multi-hop and cycle-safe | [`core/rbac_graph.py`](k8smatrixwarden/core/rbac_graph.py) |
| NetworkPolicy engine, both directions | [`core/netpol.py`](k8smatrixwarden/core/netpol.py) |
| Resource-level attack paths | [`core/attack_path.py`](k8smatrixwarden/core/attack_path.py) |
| Reachability tagging | [`core/reachability.py`](k8smatrixwarden/core/reachability.py) |
| Scan by runtime correlation | [`core/correlation.py`](k8smatrixwarden/core/correlation.py) |
| Confidence policy | [`core/explain.py`](k8smatrixwarden/core/explain.py) |
| 7 domain shards | [`shards/`](k8smatrixwarden/shards/) |

Full architecture map: [K8sMatrixWarden-doc.html](K8sMatrixWarden-doc.html).

---

## What the tool refuses to claim

Five confidences are kept separate on purpose, because they answer five different questions.
Collapsing them is how a scanner ends up sounding certain about evidence it never read.

| Confidence | Answers |
|---|---|
| **Evidence** | Was this resource type read, and how do we know the fraction? |
| **Assessment** | How much of the cluster did the scan see? |
| **Finding** | How much should this specific conclusion be trusted? |
| **Correlation** | How tightly does a runtime event tie to this finding? |
| **Attack path** | How strongly is this route evidenced? |

The rules that hold them together:

1. Nothing is more confident than the evidence under it. An unread resource produces **no
   claim**, not a confident absence.
2. Only a **resource-level** runtime match earns certainty. Namespace activity corroborates
   and is capped below it.
3. A runtime event at one hop does **not** make a multi-hop path observed.
4. Confidence never changes severity and never hides a finding.
5. `unknown` and `partial` are values, not synonyms for `false` or `safe`.

Enforced by [`tests/test_integration_pipeline.py`](tests/test_integration_pipeline.py).
Full model: [Getting Started, Section 24](GETTING-STARTED.md#24-the-confidence-model).

---

## Commands

| Command | What it does |
|---|---|
| `check [PATH...]` | The everyday command: the live cluster, or manifests/a Helm chart with no cluster. Ranked, brief output. |
| `scan ...` | The same engine with every flag exposed: scope, selector, or a natural-language query |
| `web [--port 8080]` | Security dashboard. Binds `127.0.0.1` |
| `notify` | Post the latest scan summary to Slack (or a compatible webhook) |
| `matrix [--coverage]` | Kubernetes Threat Matrix for a scan, or global coverage |
| `rules` / `coverage` | Rule registry and MITRE tactic coverage |
| `cis ...` | CIS Kubernetes Benchmark v1.8, all 130 controls |
| `posture` | What changed since the previous scan |
| `topology` | Network topology: who can reach whom |
| `report list / download` | List and re-render saved scans in any format |
| `roles` | Generate scoped read-only RBAC, one ClusterRole per shard plus a platform-inventory role |

```
scope    : --namespace/-n · --pod · --workload KIND/name · --node · --image · --helm-release
selector : --tactic · --technique · --module · --rule · --alias · --framework · --severity-min
mode     : --mock (default) · --live · --manifests PATH... · --fixture PATH · --kubeconfig PATH · --context NAME
output   : -o {terminal,text,markdown,json,sarif,html,brief} · --output-file PATH
flow     : --dry-run · --yes · --fail-on {LOW,MEDIUM,HIGH,CRITICAL} · --baseline REF   (CI mode)
```

```bash
python -m k8smatrixwarden scan -n production --tactic "Credential Access" -o markdown --mock
python -m k8smatrixwarden scan --technique "Container Escape" --mock
python -m k8smatrixwarden scan --live --fail-on CRITICAL -o sarif --output-file results.sarif
```

> **Scans are saved by default** to the shared report store and appear in the dashboard's
> Scan history. Use `--no-save` for a throwaway run.

Full flag reference: [Getting Started, Section 20](GETTING-STARTED.md#20-command-reference).

---

## Safety

**Detect and report only.** The scanner never mutates a cluster from any surface. There is no
remediation or apply path. The single opt-in exception is the Runtime tab's Falco deploy: it does nothing
unless the dashboard was started with `K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE=1` and you confirm, and then
it runs your own `helm`/`kubectl` in a dedicated namespace; it is off by default. Scanning reads with `get`, `list`, and `watch` only, and every
output derives from that read-only snapshot. No module in the package ever calls a
cluster-mutating Kubernetes API verb, enforced by a static audit in
`tests/test_adversarial.py::test_no_module_can_write_to_the_cluster`.

Before scanning anything you care about, generate and apply the tool's own least-privilege
RBAC:

```bash
python -m k8smatrixwarden roles --bind --output-file k8smatrixwarden-rbac.json
kubectl apply -f k8smatrixwarden-rbac.json
```

The dashboard binds `127.0.0.1` and **has no authentication**. Put your own authentication in
front of the port before exposing it.

---

## Requirements

**Python 3.10 through 3.14, and nothing else.** The core engine imports only the standard
library, so no dependency can lag a new Python release. The 3.10 floor comes from the
optional extras, not the engine. Verified on 3.11 and 3.14 with 952 of 952 tests passing.
**3.11 or 3.12 is the safest choice** for a real deployment.

```bash
pip install -e ".[live]"        # kubernetes client, for real clusters
pip install -e ".[manifests]"   # pyyaml, for scan --manifests / check on YAML and Helm
pip install -e ".[pretty]"      # rich terminal tables
pip install -e ".[all]"         # everything above
```

Live scanning also needs a kubeconfig, read-only cluster access, and the matching cloud CLI
for managed clusters.
**[Getting Started, Part III](GETTING-STARTED.md#part-iii-connecting-to-a-real-cluster)**
covers all of that from scratch.

---

## Validation status

| Area | Status |
|---|---|
| Static scanning, RBAC graph, NetworkPolicy, attack paths, risk, CIS | Tested, live cluster and fixtures |
| Live Falco correlation | Tested live, Falco 0.44.1, modern eBPF (needs a node with real kernel access — not every local dev setup has this, see Known Limitations) |
| falcosidekick push feed | Tested live, 2.x. Push and pull produce identical security meaning. |
| Kubernetes audit rules | Fixture-tested end to end against native `audit.k8s.io/v1` records |
| All 7 report formats, the dashboard | Tested |
| Test suite | 952 passing, 0 failures |

Two reported numbers are worth understanding before reading a report:

- **`resource_findings` vs `workload_issues`.** A live scan showed **517** and **173**.
  Kubernetes propagates a Deployment's flaw to its ReplicaSets and every Pod, so all of them
  genuinely carry it. The first is the evidence, the second is the work. Neither replaces the
  other and nothing is hidden.
- **Risk scoring uses the workload count**, so a controller's replica chain cannot inflate a
  score. Two distinct workloads with the same flaw still score twice.

---

## Extending

Drop a module in `k8smatrixwarden/shards/` exposing `SHARD = YourShard`, subclassing
`DomainShard` and implementing `rules()`. The Plugin Loader auto-discovers it, the Mapping
Engine auto-indexes its tags, and a scoped RBAC role is generated from its declared resource
needs. **No engine change.**

New MITRE technique? Add its id to `taxonomy/attack_for_containers.json` and tag rules with
it. New framework? Add a `cis:`, `nsa_cisa:`, or `owasp:` tag.

```bash
python -m tests.run_tests     # bundled stdlib runner, no pytest needed
python -m pytest tests/       # also works
```

---

## Documentation

| | |
|---|---|
| **[GETTING-STARTED.md](GETTING-STARTED.md)** | **Start here.** Zero to a production scan: concepts, install, cloud credentials and cluster access for EKS/GKE/AKS, least-privilege RBAC, dashboard, runtime correlation, CI, troubleshooting, glossary. |
| [K8sMatrixWarden-doc.html](K8sMatrixWarden-doc.html) | Full technical reference. Architecture, risk-scoring math, all 7 shard rule catalogs, complete CLI reference. Open in a browser. |
| [ADOPTION_REVIEW.md](ADOPTION_REVIEW.md) | A security engineer's and a DevOps engineer's independent, skeptical review: which tools this can and can't replace yet, and what it still needs to become a daily driver. |

---

## License

See [LICENSE](LICENSE).
