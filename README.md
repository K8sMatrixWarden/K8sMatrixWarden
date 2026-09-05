<h1 align="center">K8sMatrixWarden</h1>

<p align="center">
  <strong>Links static Kubernetes findings to live runtime exploitation</strong><br/>
  <em>Not "here is a weakness". Instead: "this weakness is being exploited right now, and here is the kill chain."</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/deps-zero%20(stdlib%20core)-brightgreen"/>
  <img src="https://img.shields.io/badge/rules-62-orange"/>
  <img src="https://img.shields.io/badge/MCP%20tools-47-blueviolet"/>
  <img src="https://img.shields.io/badge/tests-1069%20passing-success"/>
  <img src="https://img.shields.io/badge/license-see%20LICENSE-lightgrey"/>
</p>

<p align="center">
  <a href="GETTING-STARTED.md"><strong>Getting Started</strong></a> ·
  <a href="#use-it-from-an-ai-agent-mcp"><strong>MCP Setup</strong></a> ·
  <a href="#proof-kubernetes-goat">Benchmarks</a> ·
  <a href="K8sMatrixWarden-doc.html">Technical Reference</a>
</p>

---

## Demo

| Video | Shows |
|---|---|
| **[Driving it from an MCP client](https://github.com/rohitsoni1209/K8sMatrixWarden/raw/refs/heads/main/K8sMatrixWarden-MCPClient-working.mp4)** | The whole product run conversationally from an AI agent. The intended workflow. |
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

No install, no dependencies, no cluster. The core engine is pure standard library and ships
with a deliberately insecure mock cluster.

```bash
git clone <repo-url> && cd K8sMatrixWarden

python -m k8smatrixwarden doctor        # verify the install
python -m k8smatrixwarden falco status  # is the runtime event source up?
python -m k8smatrixwarden helm status   # is Helm available for the Falco lifecycle?
python -m k8smatrixwarden scan --mock   # full scan, zero dependencies
python -m k8smatrixwarden web --open    # dashboard on 127.0.0.1:8080
```

Scanning a real cluster needs one extra:

```bash
pip install -e ".[live]"
python -m k8smatrixwarden scan --live --name "prod" --yes
```

**New to the product?** The **[Getting Started Guide](GETTING-STARTED.md)** takes you from
zero to a production scan, including obtaining cloud credentials and cluster access from
scratch for [EKS](GETTING-STARTED.md#9-amazon-eks),
[GKE](GETTING-STARTED.md#10-google-gke), and [AKS](GETTING-STARTED.md#11-microsoft-aks).

---

## Use it from an AI agent (MCP)

**This is the intended way to run the product.** Rather than composing flags, you describe
what you want and the agent picks from **47 MCP tools**, all read-only.

The repository **ships the config file for every MCP client with project-local discovery**,
so there is nothing to write and no path to fill in.

| Client | File it reads | Ships here |
|---|---|:---:|
| **Cursor** | `.cursor/mcp.json` | Yes |
| **Claude Code** (CLI, desktop, VS Code and JetBrains) | `.mcp.json` | Yes |
| **VS Code** Copilot Chat, *Agent* mode 1.102+ | `.vscode/mcp.json` | Yes |

```bash
pip install -e ".[mcp]"
python -m k8smatrixwarden mcp --list-tools   # verify: prints all 40, does not start the server
```

Open the repo folder in your client, enable the server (`/mcp` in Claude Code, Settings ->
Tools and MCP in Cursor, Agent mode in VS Code), then just ask:

> Run an `intelligent_scan` for privilege escalation on the mock cluster, summarize the
> findings, and start the web interface.

> Run a live scan of my cluster covering the whole attack matrix. kubeconfig
> `"C:\Users\me\.kube\config"`, name it `"Prod live Scan"`, give me a markdown report.

Scans run over MCP save to the shared report store, so they appear in the dashboard's **Scan
history** immediately.

Claude Desktop and Windsurf use a machine-wide config instead. Setup for those, the config
file contents, and troubleshooting are in
**[Getting Started, Section 19](GETTING-STARTED.md#19-ai-agent-integration-mcp)**.

---

## What it does

**1. Scan.** 62 rules across 11 domain shards. A shard is the execution boundary: it owns
its rules, its evidence fetch, and its scoped RBAC role.

`cluster_control_plane` · `workload_pod_security` · `rbac_identity` · `network_security` ·
`image_supply_chain` · `secrets` · `compliance` · `attack_surface` · `admission_control` ·
`cloud_iam` · `log_analysis`

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

**5. Report.** Eight formats: terminal, text, markdown, JSON, SARIF, HTML, PDF, Excel. With
CIS Benchmark v1.8 (130 controls), MITRE ATT&CK for Containers, and OWASP Kubernetes Top 10
mapping.

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
| MCP server, 47 tools | [`mcp/server.py`](k8smatrixwarden/mcp/server.py) |
| 11 domain shards | [`shards/`](k8smatrixwarden/shards/) |

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
| `mcp [--list-tools]` | Run the MCP server, or list its 47 tools |
| `scan ...` | Scan by scope and selector, or a natural-language query |
| `web [--port 8080]` | Security dashboard. Binds `127.0.0.1` |
| `chat` | Interactive assistant, confirm then run |
| `matrix [--coverage]` | Kubernetes Threat Matrix for a scan, or global coverage |
| `rules` / `coverage` | Rule registry and MITRE tactic coverage |
| `cis ...` | CIS Kubernetes Benchmark v1.8, all 130 controls |
| `compliance ...` | PCI DSS 4.0, SOC 2, ISO 27001:2022, NIST 800-53 r5 |
| `posture` | What changed since the previous scan |
| `federation` | Cross-cluster blast radius |
| `report list / download` | List and re-render saved scans in any format |
| `roles` | Generate scoped read-only RBAC, one ClusterRole per shard |
| `doctor [--probe]` | Full health check, 20 items |

```
scope    : --namespace/-n · --pod · --workload KIND/name · --node · --image · --helm-release
selector : --tactic · --technique · --module · --rule · --alias · --framework · --severity-min
mode     : --mock (default) · --live · --fixture PATH · --kubeconfig PATH · --context NAME
output   : -o {terminal,text,markdown,json,sarif,html,pdf,xlsx} · --output-file PATH
flow     : --dry-run · --yes · --fail-on {LOW,MEDIUM,HIGH,CRITICAL}   (CI mode)
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

**Detect and report only.** The tool never mutates a cluster from any surface. There is no
remediation or apply path. Scanning reads with `get`, `list`, and `watch` only, and every
output derives from that read-only snapshot. The MCP surface exposes no write-capable tool,
enforced by `tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed`.

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
optional extras, not the engine. Verified on 3.11 and 3.14 with 1069 of 1069 tests passing.
**3.11 or 3.12 is the safest choice** for a real deployment.

```bash
pip install -e ".[live]"      # kubernetes client, for real clusters
pip install -e ".[mcp]"       # MCP protocol server
pip install -e ".[pretty]"    # rich terminal tables
pip install -e ".[pdf]"       # fpdf2, for -o pdf
pip install -e ".[excel]"     # openpyxl, for -o xlsx
pip install -e ".[all]"       # everything
```

Live scanning also needs a kubeconfig, read-only cluster access, and the matching cloud CLI
for managed clusters.
**[Getting Started, Part III](GETTING-STARTED.md#part-iii-connecting-to-a-real-cluster)**
covers all of that from scratch.

---

## Optional LLM layer

**The scanner never needs a model.** Every number this README quotes, findings, risk,
coverage, the threat matrix, attack paths, CIS and compliance status, comes from
deterministic Python. The optional layer powers only the local `chat` command's multi-step
tool chaining. An MCP client brings its own model and does not use it at all.

Nothing about the provider or model is compiled in. Five providers are supported:

| `provider` | Endpoint |
|---|---|
| `anthropic` | Anthropic hosted models |
| `openai` | OpenAI |
| `azure-openai` | Azure OpenAI deployments |
| `openai-compatible` | Any OpenAI-shaped endpoint: OpenRouter, Together, Groq, vLLM, llama.cpp, LM Studio |
| `ollama` | Local Ollama |

```bash
export K8SMATRIXWARDEN_LLM_PROVIDER=openai-compatible
export K8SMATRIXWARDEN_LLM_BASE_URL=http://localhost:11434/v1
export K8SMATRIXWARDEN_LLM_MODEL=llama3.1:70b
```

Selection is deterministic: an explicit argument, then environment variables, then the
`llm` block of `config/agent.json`, then auto-detection in a fixed order. **If more than
one candidate is found the tool refuses to guess** and asks you to name the provider. Any
failure falls back to the deterministic path and can never change what a scan found.

Check what is active with `python -m k8smatrixwarden doctor`, or add `--probe` to make one
live call. Full detail: [Getting Started, Section 21](GETTING-STARTED.md#21-configuration).

---

## Validation status

| Area | Status |
|---|---|
| Static scanning, RBAC graph, NetworkPolicy, attack paths, risk, compliance | Tested, live cluster and fixtures |
| Live Falco correlation | Tested live, Falco 0.44.1, modern eBPF |
| falcosidekick push feed | Tested live, 2.x. Push and pull produce identical security meaning. |
| Kubernetes audit rules | Fixture-tested end to end against native `audit.k8s.io/v1` records |
| All 8 report formats, MCP, dashboard | Tested |
| Test suite | 1069 passing, 0 failures |

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
| **[GETTING-STARTED.md](GETTING-STARTED.md)** | **Start here.** Zero to a production scan: concepts, install, cloud credentials and cluster access for EKS/GKE/AKS, least-privilege RBAC, dashboard, runtime correlation, MCP, CI, troubleshooting, glossary. |
| [K8sMatrixWarden-doc.html](K8sMatrixWarden-doc.html) | Full technical reference. Architecture, risk-scoring math, all 11 shard rule catalogs, complete CLI and MCP references. Open in a browser. |

---

## License

See [LICENSE](LICENSE).
