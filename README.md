<h1 align="center">K8sMatrixWarden</h1>

<p align="center">
  <strong>The K8s tool that links static scan findings to live runtime exploitation</strong><br/>
  <em>Not "here's a weakness" — "this weakness is being exploited right now, here's the kill-chain"</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/deps-zero%20(stdlib%20core)-brightgreen"/>
  <img src="https://img.shields.io/badge/rules-60-orange"/>
  <img src="https://img.shields.io/badge/MCP%20tools-38-blueviolet"/>
  <img src="https://img.shields.io/badge/tests-686%20passing-success"/>
  <img src="https://img.shields.io/badge/live%20demo-Kubernetes%20Goat-red"/>
</p>

---

## K8sMatrixWarden working with MCP Client
[[Watch the K8sMatrixWarden Demo Video]](https://github.com/rohitsoni1209/K8sMatrixWarden/raw/refs/heads/main/K8sMatrixWarden-working.mp4)


## What it does in 90 seconds

1. **Scan** — 60 detection rules across 11 domain shards (cluster control plane, RBAC, network, secrets, admission control, supply chain, compliance, etc.)
2. **Correlate** — joins static findings to live Falco/audit runtime events → **confirmed** (the event names the exact resource a finding is on — actively exploited), **corroborated** (same tactic/namespace, no resource link), or **runtime-only** (novel behavior)
3. **Reach** — tags every workload finding with its live attack vector without ever lowering severity: **🔴 internet-reachable** (a NodePort/LoadBalancer/Ingress fronts the pod and no NetworkPolicy isolates it — fix now), **🟡 post-breach only** (reachable only after an attacker is already in a pod), and **⚠ rbac-escalation** (the pod's ServiceAccount can reach cluster-admin). Turns a flat finding list into a triage queue — e.g. *368 findings → 74 fix-now, 270 deprioritizable* — with nothing hidden. See [`core/reachability.py`](k8smatrixwarden/core/reachability.py).
4. **Visualize** — interactive dashboard with a **pod-exposure inventory bar** (every pod bucketed worst-wins: internet+admin / internet-reachable / cluster-admin SA / post-breach-only, over an honest pod-count denominator), threat matrix heatmap, kill-chain exploit path, attack map (chain + vulnerable resources), MTTD/MTTR timeline, runtime readiness
5. **Report** — PDF/JSON/Markdown/SARIF exports with embedded attack path + per-finding attack vector, CIS Benchmark v1.8 (130 controls), MITRE ATT&CK for Containers, OWASP K8s Top 10 mapping
6. **Attest** — governance compliance audit: maps posture onto **PCI DSS v4.0, SOC 2, ISO 27001:2022, NIST 800-53 rev5** with per-requirement pass/fail/evidence and "N findings block PCI-DSS attestation" — auditor-facing PDF/HTML, not a finding dump
7. **Federate** — multi-cluster blast radius: correlates saved scans across clusters and flags **shared non-default identities** (same custom ClusterRole / ServiceAccount / cloud IAM role in >1 cluster; built-in defaults excluded) as **candidate** cross-cluster lateral-movement paths to verify — "if prod is compromised, staging may fall too — here's the shared role to check"

**38 MCP tools** (Cursor, Claude Code, VS Code Agent mode) — conversational API for scanning, correlation, RBAC generation, threat matrix building.

**Zero dependencies** in the core engine — pure Python stdlib, no database, runs offline.

---

## Why this matters

| Tool | Finds weaknesses | Shows runtime behavior | Correlates both | Attack path |
|------|---|---|---|---|
| **Trivy** | ✅ CVEs in images | ❌ | ❌ | ❌ |
| **kubescape** | ✅ Config misconfigs | ❌ | ❌ | ❌ |
| **Falco** | ❌ | ✅ Syscalls & audit | ❌ | ❌ |
| **kube-bench** | ✅ CIS controls | ❌ | ❌ | ❌ |
| **K8sMatrixWarden** | ✅ | ✅ | ✅ **Confirmed exploitation** | ✅ Kill-chain |

**The gap:** Trivy catches that a Pod can run privileged. Falco sees a privileged-only syscall. Nobody connects them — until now.
**This tool:** "Found 358 static weaknesses. Of those, 4 are being exploited **right now**. Here's how the attacker chains them."

---

## Live demo (Kubernetes Goat)

```bash
# Scan live Kubernetes Goat (runs on minikube, kind, or Docker Desktop)
pip install -e ".[live]"
python -m k8smatrixwarden scan --live --name "goat"

# Open dashboard
python -m k8smatrixwarden web --port 8080
# → http://127.0.0.1:8080
# → Overview tab: risk, evidence coverage, assessment confidence
# → Attack Path tab: kill-chain (tactic layer) + evidence-backed routes (resource layer)
# → Findings tab: expand any finding for its NetworkPolicy posture and RBAC escalation path
# → Runtime tab: load Falco events → see correlation in action
```

**Measured on Kubernetes Goat** (Docker Desktop Kubernetes, 30 pods, this repository's
current build):

- 463 findings (22 CRITICAL, 203 HIGH, 238 MEDIUM) — risk **9.8/10 Critical**
- Evidence coverage **95.5%**, basis `measured`; assessment confidence 95.5% (High). The
  missing 4.5% is Cloud IAM, which has no Kubernetes API path on a local cluster and is
  reported as unread rather than as clean
- **21 findings carry a multi-hop RBAC escalation path**, e.g.
  `ServiceAccount/local-path-provisioner-service-account → RoleBinding/local-path-provisioner-bind → Role/local-path-provisioner-role → create-workload`
- 9 tactics chained (reaches Impact) + **25 evidence-backed resource routes**, the strongest
  being `Internet → NodePort Service → Deployment/internal-proxy-deploy`
- Full scan, including RBAC graph and NetworkPolicy evaluation: **~213 ms**

No Falco was installed on that cluster, so the runtime correlation reported zero events and
said so — it did not silently render as "nothing is being exploited".

---

---

## Requirements

**Python 3.10 – 3.14.** Nothing else — the core engine imports only the standard library, so
there is no dependency that can lag a new Python release. The 3.10 floor comes from the optional
extras (`mcp`, `kubernetes` and `fpdf2` each require 3.10+), not from the engine.

Verified on 3.11 and 3.14 (686/686 tests on both). **3.11 or 3.12 is the safest choice** for a
real deployment — every extra has shipped wheels for them for years.

If you have more than one Python installed, note that MCP clients launch whichever one `python`
resolves to. See [Troubleshooting](K8sMatrixWarden-doc.html#troubleshooting) if tools don't appear.

## Prerequisites

Only for scanning a **real cluster** — `--mock` needs none of this and is the default:

- A valid `kubeconfig` for the target cluster
- Read-only access to the target Kubernetes cluster
- Cloud CLI configured (AWS, Azure, GCP) for managed Kubernetes clusters.

## Installation & Setup

### 1. With an MCP client (the intended way)

The repository ships the config files for every MCP client that supports project-local
discovery, so there is nothing to write and no path to fill in.

| Client | File it reads | Ships in this repo? |
|---|---|---|
| **Cursor** | `.cursor/mcp.json` | ✅ |
| **Claude Code** (CLI, desktop app, VS Code / JetBrains extensions) | `.mcp.json` | ✅ |
| **VS Code** — Copilot Chat, *Agent* mode (1.102+) | `.vscode/mcp.json` | ✅ |

**Steps:**

1. **Clone the repository.**
   ```bash
   git clone <repo-url> && cd K8sMatrixWarden
   ```
2. **Open the folder** in your MCP client — Cursor, Claude Code, or VS Code.
3. **Enable the server and confirm the tools load.**
   - *Cursor* — **Settings → Tools & MCP**; `k8smatrixwarden` should be listed, toggled on, with
     38 tools under it.
   - *Claude Code* — run `/mcp`, approve the project-scoped server the first time it prompts.
   - *VS Code* — open Copilot Chat, switch the mode dropdown to **Agent**, then check the tools (🛠)
     picker. MCP tools only appear in Agent mode.
4. **Open the agent chat.**
5. **Start running the tool conversationally** — describe what you want; the agent picks the tools.

**Mock scan prompt** (no cluster needed):

> Run an `intelligent_scan` for privilege escalation on the mock cluster and summarize the
> findings, and also start the web interface.

**Live scan prompt:**

> Use k8smatrixwarden and run a live scan of my cluster covering the whole attack matrix.
> kubeconfig `"C:\Users\me\.kube\config"`, name it `"Prod live Scan"`, and give me a markdown
> report. Also start the web interface.

Scans run over MCP save to the shared report store by default, so anything the agent scans appears
immediately in the web dashboard's **Scan history**.

<details>
<summary><strong>Claude Desktop and Windsurf</strong> — one paste, once</summary>

These read a single machine-wide config rather than a project file, so no repo file can reach
them. Install once — an **editable** install puts the package on `sys.path` permanently, so the
server starts no matter which directory the client spawns it in:

```bash
pip install -e ".[mcp]"     # from the repo root
```

Then add to that client's config:

```json
{
  "mcpServers": {
    "k8smatrixwarden": {
      "command": "python",
      "args": ["-m", "k8smatrixwarden", "mcp"]
    }
  }
}
```

> The `k8smatrixwarden mcp` console script works too, but is more fragile — `pip` installs that
> launcher into a per-interpreter `Scripts/` (Windows) or `bin/` directory that is **often not on
> `PATH`**, and with several Pythons installed you get one launcher each with no control over which
> wins. `python -m` avoids both problems.

| Client | Config file |
|---|---|
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` — or *Settings → Developer → Edit Config* |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Restart the client after editing.
</details>

> **Why not one file for all clients?** MCP standardizes the *protocol*, not *config discovery* —
> each client picked its own filename, directory and JSON shape (VS Code nests under `servers`
> with `"type": "stdio"`; everyone else uses `mcpServers`). The **server** never forks: all five
> clients run the identical `k8smatrixwarden mcp` process and see the identical 38 tools.

Verify the server independently at any time:

```bash
python -m k8smatrixwarden mcp --list-tools     # prints all 38, without starting the server
```

### 2. From the command line

The **core needs nothing** — it runs on the Python standard library alone against a bundled,
deliberately-insecure mock cluster.

```bash
python -m k8smatrixwarden doctor        # sanity-check the install
python -m k8smatrixwarden scan --mock   # full scan, zero dependencies
```

Optional extras unlock live scanning / prettier output / MCP / PDF export:

```bash
pip install -e .              # installs the `k8smatrixwarden` command
pip install -e ".[live]"      # + kubernetes client for real clusters
pip install -e ".[pretty]"    # + rich terminal tables
pip install -e ".[mcp]"       # + MCP protocol server
pip install -e ".[pdf]"       # + fpdf2, for `-o pdf` report export
pip install -e ".[all]"       # everything
```

## TL;DR

```bash
# no install, no dependencies — runs against a bundled insecure mock cluster
python -m k8smatrixwarden scan --mock

# name a scan — the saved report is "<name> + date + time" in the dashboard history
python -m k8smatrixwarden scan --mock --name "Prod nightly"

# scan by MITRE tactic  (resolves across shards through ONE registry index)
python -m k8smatrixwarden scan --tactic Persistence --mock

# scan by technique / outcome alias
python -m k8smatrixwarden scan --technique "Container Escape" --mock

# natural language (one-shot)
python -m k8smatrixwarden scan "scan production for Persistence" --mock

# interactive chat assistant (back-and-forth, confirm-then-run)
python -m k8smatrixwarden chat

# see what a request resolves to WITHOUT scanning
python -m k8smatrixwarden scan --module rbac_identity --dry-run
```

## Why this design

The whole tool turns on one idea: **domain shards are the execution boundary (vertical), MITRE
tactics are cross-cutting tags (horizontal), and they are orthogonal.** A rule like `hostPath
mount` lives in **one** shard but is tagged with three tactics (Persistence + Privilege Escalation
+ Lateral Movement). Every scan — by resource, tactic, technique, module, rule, alias, or
compliance framework — resolves through a single registry index to a set of `rule_id`s, then runs
against **one shared evidence fetch**.

```
Orchestrator (intent→scope→selector) → Registry.resolve(selector) → rule_id set
   → Evidence Collector (fetch once, scope-constrained) → Detection Engine (parallel)
   → Aggregator (dedupe+merge tags) → Risk Scoring (attack-path aware) → Reporting
```

## Core differentiators

- **Scan × runtime correlation** — joins static findings to live Falco/audit events by MITRE tactic: `confirmed` (actively exploited), `corroborated` (behavior aligns), `runtime-only` (new behavior)
- **Drift detection** — flags runtime behavior contradicting declared posture (uid 0 despite `runAsNonRoot`, writes despite `readOnlyRootFilesystem`)
- **Attack paths in two layers** — the *tactic* chain (`path_type: tactic`; Initial Access → Impact, ATT&CK-navigator convention, adjacency) **and** the *resource* chain (`path_type: resource` / `observed`; `Internet → Service → Pod → ServiceAccount → RoleBinding → ClusterRole → secrets/get`), where every hop is read off a real object and carries the reason it exists. Two findings sharing a tactic are never claimed to be connected. A runtime event marks only the hops it named (`observed_nodes`), never the whole chain ([`core/attack_path.py`](k8smatrixwarden/core/attack_path.py))
- **Bounded analysis says so** — every graph walk reports `analysis_status: complete | truncated` with the bound that stopped it, so a capped result can't be mistaken for an exhaustive one
- **Multi-hop RBAC graph** — RBAC modelled as a graph, not a permission checklist: shortest, cycle-safe, namespace-aware escalation paths that name the binding and role behind every claim, including second-hop routes (*read this Secret → become that ServiceAccount → its permissions*). A capability whose target does not exist in the cluster is reported as a capability, never as an escalation ([`core/rbac_graph.py`](k8smatrixwarden/core/rbac_graph.py))
- **Complete NetworkPolicy evaluation** — `matchLabels` **and** `matchExpressions` (`In` / `NotIn` / `Exists` / `DoesNotExist`), `podSelector` + `namespaceSelector` peers, `ipBlock` with `except`, `policyTypes` defaulting, additive union across policies, in **both** directions. A policy this build cannot evaluate is `partial`, which never reads as isolation ([`core/netpol.py`](k8smatrixwarden/core/netpol.py))
- **Reachability tagging** — per-workload attack vector (internet-reachable / post-breach-only / rbac-escalation-to-cluster-admin) computed from Service/Ingress exposure, NetworkPolicy isolation, and the pod's ServiceAccount RBAC — context that prioritizes findings without ever changing severity ([`core/reachability.py`](k8smatrixwarden/core/reachability.py))
- **External graph tools (optional)** — passthrough runners for [KubeHound](https://github.com/DataDog/KubeHound) and [IceKube](https://github.com/ReversecLabs/IceKube) when a customer wants deep multi-hop attack-path graphs alongside posture ([`integrations/external_graph.py`](k8smatrixwarden/integrations/external_graph.py))
- **7-tab SPA dashboard** — Overview (KPIs), Findings (search/filter/sort), Threat Matrix (heatmap), Attack Path, Attack Map (chain + resources), Runtime, Scan history
- **Coverage accounting** — 77.8% scan + 85.2% including runtime detections (techniques only visible live are not counted as gaps)
- **Honest evidence reporting** — fails with real credential errors, never silently collects nothing
- **Safe by default** — dashboard binds `127.0.0.1`, kubeconfig auth is sandbox-isolated

## Commands

| Command | What it does |
|---|---|
| `k8smatrixwarden mcp [--list-tools]` | **Run the MCP server**, or list its 38 tools |
| `k8smatrixwarden chat` | **Interactive conversational assistant** (plain-English, confirm-then-run) |
| `k8smatrixwarden scan ...` | Run a scan by scope × selector, or a one-shot natural-language query |
| `k8smatrixwarden web [--port 8080]` | **Security Dashboard** web UI — browse scans, open reports, view the per-scan threat matrix, run a scan. Binds `127.0.0.1` |
| `k8smatrixwarden matrix [--coverage]` | Print the **Kubernetes Threat Matrix** for a scan (or global detection coverage) |
| `k8smatrixwarden rules [--module M] [--tactic T]` | List the rule registry (each tagged `surface=scan`) |
| `k8smatrixwarden coverage` | MITRE tactic coverage (rules per tactic) |
| `k8smatrixwarden cis ...` | Full **CIS Kubernetes Benchmark v1.8** (all 130 controls) |
| `k8smatrixwarden compliance ...` | Governance audit: **PCI DSS 4.0 · SOC 2 · ISO 27001:2022 · NIST 800-53 r5** |
| `k8smatrixwarden federation` | **Cross-cluster blast radius** from the saved scans of each cluster |
| `k8smatrixwarden posture` | **What changed** since the previous scan: new / resolved / persistent / regressed |
| `k8smatrixwarden report list / download` | List & re-download saved scans in any format/filename (scans are saved automatically) |
| `k8smatrixwarden roles` | Per-plugin scoped RBAC ClusterRoles |
| `k8smatrixwarden doctor [--probe]` | **Full health check** — shards, config, rules, taxonomy, MCP, report formats, runtime, LLM, deps, read-only invariants |

### Scan options

```
scope    : --namespace/-n · --pod · --workload KIND/name · --node · --image · --helm-release
selector : --tactic · --technique · --module · --rule · --alias · --framework · --severity-min
mode     : --mock (default) · --live · --fixture PATH · --kubeconfig PATH · --context NAME
output   : -o {terminal,text,markdown,json,sarif,html,pdf} · --output-file PATH
naming   : --name "<scan name>"     report is named "<name> + date + time"
store    : (saved by default → web dashboard) · --no-save to skip · --reports-dir PATH
flow     : --dry-run · --yes · --fail-on {LOW,MEDIUM,HIGH,CRITICAL}   (CI mode)
```

> **Scans are saved by default.** Every `scan` (and every MCP `run_scan`/`intelligent_scan`)
> persists to the shared report store, so it shows up immediately in the web dashboard's
> **Scan history** — no `--save` needed. Use `--no-save` for a throwaway run.

Examples:

```bash
python -m k8smatrixwarden scan -n production --tactic "Credential Access" -o markdown --mock
python -m k8smatrixwarden scan --framework CIS -o json --mock
python -m k8smatrixwarden scan --technique "Exposed Secrets" --mock
python -m k8smatrixwarden scan --live --fail-on CRITICAL -o sarif --output-file results.sarif
```

### Full CIS Kubernetes Benchmark v1.8 (all 130 controls)

```bash
python -m k8smatrixwarden cis --mock                          # 130 controls, dashboard + failures
python -m k8smatrixwarden cis --kube-bench-json kb.json       # resolve the 31 node file controls
python -m k8smatrixwarden cis --mock --profile eks            # managed: control plane → NA
```

Every control gets a status — `PASS` / `FAIL` / `MANUAL` / `NA` / `NEEDS_NODE` — so nothing
is missed. **65 of 130 controls are evaluated straight from the K8s API** (25 native rules +
2 builtin + 38 control-plane/kubelet **process-flag** checks recovered from static-pod specs),
only **31** true file-permission controls need kube-bench (`--kube-bench-json`), and 34 are
CIS-designated manual reviews (surfaced, never auto-passed).

## Architecture map

| Component | Code |
|---|---|
| Rule model | `k8smatrixwarden/core/models.py` (`Rule`, `Finding`, `Scope`, `Selector`, `ScanRequest`) |
| Rule / Scanner registries | `k8smatrixwarden/core/registry.py` |
| MITRE Mapping Engine | `k8smatrixwarden/core/mapping_engine.py` — the single selector → rule_id path |
| Evidence Collector | `k8smatrixwarden/core/evidence.py` (mock + live, camelCase, fetch-once) |
| Detection Engine | `k8smatrixwarden/core/detection.py` (parallel, per-rule isolation) |
| Result Aggregator | `k8smatrixwarden/core/aggregator.py` |
| Risk Scoring | `k8smatrixwarden/core/scoring.py` (attack-path bonus) |
| Reporting | `k8smatrixwarden/core/reporting.py` (7 formats) + `finding_context.py` (shared Summary/Standards/MITRE/Impact/Validation content) + `pdf_report.py` |
| Threat Matrix | `k8smatrixwarden/core/threat_matrix.py` + `threat_matrix_render.py` |
| Plugin model | `k8smatrixwarden/core/plugin.py` |
| 11 Domain Shards | `k8smatrixwarden/shards/*` |
| Orchestrator / Scanner / Runtime agents | `k8smatrixwarden/agents/*` |
| MCP Server | `k8smatrixwarden/mcp/` — **38 tools**: knowledge (15), scan/audit/runtime/graph analysis (15), reports & stored-scan analysis (7), platform (1). Every parameter carries a schema description. Read-only: no remediation/apply tool is exposed. |
| Scan × Runtime correlation | `k8smatrixwarden/core/correlation.py` |
| RBAC graph | `k8smatrixwarden/core/rbac_graph.py` — principals → bindings → roles → permissions → escalation, multi-hop, cycle-safe |
| NetworkPolicy engine | `k8smatrixwarden/core/netpol.py` — matchLabels + matchExpressions, ingress **and** egress, `partial`/`unknown` when a policy can't be evaluated |
| Resource-level attack paths | `k8smatrixwarden/core/attack_path.py` — the causal layer beneath the tactic chain |
| Reachability tagging | `k8smatrixwarden/core/reachability.py` (attack vector + structural hop chain) |
| Evidence coverage & confidence | `k8smatrixwarden/core/coverage.py` |
| Finding explanation | `k8smatrixwarden/core/explain.py` — one structured shape, every surface |
| Historical posture | `k8smatrixwarden/core/posture.py` + `report_store.py` (timeline) |
| Health checks | `k8smatrixwarden/doctor.py` (PASS / WARN / FAIL / NOT CONFIGURED) |
| Optional LLM layer | `k8smatrixwarden/agents/llm_provider.py` — provider/model agnostic, never used by the scanner |
| Interactive Dashboard | `k8smatrixwarden/web/` — zero-dependency SPA, `/api/dashboard` · `/api/timeline` · `/api/runtime` |
| IST timestamps | `k8smatrixwarden/core/timeutil.py` |
| Taxonomy / Config | `k8smatrixwarden/taxonomy/*.json` · `k8smatrixwarden/config/default_config.json` |

## Optional LLM layer — provider- and model-agnostic

**The scanner never needs an LLM.** Every number in this README (findings, risk, coverage,
threat matrix, attack path, CIS/compliance status) is produced by deterministic Python with
zero model involvement. The optional agent layer only powers the local `chat` REPL's
multi-step tool chaining; an MCP client brings its own model and does not use this at all.

When you do want it, nothing about the provider or model is compiled in — configure it:

```bash
# any OpenAI-compatible endpoint: OpenAI, Azure OpenAI, OpenRouter, Together, Groq,
# vLLM, llama.cpp, LM Studio, Ollama — including fully local models
export K8SMATRIXWARDEN_LLM_PROVIDER=openai-compatible
export K8SMATRIXWARDEN_LLM_BASE_URL=http://localhost:11434/v1
export K8SMATRIXWARDEN_LLM_MODEL=llama3.1:70b

# or a hosted Anthropic model
export K8SMATRIXWARDEN_LLM_PROVIDER=anthropic
export K8SMATRIXWARDEN_LLM_MODEL=<any model your account can call>
export ANTHROPIC_API_KEY=...
```

Equivalent settings live in the `"llm"` block of `k8smatrixwarden/config/agent.json`:

```json
{
  "llm": {
    "provider": "openai-compatible",
    "model": "llama3.1:70b",
    "base_url": "http://localhost:11434/v1",
    "api_key_env": "MY_LOCAL_KEY",
    "extra": {"headers": {"X-Tenant": "sec-team"}}
  }
}
```

| Setting | Env var | Meaning |
|---|---|---|
| `provider` | `K8SMATRIXWARDEN_LLM_PROVIDER` | `anthropic`, `openai`, `azure-openai`, `openai-compatible`, `ollama` |
| `model` | `K8SMATRIXWARDEN_LLM_MODEL` | any model id the endpoint serves — **no model is baked in** |
| `base_url` | `K8SMATRIXWARDEN_LLM_BASE_URL` | endpoint, for self-hosted / gateway / local servers |
| `api_key_env` | `K8SMATRIXWARDEN_LLM_API_KEY_ENV` | name of the variable holding the key (the key itself never goes in a file) |
| — | `K8SMATRIXWARDEN_LLM_API_KEY` | the key directly, when you would rather not use a named variable |
| `extra` | `K8SMATRIXWARDEN_LLM_EXTRA` (JSON) | per-provider extras (custom headers, Azure deployment/api-version) |

**Selection is deterministic, and documented rather than incidental.** Precedence, highest
first:

1. an explicit argument (`resolve_config(provider=…, model=…)`, used by API callers)
2. environment variables
3. the `llm` block of `agent.json`
4. controlled auto-detection, in this fixed order: `ANTHROPIC_API_KEY` → `OPENAI_API_KEY`
   → `AZURE_OPENAI_API_KEY` → `OLLAMA_HOST`

If auto-detection finds **more than one** candidate, the tool refuses to guess: it reports
an ambiguity and asks you to name the provider. It never depends on dictionary or
environment iteration order. With no candidate at all, the agent path simply stays off and
the scanner is unaffected.

**Changing the model is configuration, never a code change.** Check what is active:

```bash
python -m k8smatrixwarden doctor            # reports provider/model/config validity
python -m k8smatrixwarden doctor --probe    # also makes one tiny live call
```

Any LLM problem — no key, wrong model, unreachable endpoint, rate limit, missing SDK — is
reported and the tool falls back to its deterministic path. It can never change what a scan
found. The OpenAI-compatible adapter works with no third-party package at all (stdlib HTTP);
`pip install -e ".[agent]"` adds the Anthropic SDK.

## The 11 domain shards

`① cluster_control_plane · ② workload_pod_security · ③ rbac_identity · ④ network_security ·
⑤ image_supply_chain · ⑥ secrets · ⑦ compliance · ⑧ attack_surface · ⑨ admission_control ·
⑩ cloud_iam · ⑪ log_analysis`

⑪ **log_analysis** answers the question the other ten don't: *if an attacker got in, could
you tell?* The others ask whether a door is open; this one asks whether anyone is writing
down who walked through it — audit policy, retention, log rotation, and whether any
collector ships logs off-node at all.

## Extending

Add a new scanner shard: drop a module in `k8smatrixwarden/shards/` exposing `SHARD = YourShard`
(subclass `DomainShard`, implement `rules()`). The Plugin Loader auto-discovers it, the
Mapping Engine auto-indexes its rules' tags, and a scoped RBAC role is generated from its
declared resource needs. **No engine change.** New MITRE technique? Add its id to
`taxonomy/attack_for_containers.json` and tag rules with it. New framework? Add a `cis:` /
`nsa_cisa:` / `owasp:` tag.

## Tests

```bash
python -m tests.run_tests          # bundled stdlib runner (no pytest needed)
python -m pytest tests/            # also works if pytest is installed
```

## Kubernetes semantics: what is actually validated

RBAC and NetworkPolicy are where a scanner most easily invents or misses a finding, so the
exact semantics are pinned by an adversarial suite
([`tests/test_adversarial.py`](tests/test_adversarial.py)) whose tests are written to make
the tool wrong. Support is claimed only where a test proves it.

**RBAC** — `Role` and `ClusterRole`; `RoleBinding` and `ClusterRoleBinding`; **a
RoleBinding referencing a ClusterRole grants only inside that namespace** and is labelled
as such, never as cluster-admin; `apiGroups` are honoured, so a CustomResource named
`secrets` is not a core Secret; `resourceNames` limit a grant to those objects and never
establish a blanket capability; subresource identity is exact (`pods/exec` ≠ `pods`);
`nonResourceURLs` grant no resource access; wildcards on one axis are not wildcards on the
other; identical ServiceAccount names in different namespaces stay distinct; cycles
terminate.
*Not resolved:* an aggregated ClusterRole's effective rules — reported as **unknown**, never
as empty. *Not traversed:* `User`/`Group` subjects resolve but have no onward hop.

**NetworkPolicy** — `matchLabels` and `matchExpressions` (`In`/`NotIn`/`Exists`/
`DoesNotExist`, with a missing key satisfying `NotIn`); `podSelector` and
`namespaceSelector` peers, including both on one peer (AND) versus separate peers (OR);
`ipBlock` with `except`; `policyTypes` defaulting (omitted ⇒ Ingress only, plus Egress only
when egress rules exist); the additive union across policies, where one allow-all rule
defeats every strict sibling; ingress **and** egress.
*Not modelled:* ports. They are carried and displayed as data, but a port-443-only policy
is treated exactly like an all-ports one — narrowing reachability by port without a port
model would be false precision.

**Workloads** — the same rule fires on `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`,
`ReplicaSet`, `Job` **and `CronJob`** (whose PodSpec nests one level deeper), across
regular, `init` and `ephemeral` containers.

**Pod security** — pod-level settings are defaults a container can override, so a promise
holds only when every container keeps it; an omitted field is never read as an explicit
safe value.

## Confidence, and what the tool refuses to claim

Five different confidences exist because they answer five different questions. They are
kept apart on purpose — collapsing them is how a scanner ends up sounding certain about
evidence it never read. The policy is in
[`core/explain.py`](k8smatrixwarden/core/explain.py) (`CONFIDENCE_POLICY`) and enforced by
[`tests/test_integration_pipeline.py`](tests/test_integration_pipeline.py):

| Confidence | Answers | Values |
|---|---|---|
| Evidence | was this resource type read, and how do we know the fraction? | `measured` · `estimated` · `heuristic` · `unknown` |
| Assessment | how much of the cluster did the scan see? | 0–100%, a function of coverage **only** |
| Finding | how much to trust *this* conclusion? | 0–1 with the reasons that produced it |
| Correlation | how tightly does a runtime event tie to a finding? | `confirmed` · `corroborated` · `runtime-only` |
| Attack path | how strongly is this route evidenced? | `configuration-only` · `corroborated` · `observed` |

The rules that keep them coherent:

1. Nothing is more confident than the evidence under it. An unread resource type produces
   **no claim**, not a confident absence.
2. Only a **resource-level** runtime match earns certainty. Activity elsewhere in the
   namespace corroborates, and is capped below it.
3. A runtime event at one hop does **not** make a multi-hop path observed. The path names
   which hops were witnessed and says the rest is configuration-derived.
4. Confidence never changes severity and never hides a finding. A low-confidence CRITICAL
   is still a CRITICAL — it just needs verifying first.
5. `unknown` and `partial` are values, not synonyms for `false` or `safe`. They propagate
   as themselves through coverage, NetworkPolicy, RBAC, the reports and the dashboard.

## Safety

**Detect-and-report only.** This tool never mutates the cluster from any surface — it has
no remediation/apply path. Scanning reads the cluster (get/list/watch only), and every
output (reports, threat matrix, MCP tools, web dashboard) is derived from that read-only
snapshot. The MCP surface exposes no write-capable tool, enforced by
`tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed`.

Before scanning anything you care about, generate and apply the tool's own least-privilege RBAC —
one scoped `ClusterRole` per shard, every verb `get`/`list`/`watch`:

```bash
k8smatrixwarden roles --bind --output-file k8smatrixwarden-rbac.json
kubectl apply -f k8smatrixwarden-rbac.json
```

## Documentation

**[`K8sMatrixWarden-doc.html`](K8sMatrixWarden-doc.html)** — open it directly in a browser. One
self-contained, searchable page (dark/light aware) covering everything: architecture and design
decisions, the risk-scoring math, all 11 shards' rule catalogs, MITRE / OWASP / CIS coverage, the
complete CLI flag reference, configuration, live-cluster setup, the runtime-correlation layer, the
full 38-tool MCP reference with per-client setup, known limitations, and troubleshooting.

## License

See [LICENSE](LICENSE).
