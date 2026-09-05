# K8sMatrixWarden

## Getting Started Guide

A complete onboarding guide for new users. No prior experience with this tool is assumed.

**Version 1.0** | Read-only Kubernetes security scanner

---

### About this guide

This guide takes you from zero to a working security scan of a production Kubernetes
cluster. It is written for readers who may be new to Kubernetes security tooling, so
concepts are explained before they are used.

You do not need a Kubernetes cluster, a cloud account, or any dependencies to begin. The
product ships with a sample cluster so you can learn the tool offline before pointing it
at anything real.

**A note on safety.** K8sMatrixWarden never modifies your cluster. It has no remediation
path, no apply command, and no write-capable operation on any interface. Every action
described in this guide is read-only. The single exception is Section 11, where *you*
apply an RBAC manifest that the tool generates for you.

---

## Table of contents

**Part I: Understanding the product**

1. [Product overview](#1-product-overview)
2. [How the scanner works](#2-how-the-scanner-works)
3. [Understanding the results](#3-understanding-the-results)

**Part II: Installation and first run**

4. [System requirements](#4-system-requirements)
5. [Installation](#5-installation)
6. [Your first scan](#6-your-first-scan)

**Part III: Connecting to a real cluster**

7. [How Kubernetes access works](#7-how-kubernetes-access-works)
8. [Local clusters](#8-local-clusters)
9. [Amazon EKS](#9-amazon-eks)
10. [Google GKE](#10-google-gke)
11. [Microsoft AKS](#11-microsoft-aks)
12. [Least-privilege access for the scanner](#12-least-privilege-access-for-the-scanner)
13. [Running a live scan](#13-running-a-live-scan)

**Part IV: Working with the product**

14. [The web dashboard](#14-the-web-dashboard)
15. [Runtime correlation](#15-runtime-correlation)
16. [Reports and scan history](#16-reports-and-scan-history)
17. [Compliance and benchmarks](#17-compliance-and-benchmarks)
18. [CI/CD integration](#18-cicd-integration)
19. [AI agent integration (MCP)](#19-ai-agent-integration-mcp)

**Part V: Reference**

20. [Command reference](#20-command-reference)
21. [Configuration](#21-configuration)
22. [Troubleshooting](#22-troubleshooting)
23. [Glossary](#23-glossary)
24. [The confidence model](#24-the-confidence-model)

---

# Part I: Understanding the product

## 1. Product overview

### 1.1 What the product does

K8sMatrixWarden is a Kubernetes security scanner. Most scanners answer one question. This
product answers three, and connects the answers to each other.

**Question 1: What is misconfigured?**

The scanner applies 62 detection rules across 11 security domains. It identifies issues
such as privileged containers, overly broad RBAC permissions, missing network
segmentation, exposed management interfaces, unencrypted secret storage, and inadequate
audit logging.

**Question 2: Is any of it being exploited right now?**

The scanner correlates its static findings against live runtime activity from Falco and
from the Kubernetes audit log. When a runtime event names the exact resource that a static
finding was raised on, that finding is marked **confirmed**, meaning the weakness is under
active exploitation rather than merely present.

**Question 3: What should be fixed first?**

Every workload finding is tagged with its real attack vector, computed from Service and
Ingress exposure, NetworkPolicy isolation, and the ServiceAccount permissions available to
the pod. This separates issues an external attacker can reach today from issues that
require an attacker to already be inside the cluster.

### 1.2 Where the product fits

| Capability | Trivy | kubescape | Falco | kube-bench | K8sMatrixWarden |
|---|:---:|:---:|:---:|:---:|:---:|
| Configuration weaknesses | Yes | Yes | No | Yes | Yes |
| Runtime behavior | No | No | Yes | No | Yes |
| Correlation of the two | No | No | No | No | **Yes** |
| Attack path reconstruction | No | No | No | No | **Yes** |
| Image CVE scanning | **Yes** | Yes | No | No | No |

The gap this product closes: a configuration scanner reports that a pod *can* run
privileged. A runtime sensor reports a syscall that only a privileged pod could make.
Neither connects the two observations. K8sMatrixWarden does.

### 1.3 Capabilities

- Kubernetes configuration analysis across 11 domains
- Multi-hop RBAC privilege escalation path analysis
- NetworkPolicy evaluation in both directions
- Runtime correlation with Falco and Kubernetes audit events
- CIS Kubernetes Benchmark v1.8, all 130 controls
- Governance frameworks: PCI DSS v4.0, SOC 2, ISO 27001:2022, NIST 800-53 rev5
- Cross-cluster blast radius analysis

---

## 2. How the scanner works

### 2.1 The two-axis model

The product is built on one organizing idea: **where a rule lives and what a rule means
are separate concerns.**

**Domain shards** define where a rule lives. There are 11, and they form the execution
boundary of the scanner.

| Shard | Covers |
|---|---|
| `cluster_control_plane` | API server, etcd, kubelet, and Kubernetes version |
| `workload_pod_security` | Pod and container security context |
| `rbac_identity` | Roles, bindings, ServiceAccounts, and privilege escalation |
| `network_security` | Services, Ingress, NetworkPolicy, and exposure |
| `image_supply_chain` | Image references, tags, signatures, and pull policy |
| `secrets` | Secret handling, storage, and exposure |
| `compliance` | Pod Security Admission and baseline posture |
| `attack_surface` | Cross-cutting exposure analysis |
| `admission_control` | Admission webhooks and scheduled jobs |
| `cloud_iam` | Cloud identity reachable from the cluster |
| `log_analysis` | Audit policy, retention, rotation, and log shipping |

`log_analysis` answers a question the other ten do not. The others ask whether a door is
unlocked. This one asks whether anyone is recording who walked through it.

**MITRE ATT&CK tactics** define what a rule means to an attacker. Tactics are tags applied
across shards, not locations within them. A single rule such as "hostPath mount" lives in
exactly one shard but carries three tactics: Persistence, Privilege Escalation, and
Lateral Movement.

Keeping these axes separate is what allows every method of requesting a scan, whether by
namespace, tactic, technique, shard, rule identifier, alias, or compliance framework, to
resolve through one index into a set of rule identifiers.

### 2.2 The scan pipeline

```
Orchestrator          interprets intent, resolves scope and selector
       |
Registry              resolves the selector to a set of rule identifiers
       |
Evidence Collector    reads the cluster ONCE, constrained to the scope
       |
Detection Engine      runs the selected rules in parallel, isolated per rule
       |
Aggregator            deduplicates findings and merges tags
       |
Risk Scoring          applies attack-path-aware scoring
       |
Reporting             renders to any of 8 output formats
```

The single most important property here is **fetch once**. All selected rules evaluate
against one shared, consistent read of the cluster. This makes scans fast, roughly 213
milliseconds for a full 30-pod cluster including RBAC graph construction and NetworkPolicy
evaluation, and it guarantees that two rules never disagree because they read the cluster
at different moments.

### 2.3 Two detection surfaces

The product maintains two independent detection surfaces that feed one evidence model.

| Surface | Data source | Question answered | Rule count |
|---|---|---|---|
| **Scan** | Kubernetes API objects, point in time | Is this door unlocked? | 62 |
| **Runtime** | Falco alerts and Kubernetes audit events | Did somebody walk through it? | 11 |

These catalogs are deliberately separate and are never merged. A scan rule describes a
configuration state. A runtime rule describes an observed action. Correlating them is a
distinct step with its own confidence vocabulary, described in Section 3.3.

---

## 3. Understanding the results

Read this section before your first scan. It explains three output concepts that surprise
new users.

### 3.1 Two finding counts, both correct

Reports publish two numbers. Neither replaces the other.

| Field | Meaning |
|---|---|
| `resource_findings` | Every Kubernetes object carrying the flaw. This is the evidence. |
| `workload_issues` | One entry per rule per owning workload. This is the work. |

A live scan produced **517** resource findings and **173** workload issues. The difference
is not duplication. When a Deployment is misconfigured, Kubernetes propagates that
specification to its ReplicaSets and then to every Pod. The scanner correctly reports the
flaw on all of them, because all of them genuinely carry it.

Use `resource_findings` when you need the complete evidence trail. Use `workload_issues`
when you need to know how many fixes you actually have to make.

Grouping follows `ownerReferences` only, never a name prefix. Namespace and cluster are
part of workload identity, so two workloads with the same name in different namespaces are
never collapsed into one.

**Risk scoring uses the workload count.** The score sums one contributor per workload
issue, not per Kubernetes object, so a controller's replica chain cannot inflate it. This
is not a discount: two distinct workloads with the same flaw still score twice, and a
standalone Pod scores on its own.

### 3.2 Attack vectors, for prioritization

Every workload finding carries an attack vector tag. This tag exists to build a triage
queue.

| Tag | Meaning | Priority |
|---|---|---|
| **Internet-reachable** | A NodePort, LoadBalancer, or Ingress routes external traffic to this pod, and no NetworkPolicy isolates it. | Fix now |
| **Post-breach only** | Exploitable only by an attacker who is already executing inside a pod. | Defense in depth |
| **RBAC escalation** | This pod's ServiceAccount can reach cluster-admin. | Investigate |

**The tag never changes severity and never hides a finding.** A CRITICAL finding tagged
"post-breach only" remains CRITICAL. The tag adds context for sequencing work; it does not
downgrade risk.

In practice this converts a flat list into an ordered queue. One measured scan reduced 368
findings to 74 that required immediate attention and 270 that could be safely
deprioritized, with nothing hidden from view.

### 3.3 Correlation verdicts

When runtime data is available, each static finding may receive a correlation verdict.

| Verdict | Meaning |
|---|---|
| **Confirmed** | A live event named the exact resource this finding is on. The weakness is being exploited. |
| **Corroborated** | Activity in the same tactic and namespace, but no resource-level link. |
| **Runtime-only** | Observed behavior with no matching static finding. |

Only a resource-level match earns "confirmed". Activity elsewhere in the namespace
corroborates and is deliberately capped below certainty.

### 3.4 Reading a single finding

Every finding renders the same fields. Each exists for a reason.

```
rule      : the detection that fired, and the shard that owns it
mitre     : the ATT&CK tactic and technique
owasp     : OWASP Kubernetes Top 10 category, and the CIS control if mapped
impact    : exploitability, blast radius, and computed score
vector    : the attack vector tag from Section 3.2
detail    : the exact field on the exact object
why       : why an attacker cares about this
verify    : the kubectl command to confirm the finding yourself
```

The `verify` field is deliberate. Every claim the scanner makes can be independently
checked with a single command, without trusting the scanner.

---

# Part II: Installation and first run

## 4. System requirements

### 4.1 Required

**Python 3.10 or later, and nothing else.**

The core engine imports only the Python standard library. There is no database, no
external service, and no required package. It runs fully offline.

```bash
python --version
```

**Supported versions: 3.10 through 3.14.** The 3.10 floor is imposed by the optional
extras, not by the engine. **Python 3.11 or 3.12 is recommended for production use**,
because every optional extra has shipped prebuilt packages for those versions for years.
The full test suite of 966 tests passes on both 3.11 and 3.14.

### 4.2 Optional, by capability

Nothing below is needed to evaluate the product. Add each item only when you want that
capability.

| To do this | You need | Install command |
|---|---|---|
| Scan a real cluster | `kubernetes` package and a kubeconfig | `pip install -e ".[live]"` |
| Formatted terminal tables | `rich` | `pip install -e ".[pretty]"` |
| Use from Cursor, Claude, or VS Code | `mcp` | `pip install -e ".[mcp]"` |
| Export PDF reports | `fpdf2` | `pip install -e ".[pdf]"` |
| Export Excel workbooks | `openpyxl` | `pip install -e ".[excel]"` |
| Local chat assistant with an LLM | `anthropic`, or any OpenAI-compatible endpoint | `pip install -e ".[agent]"` |
| All of the above | | `pip install -e ".[all]"` |

### 4.3 Cluster access requirements

Needed only when scanning a real cluster.

- A valid kubeconfig file for the target cluster
- Read-only access to the Kubernetes API
- For managed clusters only: the matching cloud CLI, which is explained in Section 7.4

**kubectl is not required.** The product communicates with the Kubernetes API directly
through the Python client. kubectl is useful for verifying things yourself, and this guide
uses it for that purpose, but the product does not depend on it.

---

## 5. Installation

### 5.1 Obtain the source

```bash
git clone <repository-url>
cd K8sMatrixWarden
```

### 5.2 Verify the installation

Run the health check first. Always run this before reporting a problem.

```bash
python -m k8smatrixwarden doctor
```

Expected result on a fresh checkout:

```
20 pass · 0 warn · 0 fail · 7 not configured
```

Reading the output:

| Status | Meaning | Action |
|---|---|---|
| `PASS` | Working correctly | None |
| `NOT CONFIGURED` | An optional extra is absent | None, unless you want that capability |
| `WARN` | Functional, with a caveat | Read the message |
| `FAIL` | Broken | Must be resolved |

`FAIL` is the only status that indicates a problem.

The doctor command validates 20 items: every shard and rule loaded correctly, every MITRE
technique identifier resolves against the vendored ATT&CK taxonomy, every composite alias
resolves to real rule identifiers, no duplicate rule identifiers exist across shards, all
8 report formats render, the runtime catalog loaded, and the generated RBAC contains only
read verbs.

For the detail behind every check:

```bash
python -m k8smatrixwarden doctor --verbose
```

### 5.3 Install optional extras

An **editable install is recommended**. It places the package permanently on the Python
path, which allows AI agent clients and any working directory to locate it.

```bash
pip install -e ".[all]"
```

Or install only what you need:

```bash
pip install -e ".[live]"     # real cluster scanning
pip install -e ".[mcp]"      # AI agent integration
pip install -e ".[pdf]"      # PDF export
```

### 5.4 Invocation: prefer the module form

After installation, two invocation styles work:

```bash
python -m k8smatrixwarden doctor     # module form, recommended
k8smatrixwarden doctor               # console script
```

**Use the module form.** `pip` installs the console script into a per-interpreter
directory, `Scripts/` on Windows or `bin/` elsewhere, which is frequently absent from
`PATH`. On a machine with several Python installations you get one launcher per
interpreter with no control over which one resolves first. The module form always uses the
interpreter you invoked.

With multiple Python versions installed, be explicit:

```bash
py -3.12 -m pip install -e ".[all]"
py -3.12 -m k8smatrixwarden doctor
```

### 5.5 Choosing an interface

The product offers three interfaces over the same engine. They produce identical results,
and scans from any of them are saved to the same report store.

| Interface | Best for | Section |
|---|---|---|
| **AI agent client (MCP)** | The intended primary workflow. Describe what you want; the agent selects from 47 tools. | [19](#19-ai-agent-integration-mcp) |
| **Command line** | Scripting, CI pipelines, and precise control over scope and selectors. | [13](#13-running-a-live-scan) |
| **Web dashboard** | Reviewing results, browsing scan history, and sharing findings. | [14](#14-the-web-dashboard) |

This guide teaches the command line first, because it makes the underlying model visible.
Once the concepts in Part I are familiar, the agent interface is usually faster for daily
work.

---

## 6. Your first scan

The product ships with a deliberately insecure sample cluster. Everything in this section
works offline, with no cluster, no cloud account, and no dependencies installed.

### 6.1 Run a scan

```bash
python -m k8smatrixwarden scan --mock
```

`--mock` is the default mode. Findings are grouped by severity, and each renders the field
set described in Section 3.4.

Read one finding closely before moving on. The output is dense by design, and every field
is intended to be actionable.

### 6.2 Explore without scanning

These commands inspect the product itself rather than a cluster.

```bash
# the full rule catalog
python -m k8smatrixwarden rules

# rules in one domain
python -m k8smatrixwarden rules --module rbac_identity

# MITRE tactic coverage, expressed as rules per tactic
python -m k8smatrixwarden coverage

# the global threat matrix across all rules
python -m k8smatrixwarden matrix --coverage

# resolve a selector and show which rules would run, without scanning
python -m k8smatrixwarden scan --module secrets --dry-run
```

`--dry-run` is worth adopting as a habit. It answers "what is this command about to do"
without touching anything.

### 6.3 Open the dashboard

Scans are saved automatically, so the dashboard already has data from Section 6.1.

```bash
python -m k8smatrixwarden web --port 8080 --open
```

This serves `http://127.0.0.1:8080`. See Section 14 for a description of each tab and the
relevant security considerations.

### 6.4 Practice with selectors

```bash
# by MITRE tactic
python -m k8smatrixwarden scan --mock --tactic "Credential Access"

# by technique or composite alias
python -m k8smatrixwarden scan --mock --technique "Container Escape"

# by scope and severity
python -m k8smatrixwarden scan --mock -n production --severity-min HIGH

# natural language, resolved to a selector
python -m k8smatrixwarden scan --mock "scan production for Persistence"

# export to a file
python -m k8smatrixwarden scan --mock -o markdown --output-file report.md
```

At this point you have exercised the complete product except for live cluster access. If
you are evaluating rather than deploying, you can stop here.

---

# Part III: Connecting to a real cluster

## 7. How Kubernetes access works

This section explains the concepts that the next four sections depend on. Read it once,
and the cloud-specific instructions become straightforward.

### 7.1 What a kubeconfig is

A **kubeconfig** is a file that tells any Kubernetes client three things:

1. **Where the cluster is.** The API server URL and its certificate authority.
2. **Who you are.** A credential, or instructions for obtaining one.
3. **Which cluster is currently selected.** Known as the *current context*.

Default location:

| Operating system | Path |
|---|---|
| Linux and macOS | `~/.kube/config` |
| Windows | `%USERPROFILE%\.kube\config`, for example `C:\Users\you\.kube\config` |

Check whether you already have one:

```bash
kubectl config get-contexts
```

If that command lists a cluster with an asterisk beside it, you already have working
access. Proceed to Section 12.

**A kubeconfig is a credential.** Treat it as you would a password. Never commit it to
version control, never paste it into a chat or a support ticket, and restrict its
permissions on shared machines:

```bash
chmod 600 ~/.kube/config
```

### 7.2 Contexts

A single kubeconfig can describe many clusters. A **context** binds together one cluster,
one user identity, and optionally one default namespace. Switching contexts switches which
cluster your commands target.

```bash
kubectl config get-contexts        # list all contexts, marking the current one
kubectl config current-context     # show the active context
kubectl config use-context prod    # switch
```

Every cluster-touching command in this product accepts `--kubeconfig PATH` and
`--context NAME`, so you can target a specific cluster without changing global state:

```bash
python -m k8smatrixwarden scan --live --kubeconfig ~/.kube/prod.yaml --context prod-eks
```

This is the recommended practice when working with multiple environments. It makes the
target explicit in the command rather than dependent on hidden state.

### 7.3 Two layers of access control

**This is the concept that causes the most confusion, and the most failed first scans.**

Reaching a managed Kubernetes cluster requires passing two independent checks, enforced by
two separate systems:

```
Layer 1: Cloud IAM              Layer 2: Kubernetes RBAC
"Are you allowed to obtain      "Now that you are inside, which
 credentials for this cluster?"   objects may you read?"

AWS IAM / Google Cloud IAM /    Roles, ClusterRoles, RoleBindings,
Azure RBAC                       ClusterRoleBindings
```

Passing Layer 1 and failing Layer 2 produces a working kubeconfig that returns
`Unauthorized` on every request. This is the single most common first-time failure, and it
looks like a broken tool when it is actually an incomplete permission grant.

Each cloud section below lists **both layers together in one place**, so the complete
requirement is visible at once.

### 7.4 Why managed clusters need a cloud CLI

A kubeconfig for EKS, GKE, or AKS does not contain a long-lived credential. It contains an
**exec credential plugin**: an instruction telling the client to run a local command that
mints a short-lived token on demand.

This is a security improvement, because no durable cluster credential sits on disk. It has
one practical consequence: **the corresponding cloud CLI must be installed and
authenticated**, or no token can be produced and every API call fails.

| Cluster type | Required local tool |
|---|---|
| Amazon EKS | AWS CLI v2 |
| Google GKE | gcloud CLI plus `gke-gcloud-auth-plugin` |
| Azure AKS | Azure CLI, plus `kubelogin` for Entra ID integrated clusters |
| Self-managed or local | None. Credentials are embedded directly. |

### 7.5 Kubernetes RBAC in brief

Kubernetes authorization is built from four object types.

| Object | Purpose |
|---|---|
| **Role** | A set of permissions, valid within one namespace |
| **ClusterRole** | A set of permissions, valid cluster-wide |
| **RoleBinding** | Grants a Role or ClusterRole to a subject, **within one namespace** |
| **ClusterRoleBinding** | Grants a ClusterRole to a subject, **cluster-wide** |

A permission is expressed as a combination of API group, resource, and verb, for example
"get pods in the core API group".

One detail matters throughout this product's RBAC analysis: **a RoleBinding that
references a ClusterRole grants those permissions only inside the RoleBinding's
namespace.** It does not grant them cluster-wide. Tools that miss this distinction report
false cluster-admin findings. This product labels the scope explicitly.

The product models RBAC as a graph rather than a permission checklist, which allows it to
find multi-hop escalation paths such as: read this Secret, use it to authenticate as that
ServiceAccount, then inherit that ServiceAccount's permissions. Every hop names the
binding and the role that created it.

---

## 8. Local clusters

A local cluster is the recommended environment for learning the product. It is free, it
requires no cloud account, and you cannot damage anything.

### 8.1 Create a cluster

Choose one of the following.

**Docker Desktop** is the simplest option on Windows and macOS.

1. Install Docker Desktop.
2. Open Settings, select Kubernetes, enable **Enable Kubernetes**, then Apply and Restart.
3. Docker Desktop writes the kubeconfig for you.

**minikube**

```bash
minikube start
```

**kind**

```bash
kind create cluster --name test
```

Verify any of them:

```bash
kubectl get nodes
```

### 8.2 Add a realistic target

A healthy local cluster produces few findings, which makes it a poor learning environment.
Kubernetes Goat is a deliberately vulnerable cluster, and it is the environment the
product's published measurements were taken against.

```bash
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
bash setup-kubernetes-goat.sh
```

Then scan it:

```bash
python -m k8smatrixwarden scan --live --name "goat" --yes
```

**Reference results** from Kubernetes Goat on Docker Desktop, 30 pods:

- 489 findings: 28 CRITICAL, 215 HIGH, 246 MEDIUM. Risk score 9.9 of 10.
- Evidence coverage 95.5 percent, basis `measured`. The missing 4.5 percent is the
  `cloud_iam` domain, which has no Kubernetes API path on a local cluster and is therefore
  reported as unread rather than clean.
- 9 MITRE tactics chained, reaching Impact, plus 25 evidence-backed resource routes.
- Complete scan time including RBAC graph and NetworkPolicy evaluation: roughly 213
  milliseconds.

The count includes Falco's own DaemonSet, which is privileged and mounts host paths by
design. The scanner reports it rather than exempting it, so the output stays auditable.

---

## 9. Amazon EKS

### 9.1 All required permissions

**Three permissions form the complete requirement.** They originate in two different
systems. This is the two-layer model from Section 7.3, and both layers are listed here
together so the full requirement is visible in one place.

| # | System | Permission | Grants |
|---|---|---|---|
| 1 | **AWS IAM** | `eks:ListClusters` | List clusters in the account, so you can find the cluster name |
| 2 | **AWS IAM** | `eks:DescribeCluster` | Read the cluster endpoint and certificate authority, which is what generates the kubeconfig |
| 3 | **EKS access** | `AmazonEKSViewPolicy` | **Read-only access to the cluster's Kubernetes objects**, which is what the scan itself requires |

**Items 1 and 2 are AWS IAM permissions.** They are attached to your IAM user or role as
an IAM policy. They govern Layer 1 only: they get you *to* the cluster and say nothing
about what you may read inside it.

**Item 3 is an EKS cluster access policy, not an IAM policy.** `AmazonEKSViewPolicy` is an
AWS-managed access policy that maps to Kubernetes read-only RBAC. It is associated with
your principal *on the cluster*, not attached in IAM. This is Layer 2.

**Granting items 1 and 2.** Attach the following IAM policy to your user or role. If you
cannot attach policies yourself, send this JSON to your AWS administrator:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["eks:ListClusters", "eks:DescribeCluster"],
    "Resource": "*"
  }]
}
```

**Granting item 3.** Associate the read-only access policy with your principal. Full
context, including the legacy alternative, is in Section 9.5:

```bash
aws eks associate-access-policy \
  --cluster-name my-cluster --region us-east-1 \
  --principal-arn arn:aws:iam::111122223333:role/MyRole \
  --access-scope type=cluster \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy
```

`AmazonEKSViewPolicy` is read-only cluster-wide and deliberately excludes Secret *values*.
This is sufficient for the scanner, which reads Secret metadata and mount references but
never Secret contents.

Nothing beyond these three permissions is required. The product performs no writes.

### 9.2 Install the AWS CLI

| Operating system | Command |
|---|---|
| Windows | `winget install Amazon.AWSCLI` |
| macOS | `brew install awscli` |
| Linux | `curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o a.zip && unzip a.zip && sudo ./aws/install` |

Verify. Version 2 is expected:

```bash
aws --version
```

### 9.3 Configure AWS credentials

Two methods. **IAM Identity Center is recommended**, because it issues short-lived
credentials that expire automatically. Long-lived access keys persist on disk indefinitely
and are the most common source of leaked AWS credentials.

#### Method A: IAM Identity Center (recommended)

```bash
aws configure sso
```

You will be prompted for:

| Prompt | Value |
|---|---|
| SSO session name | Any label, for example `work` |
| SSO start URL | `https://<your-org>.awsapps.com/start`, available from your administrator |
| SSO region | The region hosting Identity Center, for example `us-east-1` |
| Account and role | Select from the list presented |
| CLI default region | The region the **cluster** runs in |
| CLI profile name | Any label, for example `work` |

Sign in. Repeat this when the session expires, typically after 8 to 12 hours:

```bash
aws sso login --profile work
export AWS_PROFILE=work
```

On Windows PowerShell, set the profile with `$env:AWS_PROFILE = "work"`.

#### Method B: Long-lived access keys

Use this only when Identity Center is unavailable.

**Obtaining the keys:**

1. In the AWS Console, open **IAM**, then **Users**, then your user, then the **Security
   credentials** tab.
2. Select **Create access key**, choose *Command Line Interface (CLI)*, acknowledge the
   warning, and select Create.
3. AWS displays an **Access key ID** and a **Secret access key**. **The secret is shown
   exactly once.** Record both now.

**Configuring the CLI.** Run this yourself in your own terminal. Never paste access keys
into a chat, a support ticket, or a file inside a repository:

```bash
aws configure
```

| Prompt | Value |
|---|---|
| AWS Access Key ID | The key from step 3 |
| AWS Secret Access Key | The secret from step 3 |
| Default region name | The cluster's region, for example `us-east-1` |
| Default output format | `json` |

This writes two files:

| File | Contents |
|---|---|
| `~/.aws/credentials`, or `%USERPROFILE%\.aws\credentials` on Windows | Access key and secret |
| `~/.aws/config`, or `%USERPROFILE%\.aws\config` on Windows | Region and output format |

If you prefer to write them by hand, the formats are:

```ini
# ~/.aws/credentials
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[prod]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

```ini
# ~/.aws/config
[default]
region = us-east-1
output = json

[profile prod]
region = eu-west-1
output = json
```

Note the naming asymmetry, which is a frequent source of errors: named profiles appear as
`[name]` in the credentials file but as `[profile name]` in the config file. The default
profile is `[default]` in both.

#### Verify credentials

This is the checkpoint that matters. Nothing downstream can work until it succeeds:

```bash
aws sts get-caller-identity
```

It must print your account identifier, user identifier, and ARN.

To select a profile without reconfiguring:

```bash
export AWS_PROFILE=prod                        # Linux and macOS
$env:AWS_PROFILE = "prod"                      # Windows PowerShell
aws sts get-caller-identity --profile prod     # or per command
```

### 9.4 Generate the kubeconfig

Find the cluster name:

```bash
aws eks list-clusters --region us-east-1
```

Write the kubeconfig entry:

```bash
aws eks update-kubeconfig --region us-east-1 --name my-cluster
```

Useful variations:

```bash
# use a specific profile
aws eks update-kubeconfig --region us-east-1 --name my-cluster --profile prod

# assign a readable context name instead of the default ARN
aws eks update-kubeconfig --region us-east-1 --name my-cluster --alias prod-eks

# write to a separate file rather than merging into ~/.kube/config
aws eks update-kubeconfig --region us-east-1 --name my-cluster \
  --kubeconfig ~/.kube/prod-eks.yaml
```

By default this **merges into** `~/.kube/config` and switches the current context. Your
existing cluster entries are preserved.

Verify:

```bash
kubectl config current-context
kubectl get nodes
```

A successful `kubectl get nodes` confirms that both access layers are satisfied.

### 9.5 Grant cluster access (Layer 2)

Determine which access mechanism your cluster uses:

```bash
aws eks describe-cluster --name my-cluster --region us-east-1 \
  --query 'cluster.accessConfig.authenticationMode'
```

**If the result is `API` or `API_AND_CONFIG_MAP`**, use access entries, which is the
current mechanism:

```bash
# 1. register the IAM principal with the cluster
aws eks create-access-entry \
  --cluster-name my-cluster --region us-east-1 \
  --principal-arn arn:aws:iam::111122223333:role/MyRole

# 2. associate the read-only access policy
aws eks associate-access-policy \
  --cluster-name my-cluster --region us-east-1 \
  --principal-arn arn:aws:iam::111122223333:role/MyRole \
  --access-scope type=cluster \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy
```

**If the result is `CONFIG_MAP`**, the cluster uses the legacy `aws-auth` ConfigMap.
Someone with existing cluster access must add your principal:

```bash
kubectl edit configmap aws-auth -n kube-system
```

```yaml
data:
  mapRoles: |
    - rolearn: arn:aws:iam::111122223333:role/MyRole
      username: my-role
      groups:
        - view
```

> **Caution.** A malformed `aws-auth` ConfigMap can remove cluster access for every user,
> including administrators. Keep a second authenticated session open while editing it.

Verify your effective Kubernetes permissions:

```bash
kubectl auth can-i list pods --all-namespaces
kubectl auth can-i list clusterroles
```

Both should return `yes`.

### 9.6 Scan

```bash
python -m k8smatrixwarden scan --live --name "prod-eks" --yes
python -m k8smatrixwarden cis --live --profile eks
```

Use `--profile eks` for the CIS benchmark. AWS owns and does not expose the control plane,
so those controls are correctly marked not applicable rather than reported as failures.

### 9.7 EKS-specific notes

**Session expiry.** Identity Center credentials expire. `Unable to locate credentials` or
`ExpiredToken` appearing mid-session means you need `aws sso login --profile <name>` again.

**Profile confusion.** The kubeconfig records which profile generated it. Scanning with a
different `AWS_PROFILE` set can silently target a different account. Confirm with
`aws sts get-caller-identity` before any scan you intend to act on.

**Private endpoint clusters.** If the EKS endpoint is private, you must have network
access to the VPC through a VPN, bastion host, or Direct Connect. No credential
configuration substitutes for a missing network path.

**Cloud IAM coverage.** The `cloud_iam` domain has no Kubernetes API path, so the scanner
reports it as unread rather than clean. Expect roughly 4.5 percent of evidence coverage to
be reported as missing, along with a warning stating why. This is intentional accuracy,
not a failure.

---

## 10. Google GKE

### 10.1 All required permissions

**Two IAM roles form the complete requirement.** Both are Google Cloud IAM roles, granted
on the project or directly on the cluster resource.

| # | System | Role | Grants |
|---|---|---|---|
| 1 | **Google Cloud IAM** | `roles/container.clusterViewer` | List clusters and read cluster metadata, which is what generates the kubeconfig |
| 2 | **Google Cloud IAM** | `roles/container.viewer` | **Read-only access to the cluster's Kubernetes objects**, which is what the scan itself requires |

GKE differs structurally from EKS. Both layers live in the same system, because Google
Cloud maps IAM roles onto Kubernetes RBAC automatically. There is no separate cluster-side
grant to perform.

`roles/container.viewer` includes everything `roles/container.clusterViewer` grants, so
granting item 2 alone is sufficient. Item 1 is listed separately because it is the minimum
required if you only need to fetch credentials.

Grant them:

```bash
gcloud projects add-iam-policy-binding my-project-id \
  --member="user:you@example.com" \
  --role="roles/container.viewer"
```

For a service account, use
`--member="serviceAccount:name@my-project-id.iam.gserviceaccount.com"`.

Nothing beyond these roles is required. The product performs no writes.

### 10.2 Install the gcloud CLI

| Operating system | Command |
|---|---|
| Windows | `winget install Google.CloudSDK` |
| macOS | `brew install --cask google-cloud-sdk` |
| Linux | Follow the apt or yum instructions in the Google Cloud SDK documentation |

```bash
gcloud --version
```

### 10.3 Authenticate

```bash
gcloud auth login
gcloud config set project my-project-id
```

For a service account rather than a human identity:

```bash
gcloud auth activate-service-account --key-file=key.json
```

### 10.4 Install the authentication plugin

**This step is mandatory** for Kubernetes 1.26 and later. Without the plugin, every API
call fails.

```bash
gcloud components install gke-gcloud-auth-plugin
gke-gcloud-auth-plugin --version
```

On Debian and Ubuntu systems installed through apt:

```bash
sudo apt-get install google-cloud-sdk-gke-gcloud-auth-plugin
```

### 10.5 Generate the kubeconfig

```bash
gcloud container clusters list
gcloud container clusters get-credentials my-cluster --region us-central1
```

Zonal clusters use `--zone` in place of `--region`.

Verify:

```bash
kubectl get nodes
kubectl auth can-i list pods --all-namespaces
kubectl auth can-i list clusterroles
```

### 10.6 Scan

```bash
python -m k8smatrixwarden scan --live --name "prod-gke" --yes
python -m k8smatrixwarden cis --live --profile gke
```

---

## 11. Microsoft AKS

### 11.1 All required permissions

**Two roles form the complete requirement.** They originate in two different systems, so
both are listed here together.

| # | System | Role | Grants |
|---|---|---|---|
| 1 | **Azure IAM (RBAC)** | `Azure Kubernetes Service Cluster User Role` | Fetch cluster credentials, which is what generates the kubeconfig |
| 2 | **Kubernetes access** | `Azure Kubernetes Service RBAC Reader` | **Read-only access to the cluster's Kubernetes objects**, which is what the scan itself requires |

**Item 1 is an Azure IAM role**, assigned on the cluster resource or its resource group.
It governs Layer 1 only.

**Item 2 governs access inside the cluster**, and the mechanism depends on how the cluster
was configured:

- **Azure RBAC enabled:** assign `Azure Kubernetes Service RBAC Reader` in Azure IAM.
  Azure maps it onto Kubernetes RBAC for you.
- **Kubernetes RBAC only, without Azure RBAC integration:** this role does not apply.
  Someone with cluster access must bind your identity to the built-in `view` ClusterRole
  using a standard Kubernetes ClusterRoleBinding.

Assign both roles:

```bash
# resolve the cluster resource id
SCOPE=$(az aks show -g my-rg -n my-cluster --query id -o tsv)

az role assignment create --assignee you@example.com \
  --role "Azure Kubernetes Service Cluster User Role" --scope "$SCOPE"

az role assignment create --assignee you@example.com \
  --role "Azure Kubernetes Service RBAC Reader" --scope "$SCOPE"
```

Nothing beyond these roles is required. The product performs no writes.

### 11.2 Install the Azure CLI

| Operating system | Command |
|---|---|
| Windows | `winget install Microsoft.AzureCLI` |
| macOS | `brew install azure-cli` |
| Linux | `curl -sL https://aka.ms/InstallAzureCLIDeb \| sudo bash` |

```bash
az --version
```

### 11.3 Sign in

```bash
az login
az account set --subscription "My Subscription"
az account show
```

### 11.4 Generate the kubeconfig

```bash
az aks list -o table
az aks get-credentials --resource-group my-rg --name my-cluster
kubectl get nodes
```

### 11.5 Configure kubelogin for Entra ID clusters

If `kubectl get nodes` hangs or reports an exec plugin error, the cluster uses Entra ID
integration and requires `kubelogin`:

```bash
az aks install-cli
kubelogin convert-kubeconfig -l azurecli
```

Verify:

```bash
kubectl auth can-i list pods --all-namespaces
kubectl auth can-i list clusterroles
```

### 11.6 Scan

```bash
python -m k8smatrixwarden scan --live --name "prod-aks" --yes
python -m k8smatrixwarden cis --live --profile aks
```

---

## 12. Least-privilege access for the scanner

Do not scan a production cluster using personal cluster-admin credentials. The product
generates its own scoped, read-only RBAC: one ClusterRole per domain shard, with every
verb restricted to `get`, `list`, and `watch`.

### 12.1 Review what would be created

```bash
python -m k8smatrixwarden roles
```

### 12.2 Generate a deployable manifest

```bash
python -m k8smatrixwarden roles --bind --output-file k8smatrixwarden-rbac.json
```

`--bind` produces a complete manifest containing a Namespace, a ServiceAccount, the
per-shard ClusterRoles, and the ClusterRoleBindings that connect them.

Additional options:

| Flag | Purpose |
|---|---|
| `--service-account NAME` | ServiceAccount name to create |
| `--sa-namespace NAME` | Namespace for the ServiceAccount |
| `--no-create-namespace` | Assume the namespace already exists |

### 12.3 Apply it

Review the generated file, then apply it. **This is the only write operation in the entire
workflow, and you perform it, not the product:**

```bash
kubectl apply -f k8smatrixwarden-rbac.json
```

The read-only property is asserted on every `doctor` run:

```
PASS   generated RBAC is read-only, every generated verb is get/list/watch
```

---

## 13. Running a live scan

### 13.1 Start with a dry run

Against an unfamiliar cluster, resolve the selector and inspect the rule set before
reading anything:

```bash
python -m k8smatrixwarden scan --live --dry-run
```

### 13.2 Start narrow, then widen

```bash
# one namespace
python -m k8smatrixwarden scan --live -n default --name "first look"

# the full cluster
python -m k8smatrixwarden scan --live --name "prod full" --yes
```

### 13.3 Scope options

Select one. The default is the entire cluster.

| Flag | Scope |
|---|---|
| `--namespace`, `-n` | A single namespace |
| `--pod` | A single pod |
| `--workload KIND/name` | A single workload, for example `Deployment/api` |
| `--node` | A single node |
| `--image` | A single image reference |
| `--helm-release` | Resources belonging to one Helm release |

### 13.4 Selector options

Combine freely. The default is all 62 rules.

| Flag | Selects by |
|---|---|
| `--tactic` | MITRE ATT&CK tactic |
| `--technique` | Technique identifier, name, or composite alias |
| `--module` | Domain shard |
| `--rule` | Explicit rule identifiers |
| `--alias` | Named composite selector |
| `--framework` | `CIS`, `NSA`, or `OWASP` |
| `--severity-min` | Minimum severity: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |

### 13.5 Common examples

```bash
# specific kubeconfig and context
python -m k8smatrixwarden scan --live --kubeconfig ~/.kube/prod.yaml --context prod-eks

# a single workload
python -m k8smatrixwarden scan --live --workload Deployment/payment-api -n production

# high severity only, exported as markdown
python -m k8smatrixwarden scan --live --severity-min HIGH -o markdown --output-file prod.md

# static analysis only, skipping the runtime feed
python -m k8smatrixwarden scan --live --no-runtime
```

### 13.6 Output formats

`-o` accepts `terminal`, `text`, `markdown`, `json`, `sarif`, `html`, `pdf`, and `xlsx`.
Use `--output-file PATH` to write to a file.

A saved scan can be re-rendered into any of these formats later without rescanning, as
described in Section 16.

---

# Part IV: Working with the product

## 14. The web dashboard

```bash
python -m k8smatrixwarden web --port 8080 --open
```

### 14.1 Tabs

| Tab | Contents |
|---|---|
| **Overview** | Risk score, evidence coverage, assessment confidence, and the pod exposure inventory |
| **Findings** | Searchable and sortable finding list. Expanding a finding shows its NetworkPolicy posture and RBAC escalation path. |
| **Threat Matrix** | MITRE ATT&CK heatmap for this scan |
| **Attack Path** | Tactic-level kill chain plus evidence-backed resource routes |
| **Attack Map** | The attack chain rendered against the affected resources |
| **Runtime** | Live Falco, audit, and drift events, filterable, with a per-event detail view |
| **Scan history** | Every saved scan, re-openable |

The pod exposure inventory buckets every pod on a worst-case-wins basis: internet-reachable
with cluster-admin, internet-reachable, cluster-admin ServiceAccount, or post-breach only.
The denominator is the true pod count, so the proportions are honest.

### 14.2 Security considerations

**The dashboard binds `127.0.0.1` by default and has no authentication.** Two rules follow
from this:

1. **Do not bind it to `0.0.0.0`** on a shared or internet-facing host without placing
   your own authentication in front of the port.
2. **`--allow-remote-kubeconfig` accepts a kubeconfig in a request body on a non-loopback
   bind.** Loading a kubeconfig executes its credential plugin as your operating system
   user. Enable this flag only behind your own authentication.

For sharing results without exposing the ability to launch scans:

```bash
python -m k8smatrixwarden web --no-scan
```

This serves saved reports read-only and disables the in-dashboard scan control.

---

## 15. Runtime correlation

This capability is optional and is the product's primary differentiator. It requires a
runtime data source. Two are supported, and either or both may be used.

### 15.1 Falco: syscall detection

Install Falco in the cluster:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco --namespace falco --create-namespace
```

A `--live` scan then pulls Falco alerts automatically:

```bash
# defaults: namespace "falco", previous 1 hour
python -m k8smatrixwarden scan --live

# custom namespace and lookback window
python -m k8smatrixwarden scan --live --falco-namespace falco-system --falco-since 6h

# disable the runtime feed
python -m k8smatrixwarden scan --live --no-runtime
```

### 15.2 Kubernetes audit events: no agent required

Five of the 11 curated runtime rules read Kubernetes audit events rather than syscalls.
They detect RoleBinding creation, secret enumeration, and mass deletion, which a syscall
sensor cannot observe at all.

**No Falco installation is needed for these.** Any operator who can set
`--audit-policy-file` on the API server can feed the audit log directly to the product.
Native `audit.k8s.io/v1` records are accepted unchanged, as is Falco's `k8saudit`
rendering of the same records.

Three behaviors are worth knowing:

- **Only `ResponseComplete` records are acted upon.** A `RequestReceived` record for the
  same request is the same action reported twice, so it is rejected with a stated reason
  rather than counted or silently dropped.
- **Mass deletion is treated as a rate.** The API server writes one record per deleted
  object. The product groups a batch by user, resource, and namespace, so a burst of 25
  deletions raises one alert. The remaining 24 records are reported as counted into that
  tally, never as unmatched.
- **Deduplication joins on `auditID`**, which the API server stamps once per request. A
  cluster running both a native feed and Falco's `k8saudit` plugin therefore sees each call
  once.

An audit-sourced detection is marked `source: audit`, `detection_source: kmw`, and
`provider: kubernetes-audit`. Reports name the stream beside the detector, rendering as
`K8sMatrixWarden (audit)`, so an API-call detection is never mistaken for a syscall
detection. The actor is carried through: `username`, `user_groups`, `source_ip`,
`user_agent`, `request_uri`, `response_status`, and `audit_id`.

### 15.3 The runtime API

Ingest events by posting to the dashboard:

```bash
curl -X POST http://127.0.0.1:8080/api/runtime \
  -H 'Content-Type: application/json' -d @falco-events.json
```

This endpoint accepts pushes from falcosidekick and from the Kubernetes audit log
directly.

Read stored events back:

```bash
curl 'http://127.0.0.1:8080/api/runtime?source=falco&severity=CRITICAL,HIGH&since=2h&limit=20'
```

| Parameter | Values |
|---|---|
| `limit` | Default 50, maximum 1000 |
| `source` | `all` (default), `kmw` or `falco` by detector, `audit` or `drift` by stream |
| `severity` | Comma-separated, for example `CRITICAL,HIGH` |
| `namespace` | Exact match |
| `since` | `90s`, `15m`, `2h`, `7d`, `1w`, or a plain number of seconds |
| `scan_id` | Defaults to the most recent saved scan |

Results are ordered newest first with a content-hash tie-break, so identical timestamps do
not reshuffle between requests. **A malformed filter is ignored and reported in
`warnings[]`** rather than silently applied, because a filter that quietly does nothing
would make an unfiltered page appear filtered.

### 15.4 How detections are attributed

```
runtime event
     |
     +-- matches one of 11 curated rules?
     |        |
     |        +-- yes: KMW:<rule-id> is PRIMARY
     |        |        the Falco rule name is retained as supporting evidence
     |        |
     |        +-- no:  falco:<rule> is relayed as the provider's verdict
     |
     +-- nothing claims it: reported unusable, WITH a recorded reason
```

**The 11 curated rules are authoritative.** Where one matches, it owns the finding
including its identifier, severity, and tactic. Falco's rule name is attached as
supporting evidence for the same event, never raised as a second independent detection.

**Falco is a provider, not a rule source.** An alert with no curated equivalent is relayed
under Falco's own name, preserving its priority, timestamp, and MITRE tags. A Falco rule
never becomes a K8sMatrixWarden rule regardless of how many the operator enables. The
curated catalog is hand-maintained and intentionally small.

**Nothing is silently dropped.** Every event is matched, relayed, or reported unusable with
a reason. Each scan carries the arithmetic:

```
Detection: 176 by curated rule · 1 relayed from Falco · 0 unusable · 0 discarded
Identity:  3 complete (0 recovered from container id) · 0 partial · 0 ambiguous · 174 unknown
```

**Detection coverage and identity coverage are separate questions.** "Was this event
detected" and "do we know what it happened to" have independent answers, and an event can
be detected while remaining unplaceable. Where Falco's Kubernetes enrichment returns
nothing, the container identifier is joined against Pod `containerStatuses`, using the
identifier Kubernetes itself assigned. Exactly one match recovers the Pod. Two matches is
`ambiguous` and recovers nothing. An unknown container resolves to `unknown` with the
reason stated. No name, prefix, or similarity matching exists anywhere in that path.

`discarded` is zero by construction. Missing MITRE metadata produces `tactic: Unknown`
rather than an inferred value, and Falco priorities map to severities through one
documented table, where `Warning` becomes `MEDIUM` and never silently becomes `CRITICAL`.

### 15.5 Evidence aging

A correlation older than 7 days is reported as `historical`, states its age in the verdict,
and cannot elevate an attack path step to `observed`. The resource link remains
`confirmed`. What ages is the claim that exploitation is happening now, not the claim that
it happened.

---

## 16. Reports and scan history

### 16.1 Automatic persistence

**Every scan is saved automatically.** No flag is required.

| Setting | Value |
|---|---|
| Default store | `~/.k8smatrixwarden/reports`, or `C:\Users\<you>\.k8smatrixwarden\reports` on Windows |
| Per-command override | `--reports-dir PATH` |
| Global override | `K8SMATRIXWARDEN_REPORTS_DIR` environment variable |
| Disable for one run | `--no-save` |

Scans run through the AI agent interface save to the same store, so they appear in the
dashboard's Scan history immediately.

### 16.2 Naming scans

Name any scan you intend to return to. The report is identified as `<name> + date + time`,
which makes it findable in the dashboard:

```bash
python -m k8smatrixwarden scan --live --name "Q3 prod audit"
```

### 16.3 Listing and re-exporting

```bash
python -m k8smatrixwarden report list --limit 20
python -m k8smatrixwarden report download --scan-id <id> --format pdf --output audit.pdf
python -m k8smatrixwarden report download --format sarif --output latest.sarif
```

Omitting `--scan-id` uses the most recent scan. A saved scan can be re-rendered into any
of the 8 formats without rescanning, because the stored result carries the complete
analysis.

### 16.4 Posture comparison

Compare the latest scan against the previous scan of the same cluster:

```bash
python -m k8smatrixwarden posture
```

Findings are classified as new, resolved, persistent, or regressed.

Kubernetes object UID is deliberately excluded from finding identity. A recreated Pod
carrying the same flaw is the same finding, not a fix followed by a regression.

### 16.5 Cross-cluster analysis

Save a scan per cluster, then correlate blast radius across them:

```bash
python -m k8smatrixwarden federation -o html --output-file blast-radius.html
```

This identifies **shared non-default identities**, meaning the same custom ClusterRole,
ServiceAccount, or cloud IAM role present in more than one cluster, and flags them as
candidate cross-cluster lateral movement paths to verify. Kubernetes built-in defaults are
excluded, because their presence everywhere carries no signal.

The practical question this answers: if the production cluster is compromised, does
staging fall with it, and which shared identity is the link.

---

## 17. Compliance and benchmarks

### 17.1 CIS Kubernetes Benchmark v1.8

All 130 controls are evaluated.

```bash
python -m k8smatrixwarden cis --mock
python -m k8smatrixwarden cis --live --profile eks
python -m k8smatrixwarden cis --live --show-all
python -m k8smatrixwarden cis --live --fail-on-fail
```

`--profile` accepts `self-managed`, `eks`, `gke`, and `aks`. Managed profiles mark
provider-owned control plane controls as not applicable rather than failing them.

Every control receives an explicit status, so nothing is silently skipped:

| Status | Meaning |
|---|---|
| `PASS` | Evaluated from the API and satisfied |
| `FAIL` | Evaluated from the API and not satisfied |
| `MANUAL` | CIS designates this a human review. Surfaced, never auto-passed. |
| `NA` | The cloud provider owns this control |
| `NEEDS_NODE` | Requires node filesystem access |

**Coverage breakdown.** 65 of the 130 controls are evaluated directly from the Kubernetes
API: 25 native rules, 2 built-in checks, and 38 control plane and kubelet process-flag
checks recovered from static pod specifications. 31 controls are true node file-permission
checks that require kube-bench. The remaining 34 are CIS-designated manual reviews.

To resolve the 31 node controls:

```bash
kube-bench run --targets master,node,etcd,policies --json > kb.json
python -m k8smatrixwarden cis --live --kube-bench-json kb.json
```

### 17.2 Governance frameworks

```bash
python -m k8smatrixwarden compliance --live -o pdf --output-file attestation.pdf
python -m k8smatrixwarden compliance --live --frameworks PCI-DSS-4.0,SOC2
```

Supported frameworks: PCI DSS v4.0, SOC 2, ISO 27001:2022, and NIST 800-53 rev5.

Output is auditor-facing rather than a finding dump. Each requirement carries a pass or
fail status with supporting evidence, and the report states plainly where posture blocks
attestation, for example "N findings block PCI-DSS attestation".

Available output formats: `markdown`, `json`, `html`, and `pdf`.

---

## 18. CI/CD integration

### 18.1 Failing a build on findings

```bash
python -m k8smatrixwarden scan --live --fail-on CRITICAL -o sarif --output-file results.sarif
```

`--fail-on` accepts `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`, and exits with status 1 when a
finding at or above that severity exists.

For CIS gating, `--fail-on-fail` exits 1 when any control fails.

### 18.2 Useful pipeline flags

| Flag | Purpose |
|---|---|
| `--yes` | Skip the confirmation prompt |
| `--no-save` | Prevent pipeline runs from accumulating in the report store |
| `-o sarif` | Emit SARIF for code scanning platforms |

### 18.3 GitHub Actions example

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'

- run: pip install -e ".[live]"

- run: |
    python -m k8smatrixwarden scan --live \
      --fail-on CRITICAL \
      -o sarif --output-file results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

SARIF output uploads directly to GitHub code scanning.

---

## 19. AI agent integration (MCP)

Running the product through an AI agent client is the intended primary workflow. Instead
of composing flags, you describe what you want and the agent selects the tools.

The product exposes 40 read-only tools over the Model Context Protocol, covering scanning,
correlation, RBAC analysis, threat matrix construction, and reporting.

**No write-capable tool is exposed.** This is enforced by
`tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed`.

### 19.1 Install and verify

```bash
pip install -e ".[mcp]"
```

Confirm the server works before configuring any client. This prints all 47 tools without
starting the server:

```bash
python -m k8smatrixwarden mcp --list-tools
```

If this succeeds but a client shows no tools, the problem is in the client configuration
rather than the product. See Section 19.7.

### 19.2 Clients with project-local configuration

**Configuration files for these clients ship in the repository.** There is nothing to
write and no path to fill in.

| Client | File it reads | Included |
|---|---|---|
| Cursor | `.cursor/mcp.json` | Yes |
| Claude Code (CLI, desktop app, VS Code and JetBrains extensions) | `.mcp.json` | Yes |
| VS Code Copilot Chat, Agent mode, version 1.102 or later | `.vscode/mcp.json` | Yes |

**Setup:**

1. Clone the repository:

   ```bash
   git clone <repository-url> && cd K8sMatrixWarden
   ```

2. Open the folder in your MCP client.

3. Enable the server and confirm the tools load:

   | Client | Where to look |
   |---|---|
   | Cursor | Settings, then Tools and MCP. `k8smatrixwarden` should be listed, enabled, showing 47 tools. |
   | Claude Code | Run `/mcp` and approve the project-scoped server the first time it prompts. |
   | VS Code | Open Copilot Chat, switch the mode selector to **Agent**, then open the tools picker. MCP tools appear in Agent mode only. |

4. Open the agent chat and describe what you want. The agent selects the tools.

### 19.3 Configuration file contents

You do not need to create these. They are documented here so you can verify them, adapt
them for a client not listed above, or reproduce them elsewhere.

**Cursor,** `.cursor/mcp.json`, and **Claude Code,** `.mcp.json`. Both use the same shape:

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

**VS Code,** `.vscode/mcp.json`. Note the different top-level key and the explicit
transport type:

```json
{
  "servers": {
    "k8smatrixwarden": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "k8smatrixwarden", "mcp"]
    }
  }
}
```

**Why the formats differ.** MCP standardizes the protocol, not configuration discovery.
Each client chose its own filename, directory, and JSON shape. VS Code nests entries under
`servers` and requires `"type": "stdio"`; every other client uses `mcpServers`. The server
itself never varies: all clients launch the identical process and see the identical 40
tools.

**Why `python -m` rather than the console script.** The `k8smatrixwarden mcp` console
script also works, but it is more fragile. `pip` installs that launcher into a
per-interpreter `Scripts/` directory on Windows or `bin/` directory elsewhere, which is
frequently absent from `PATH`. With several Python versions installed you get one launcher
each, with no control over which one resolves first. The `python -m` form avoids both
problems.

### 19.4 Clients with machine-wide configuration

Claude Desktop and Windsurf read a single machine-wide configuration file rather than a
project file, so no repository file can reach them.

**Install the package editable first.** This places it permanently on the Python path, so
the server starts regardless of which directory the client launches it from:

```bash
pip install -e ".[mcp]"
```

Then add this entry to the client's configuration file:

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

| Client | Configuration file |
|---|---|
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json`, reachable from Settings, then Developer, then Edit Config |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Restart the client after editing.

### 19.5 Tool categories

| Category | Count | Examples |
|---|---|---|
| Knowledge | 14 | `list_rules`, `get_rule`, `get_taxonomy`, `mitre_coverage` |
| Scan, audit, runtime, graph analysis | 16 | `run_scan`, `intelligent_scan`, `correlate_runtime`, `analyze_rbac_paths` |
| Reports and stored scan analysis | 7 | `list_reports`, `download_report`, `posture_history` |
| Runtime provider lifecycle | 6 | `get_falco_status`, `deploy_falco`, `get_helm_status`, `install_helm` |
| Platform and application lifecycle | 4 | `run_doctor`, `start_web_server`, `get_web_server_status`, `stop_web_server` |

Every tool parameter carries a schema description, so the agent can select and populate
tools without additional prompting.

### 19.6 Example prompts

**Mock scan, no cluster required:**

> Run an `intelligent_scan` for privilege escalation on the mock cluster and summarize the
> findings, and also start the web interface.

**Live scan:**

> Use k8smatrixwarden and run a live scan of my cluster covering the whole attack matrix.
> kubeconfig `"C:\Users\me\.kube\config"`, name it `"Prod live Scan"`, and give me a
> markdown report. Also start the web interface.

**Scans run over MCP are saved to the shared report store by default**, so anything the
agent scans appears immediately in the web dashboard's Scan history. See Section 16.

### 19.7 When tools do not appear

Work through these in order.

1. **Verify the server independently.** If this fails, the problem is the installation,
   not the client:

   ```bash
   python -m k8smatrixwarden mcp --list-tools
   ```

2. **Check the interpreter.** MCP clients launch whichever interpreter the name `python`
   resolves to. If that is not the interpreter you installed into, the server cannot
   start. Install editable into the interpreter the client actually uses:

   ```bash
   py -3.12 -m pip install -e ".[mcp]"
   ```

3. **For VS Code, confirm you are in Agent mode.** MCP tools are hidden in every other
   mode.

4. **Restart the client.** Machine-wide configuration changes are read at startup.

---

# Part V: Reference

## 20. Command reference

### 20.1 Commands

| Command | Purpose |
|---|---|
| `scan` | Run a scan by scope and selector, or as a natural-language query |
| `rules` | List the 62-rule registry, filterable by `--module` and `--tactic` |
| `coverage` | MITRE tactic coverage, expressed as rules per tactic |
| `matrix` | Print the threat matrix for a scan, or `--coverage` for the global matrix |
| `cis` | CIS Kubernetes Benchmark v1.8, all 130 controls |
| `compliance` | PCI DSS 4.0, SOC 2, ISO 27001:2022, and NIST 800-53 rev5 |
| `posture` | What changed since the previous scan of the same cluster |
| `federation` | Cross-cluster blast radius from saved per-cluster scans |
| `report list` | List stored reports |
| `report download` | Re-render a stored report in any format |
| `roles` | Generate scoped read-only RBAC, one ClusterRole per shard |
| `web` | Launch the dashboard, bound to `127.0.0.1` |
| `chat` | Interactive conversational assistant, confirm before running |
| `mcp` | Run the MCP server, or list its tools with `--list-tools` |
| `doctor` | Full health and consistency check |

### 20.2 Flags common to cluster-touching commands

| Flag | Purpose |
|---|---|
| `--mock` | Use the bundled sample cluster. This is the default. |
| `--live` | Scan the live cluster |
| `--fixture PATH` | Use a custom cluster JSON file |
| `--kubeconfig PATH` | Kubeconfig location, defaulting to `~/.kube/config` |
| `--context NAME` | Kubeconfig context, defaulting to the current context |

### 20.3 Scan flags

```
scope     --namespace/-n · --pod · --workload KIND/name · --node · --image · --helm-release
selector  --tactic · --technique · --module · --rule · --alias · --framework · --severity-min
output    -o {terminal,text,markdown,json,sarif,html,pdf,xlsx} · --output-file PATH
naming    --name "<scan name>"
storage   saved by default · --no-save · --reports-dir PATH
control   --dry-run · --yes · --fail-on {LOW,MEDIUM,HIGH,CRITICAL}
runtime   --no-runtime · --falco-namespace NAME · --falco-since DURATION
```

---

## 21. Configuration

### 21.1 Configuration files

| File | Purpose |
|---|---|
| `k8smatrixwarden/config/default_config.json` | Shard toggles, rule severity overrides, composite aliases |
| `k8smatrixwarden/config/agent.json` | Optional LLM provider settings |
| `k8smatrixwarden/taxonomy/*.json` | MITRE ATT&CK, OWASP, and compliance crosswalk data |

Override the configuration file globally:

```bash
python -m k8smatrixwarden --config /path/to/config.json scan --mock
```

### 21.2 The optional LLM layer

**The scanner never requires an LLM.** Every value the product produces, including
findings, risk scores, coverage, the threat matrix, attack paths, and CIS and compliance
status, is computed by deterministic Python with no model involvement.

The optional LLM layer powers only the local `chat` command's multi-step tool chaining. An
AI agent client connecting over MCP brings its own model and does not use this layer at
all.

No provider or model is compiled in. Configure it through environment variables:

```bash
# any OpenAI-compatible endpoint: OpenAI, Azure OpenAI, OpenRouter, Together,
# Groq, vLLM, llama.cpp, LM Studio, or Ollama, including fully local models
export K8SMATRIXWARDEN_LLM_PROVIDER=openai-compatible
export K8SMATRIXWARDEN_LLM_BASE_URL=http://localhost:11434/v1
export K8SMATRIXWARDEN_LLM_MODEL=llama3.1:70b

# or a hosted Anthropic model
export K8SMATRIXWARDEN_LLM_PROVIDER=anthropic
export K8SMATRIXWARDEN_LLM_MODEL=<any model your account can call>
export ANTHROPIC_API_KEY=...
```

| Setting | Environment variable | Meaning |
|---|---|---|
| `provider` | `K8SMATRIXWARDEN_LLM_PROVIDER` | `anthropic`, `openai`, `azure-openai`, `openai-compatible`, or `ollama` |
| `model` | `K8SMATRIXWARDEN_LLM_MODEL` | Any model identifier the endpoint serves |
| `base_url` | `K8SMATRIXWARDEN_LLM_BASE_URL` | Endpoint, for self-hosted, gateway, or local servers |
| `api_key_env` | `K8SMATRIXWARDEN_LLM_API_KEY_ENV` | Name of the variable holding the key, so the key itself never enters a file |
| | `K8SMATRIXWARDEN_LLM_API_KEY` | The key directly, if a named variable is not wanted |
| `extra` | `K8SMATRIXWARDEN_LLM_EXTRA` | JSON for provider-specific extras such as custom headers or Azure deployment settings |

Equivalent settings can live in the `llm` block of `config/agent.json`:

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

**Selection is deterministic and documented.** Precedence, highest first:

1. An explicit argument passed by an API caller
2. Environment variables
3. The `llm` block of `agent.json`
4. Controlled auto-detection, in this fixed order: `ANTHROPIC_API_KEY`, then
   `OPENAI_API_KEY`, then `AZURE_OPENAI_API_KEY`, then `OLLAMA_HOST`

If auto-detection finds more than one candidate, **the product refuses to guess.** It
reports the ambiguity and asks you to name the provider. It never depends on dictionary or
environment iteration order. With no candidate at all, the agent path stays off and the
scanner is unaffected.

Verify the active configuration:

```bash
python -m k8smatrixwarden doctor            # report provider, model, and validity
python -m k8smatrixwarden doctor --probe    # additionally make one small live call
```

Any LLM problem, whether a missing key, an incorrect model name, an unreachable endpoint,
a rate limit, or a missing package, is reported, and the product falls back to its
deterministic path. **An LLM failure can never change what a scan found.**

The OpenAI-compatible adapter uses standard library HTTP and requires no third-party
package. Only the Anthropic adapter needs one, installed with `pip install -e ".[agent]"`.

---

## 22. Troubleshooting

### 22.1 `Kubernetes API authentication failed for context '...'`

The kubeconfig loaded, but no valid credentials could be obtained. **The product refuses
to save a result in this situation by design**, because a scan of a cluster it could not
read would be indistinguishable from a clean cluster.

Resolve by cloud provider:

| Provider | Resolution |
|---|---|
| AWS EKS | The profile named in the kubeconfig is not configured on this machine. Run `aws configure list-profiles`, then `AWS_PROFILE=<name> aws sts get-caller-identity`. |
| Google GKE | Run `gcloud auth login` and install `gke-gcloud-auth-plugin`. |
| Azure AKS | Run `az login`, then `kubelogin convert-kubeconfig -l azurecli`. |
| OIDC | Re-authenticate with your identity provider to refresh the ID token. |

Confirm with `kubectl get nodes` before rescanning. To scan the bundled sample cluster
instead, add `--mock`.

### 22.2 `error: You must be logged in to the server (Unauthorized)` on EKS

Layer 1 succeeded and Layer 2 failed. You are authenticated to AWS but not authorized
inside the cluster. See Section 9.5.

### 22.3 `Unable to locate credentials` or `ExpiredToken` on AWS

The Identity Center session expired:

```bash
aws sso login --profile <name>
```

### 22.4 `ModuleNotFoundError: No module named 'kubernetes'`

The live scanning extra is not installed:

```bash
pip install -e ".[live]"
```

### 22.5 `k8smatrixwarden: command not found`

The console script was installed into a directory that is not on `PATH`. Use the module
form, which always works:

```bash
python -m k8smatrixwarden doctor
```

### 22.6 `no Kubernetes API path; needs an external evidence adapter`

Expected behavior, not an error. The `cloud_iam` domain has no Kubernetes API to read
from, so it is reported as **unread rather than clean**. Its rules ran, found nothing
because there was nothing to read, and the product says so instead of implying a pass.
This typically accounts for about 4.5 percent of evidence coverage.

### 22.7 MCP tools do not appear in the client

Most often the client launched a different Python interpreter than the one you installed
into. Work through the ordered checklist in Section 19.7.

### 22.8 Findings appear duplicated

They are not. See Section 3.1. Kubernetes propagates a Deployment's specification to its
ReplicaSets and Pods, and all of them genuinely carry the flaw. `workload_issues` is the
number of fixes required.

### 22.9 The scan reports the Falco DaemonSet as insecure

Correct behavior. Falco is privileged and mounts host paths by design. The scanner reports
its own sensor rather than exempting it, because a scanner with a built-in exemption list is
a scanner whose output you cannot audit.

### 22.10 `analysis_status: truncated`

A graph traversal reached a bound and reported it, along with the bound that stopped it, so
that a capped result cannot be mistaken for an exhaustive one. Narrow the scope with
`-n <namespace>` to complete the analysis.

### 22.11 PDF or Excel export fails

The corresponding extra is not installed:

```bash
pip install -e ".[pdf]"      # fpdf2
pip install -e ".[excel]"    # openpyxl
```

### 22.12 Report write failures on Windows

Reports are written by atomic rename and read with a bounded retry across that window, so
event ingestion and the dashboard can operate simultaneously.

Two limits cannot be removed by retrying: a reader holding a file handle open indefinitely
blocks a write, because the standard library `open` cannot request share-delete semantics,
and a reader polling with no pause can starve the writer. Neither is a normal usage
profile. A failed write is reported as `stored: false` rather than assumed to have
succeeded.

### 22.13 General diagnosis

When the cause is unclear, start here:

```bash
python -m k8smatrixwarden doctor --verbose
```

This runs 20 checks across shards, configuration, rules, taxonomy, MCP, report formats,
runtime, LLM configuration, dependencies, and read-only invariants.

---

## 23. Glossary

| Term | Definition |
|---|---|
| **Shard** | A domain module owning a set of detection rules. There are 11. Shards form the scanner's execution boundary. |
| **Tactic** | A MITRE ATT&CK attacker objective such as Initial Access, Persistence, or Impact. A cross-cutting tag, not a location. |
| **Technique** | A specific method within a tactic, for example `T1611 Escape to Host`. |
| **Selector** | Any criterion that narrows which rules run: tactic, technique, module, rule identifier, alias, framework, or severity. |
| **Scope** | Which part of the cluster is read: cluster, namespace, workload, pod, node, image, or Helm release. |
| **Evidence** | The raw Kubernetes objects a scan read. Fetched once and shared by every rule. |
| **Evidence coverage** | How much of the cluster was actually read. An unread resource type is reported as unread, never as clean. |
| **Correlation** | The link between a static finding and a live runtime event: confirmed, corroborated, or runtime-only. |
| **Attack path** | Two layers. The *tactic* chain runs Initial Access through Impact. The *resource* chain runs Internet, Service, Pod, ServiceAccount, RoleBinding, ClusterRole, permission, where every hop is read from a real object. |
| **Drift** | Observed behavior contradicting declared configuration, such as running as uid 0 despite `runAsNonRoot`, or writing to disk despite `readOnlyRootFilesystem`. |
| **Reachability** | A workload's live attack vector: internet-reachable, post-breach only, or RBAC escalation. Used for prioritization, never to change severity. |
| **`unknown` and `partial`** | Real values, never synonyms for `false` or `safe`. They propagate as themselves through coverage, NetworkPolicy evaluation, RBAC analysis, reports, and the dashboard. |

### 23.1 Validated Kubernetes semantics

RBAC and NetworkPolicy are where a scanner most easily invents or misses a finding, so the
exact semantics are pinned by an adversarial test suite written to prove the tool wrong.
Support is claimed only where a test demonstrates it.

**RBAC: supported**

- `Role` and `ClusterRole`; `RoleBinding` and `ClusterRoleBinding`
- A RoleBinding referencing a ClusterRole grants permissions **only inside that
  namespace**, and is labeled as such rather than as cluster-admin
- `apiGroups` are honored, so a CustomResource named `secrets` is not treated as a core
  Secret
- `resourceNames` limit a grant to those objects and never establish a blanket capability
- Subresource identity is exact: `pods/exec` is not `pods`
- `nonResourceURLs` grant no resource access
- A wildcard on one axis is not a wildcard on the other
- Identical ServiceAccount names in different namespaces remain distinct
- Cycles terminate

**NetworkPolicy: supported**

- `matchLabels` and `matchExpressions`, covering `In`, `NotIn`, `Exists`, and
  `DoesNotExist`, with a missing key satisfying `NotIn`
- `podSelector` and `namespaceSelector` peers, including both on one peer, which is a
  logical AND, versus separate peers, which is a logical OR
- `ipBlock` with `except`
- `policyTypes` defaulting: omitted means Ingress only, plus Egress when egress rules exist
- The additive union across policies, where one permissive rule defeats every strict
  sibling
- Both ingress and egress directions

**Workloads**

The same rule fires on `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`,
`Job`, and `CronJob`, whose PodSpec nests one level deeper. Regular, `init`, and
`ephemeral` containers are all evaluated.

**Pod security**

Pod-level settings are defaults that a container can override, so a guarantee holds only
when every container preserves it. An omitted field is never interpreted as an explicit
safe value.

---

## 24. The confidence model

Five distinct confidences exist because they answer five distinct questions. They are kept
separate deliberately. Collapsing them is how a scanner ends up sounding certain about
evidence it never read.

| Confidence | Question it answers | Values |
|---|---|---|
| **Evidence** | Was this resource type read, and how do we know the fraction? | `measured`, `estimated`, `heuristic`, `unknown` |
| **Assessment** | How much of the cluster did the scan see? | 0 to 100 percent, a function of coverage only |
| **Finding** | How much should this specific conclusion be trusted? | 0 to 1, with the reasons that produced it |
| **Correlation** | How tightly does a runtime event tie to this finding? | `confirmed`, `corroborated`, `runtime-only` |
| **Attack path** | How strongly is this route evidenced? | `configuration-only`, `corroborated`, `observed` |

The policy lives in `core/explain.py` as `CONFIDENCE_POLICY` and is enforced by
`tests/test_integration_pipeline.py`.

**The five rules that keep them coherent:**

1. **Nothing is more confident than the evidence beneath it.** An unread resource type
   produces no claim, not a confident absence.
2. **Only a resource-level runtime match earns certainty.** Activity elsewhere in the
   namespace corroborates, and is capped below certainty.
3. **A runtime event at one hop does not make a multi-hop path observed.** The path names
   which hops were witnessed and states that the remainder is configuration-derived.
4. **Confidence never changes severity and never hides a finding.** A low-confidence
   CRITICAL is still a CRITICAL. It simply needs verifying first.
5. **`unknown` and `partial` are values, not synonyms for `false` or `safe`.** They
   propagate as themselves through coverage, NetworkPolicy evaluation, RBAC analysis,
   reports, and the dashboard.

---

## Further reading

| Resource | Contents |
|---|---|
| `K8sMatrixWarden-doc.html` | Complete technical reference. One self-contained searchable page covering architecture and design decisions, risk-scoring mathematics, all 11 shard rule catalogs, MITRE, OWASP and CIS coverage, the full CLI flag reference, configuration, live cluster setup, the runtime correlation layer, the complete MCP tool reference with per-client setup, known limitations, and troubleshooting. |
| `README.md` | Feature overview and product positioning |
| `python -m k8smatrixwarden doctor --verbose` | Installation verification, with the detail behind every check |
| `python -m tests.run_tests` | The full test suite, 966 tests, no external test framework required |
