# K8sMatrixWarden evaluation against DVKA

Scan of the vulnerable fixture: 201 resources, 221 findings in 0.18s (peak 8.1 MB).

## Headline

| Measure | Result |
|---|---|
| Recall (planted weaknesses detected) | **100.0%** (115/115) |
| Precision (reported findings correct) | **99.1%** (115/116) |
| Secure controls left unflagged | 6/7 |
| Hardened cluster: findings reported | 1 (expected 0) |
| Documented gaps confirmed undetected | 9/9 |
| Runtime events in the right tier | 6/6 |
| Attack path Internet to Secrets found | yes |
| Exposed outranks isolated (same flaw) | yes (65.625 vs 46.875) |

## Recall by category

| Category | Detected | Expected | Recall |
|---|---|---|---|
| AP | 3 | 3 | 100.0% |
| AS | 1 | 1 | 100.0% |
| CP | 4 | 4 | 100.0% |
| NET | 5 | 5 | 100.0% |
| NS | 8 | 8 | 100.0% |
| PRIO | 3 | 3 | 100.0% |
| RB | 34 | 34 | 100.0% |
| SEC | 5 | 5 | 100.0% |
| WL | 52 | 52 | 100.0% |

## Precision by shard

| Shard | Correct | Reported | Precision |
|---|---|---|---|
| attack_surface | 1 | 1 | 100.0% |
| compliance | 3 | 3 | 100.0% |
| log_analysis | 4 | 4 | 100.0% |
| network_security | 12 | 12 | 100.0% |
| rbac_identity | 34 | 34 | 100.0% |
| secrets | 5 | 6 | 83.3% |
| workload_pod_security | 56 | 56 | 100.0% |

## Missed (false negatives)

- none

## False positives

| Rule | Resource | Class | Ref |
|---|---|---|---|
| `sec-configmap-credentials` | dvka-secure/fp-model-config | probe | FP-SEC |

## Documented gaps

| ID | Weakness | Still undetected | What would catch it |
|---|---|---|---|
| NS-03 | Egress policy that allows everything (metadata API still open) | yes | evaluate egress rules with netpol.py against 169.254.169.254/32 |
| GAP-RB | Namespaced Role that can read Secrets | yes | extend the rule to Roles and report namespace-scoped blast radius |
| GAP-SEC1 | Plaintext credentials stored in a Secret object | yes | secret scanning at commit time (gitleaks) or an admission policy |
| GAP-SEC2 | Long-lived ServiceAccount token stored as a Secret | yes | list Secrets by type (metadata only) and flag service-account-token |
| GAP-IMG1 | Image with known CVEs (nginx 1.14.0) | yes | run with --live --grype (Grype on the running image digests) |
| GAP-IMG2 | Image pulled from an untrusted public registry | yes | admission policy (Kyverno/Gatekeeper) + cosign verification |
| GAP-WL2 | CronJob that downloads and runs a script | yes | Falco at runtime |
| GAP-ADM | Mutating webhook that fails open and injects a sidecar | yes | restore the admission rules (evidence is still collected) |
| GAP-OPS | No ResourceQuota, LimitRange or PodDisruptionBudget | yes | rules over ResourceQuota / LimitRange / PodDisruptionBudget |

## Runtime correlation

| ID | Scenario | Expected | Got | |
|---|---|---|---|---|
| RT-01 | Shell in the privileged frontend | confirmed | confirmed | ok |
| RT-02 | Read /etc/shadow in a pod with an auto-mounted token | confirmed | confirmed | ok |
| RT-03 | Shell in a pod the scan has never seen | corroborated | corroborated | ok |
| RT-04 | Shell in a cluster whose scan found nothing | runtime-only | runtime-only | ok |
| RT-06 | Shell in a clean namespace of a cluster with other findings | corroborated | corroborated | ok |
| RT-05 | Pod name that only shares a prefix with a flaw | corroborated | corroborated | ok |

## Attack path

- chain: Internet -> Service -> Deployment -> ServiceAccount -> ClusterRoleBinding -> ClusterRole -> Capability -> read-secrets
