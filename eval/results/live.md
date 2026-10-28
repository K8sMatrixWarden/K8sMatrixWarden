# K8sMatrixWarden evaluation against DVKA

Live scan of `minikube`: 969 findings in 21.76s; 94 more findings are on objects outside DVKA (kube-system etc.) and are not scored.

## Headline

| Measure | Result |
|---|---|
| Recall (planted weaknesses detected) | **100.0%** (111/111) |
| Precision (reported findings correct) | **99.1%** (111/112) |
| Secure controls left unflagged | 6/7 |
| Hardened cluster: findings reported | 0 (expected 0) |
| Documented gaps confirmed undetected | 8/8 |
| Attack path Internet to Secrets found | yes |
| Exposed outranks isolated (same flaw) | yes (65.625 vs 46.875) |
| Exposed vulnerable image outranks the isolated one | yes (52.5 vs 37.5) |

## Recall by category

| Category | Detected | Expected | Recall |
|---|---|---|---|
| AP | 3 | 3 | 100.0% |
| AS | 1 | 1 | 100.0% |
| GAP | 1 | 1 | 100.0% |
| NET | 5 | 5 | 100.0% |
| NS | 8 | 8 | 100.0% |
| PRIO | 4 | 4 | 100.0% |
| RB | 34 | 34 | 100.0% |
| SEC | 4 | 4 | 100.0% |
| WL | 51 | 51 | 100.0% |

## Precision by shard

| Shard | Correct | Reported | Precision |
|---|---|---|---|
| attack_surface | 1 | 1 | 100.0% |
| compliance | 3 | 3 | 100.0% |
| network_security | 12 | 12 | 100.0% |
| rbac_identity | 34 | 34 | 100.0% |
| secrets | 4 | 5 | 80.0% |
| workload_pod_security | 57 | 57 | 100.0% |

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
| GAP-IMG2 | Image pulled from an untrusted public registry | yes | admission policy (Kyverno/Gatekeeper) + cosign verification |
| GAP-WL2 | CronJob that downloads and runs a script | yes | Falco at runtime |
| GAP-ADM | Mutating webhook that fails open and injects a sidecar | yes | restore the admission rules (evidence is still collected) |
| GAP-OPS | No ResourceQuota, LimitRange or PodDisruptionBudget | yes | rules over ResourceQuota / LimitRange / PodDisruptionBudget |

## Attack path

- chain: Internet -> Service -> Deployment -> ServiceAccount -> ClusterRoleBinding -> ClusterRole -> Capability -> read-secrets
