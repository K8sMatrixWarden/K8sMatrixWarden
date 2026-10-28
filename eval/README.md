# Evaluation: DVKA (Damn Vulnerable Kubernetes Application)

A deliberately insecure Kubernetes application plus an answer key, used to measure
K8sMatrixWarden: precision, recall, false positives, runtime correlation, attack paths,
prioritisation and performance (the slide's measurement plan).

> **DVKA is intentionally insecure.** It mounts the node's `/` and the Docker socket, binds
> `cluster-admin` to the default ServiceAccount and to `system:anonymous`. Apply it **only** to a
> disposable local cluster (kind, minikube, k3d). Never to a shared or production cluster.

## Layout

| Path | What |
|---|---|
| `dvka/catalog.py` | the single source of truth: every planted weakness and its expected findings |
| `dvka/build.py` | generates everything below from the catalog |
| `dvka/manifests/*.yaml` | the application: `kubectl apply -f eval/dvka/manifests/` |
| `dvka/cluster_fixture.json` | the same cluster as scanner evidence, so no cluster is needed |
| `dvka/cluster_fixture_hardened.json` | only the secure objects; the scanner should report nothing |
| `dvka/ground_truth.json` | the answer key |
| `dvka/CATALOG.md` | the readable list of categories and weaknesses |
| `run_eval.py` | scans the fixtures and scores the result |
| `results/latest.{md,json}` | the last run |

## Run

```bash
python3 eval/dvka/build.py        # only after editing catalog.py
python3 eval/run_eval.py          # report to the terminal and eval/results/
python3 eval/run_eval.py --scale 50 --fail-under 0.9
```

## Deploy to a local cluster and score the live scan

```bash
minikube start                                   # or kind / k3d; Docker must be running
kubectl apply -f eval/dvka/manifests/00-namespaces.yaml
for f in $(ls eval/dvka/manifests/*.yaml | grep -v 95-); do kubectl apply -f $f; done
python3 eval/run_eval.py --live --context minikube   # writes eval/results/live.md
eval/dvka/teardown.sh                            # removes everything DVKA created
```

Do not apply `95-hardened-extras.yaml`: it exists only for the hardened fixture and changes the
`default` namespace. Findings on objects outside DVKA (kube-system and friends) are reported as a
count and not scored, since this key cannot judge them. `CP-*` entries are fixture-only (a normal
cluster cannot be given insecure API-server flags), so a live run scores 83 expected findings
instead of 88.

## How the key is built

* **Single flaw.** Each vulnerable workload is the fully hardened baseline with exactly one
  deviation, so the rules it should trigger are known. A forced second weakness (a privileged
  container must allow privilege escalation) is listed, with the reason.
* **Written from the rules and Kubernetes, not from the scanner's output.** Where the scanner
  disagreed during construction, each disagreement was adjudicated: three were gaps in the key
  (a `(*,*,*)` role really can read Secrets; the `default` namespace really is unprotected; one
  rule id was misspelled) and were corrected with the reason recorded in `catalog.py`.
* **Gaps are in the app on purpose** (`GAP-*`, and `NS-03`): real weaknesses the tool does not
  claim to detect, so recall is not flattered by testing only what the tool was built for.
* **Negatives** (`NEG-*`) must stay unflagged; **probes** (`FP-*`) look like a weakness but are not.

## Matching

A finding is `(rule id, namespace, owning workload)`. The same weakness reported on a Deployment,
its ReplicaSet and its Pod counts once.

## Adding a weakness

Add an `Entry` to `dvka/catalog.py` with the objects and the rules it must trigger, run
`build.py`, run `run_eval.py`. Anything the scanner reports that you did not expect shows up as
a false positive; decide whether the key or the scanner is wrong, and record why.
