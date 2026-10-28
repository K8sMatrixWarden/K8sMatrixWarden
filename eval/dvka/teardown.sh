#!/usr/bin/env bash
# Remove everything DVKA created (objects carry app.kubernetes.io/part-of=dvka).
# Namespaces cascade to everything inside them. The built-in `default` namespace is untouched.
set -euo pipefail
CTX="${1:-$(kubectl config current-context)}"
echo "Removing DVKA from context: $CTX"
kubectl --context "$CTX" delete namespace,clusterrolebinding,clusterrole,mutatingwebhookconfiguration \
  -l app.kubernetes.io/part-of=dvka --ignore-not-found
kubectl --context "$CTX" delete deployment -n default -l app.kubernetes.io/part-of=dvka --ignore-not-found
