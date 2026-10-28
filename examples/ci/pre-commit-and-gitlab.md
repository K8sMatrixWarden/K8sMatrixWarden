# Other places to run it

**Pre-commit (before the code leaves the laptop)**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: k8smatrixwarden
        name: Kubernetes security check
        entry: k8smatrixwarden check --fail-on HIGH
        language: system
        files: \.(ya?ml)$
        pass_filenames: true
```

**GitLab CI**
```yaml
k8s-security:
  image: {name: ghcr.io/YOUR-ORG/k8smatrixwarden, entrypoint: [""]}
  script: k8smatrixwarden check k8s/ --fail-on HIGH -o sarif --output-file gl-sast-report.sarif
```

**Any CI, with the container image**
`docker run --rm -v "$PWD:/work:ro" k8smatrixwarden check /work/k8s --fail-on HIGH`
