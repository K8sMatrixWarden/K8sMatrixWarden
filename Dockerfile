# k8smatrixwarden: read-only Kubernetes security checks.
#
#   docker build -t k8smatrixwarden .
#   docker run --rm -v "$PWD/k8s:/work:ro" k8smatrixwarden check /work --fail-on HIGH
#   docker run --rm -v ~/.kube:/root/.kube:ro k8smatrixwarden check          # live cluster
#
# Add image CVE scanning with:  docker build --build-arg WITH_GRYPE=1 -t k8smatrixwarden .
FROM python:3.12-slim
ARG WITH_GRYPE=0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && if [ "$WITH_GRYPE" = "1" ]; then \
         curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin; \
       fi \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY k8smatrixwarden ./k8smatrixwarden
RUN pip install --no-cache-dir ".[live,manifests]"
WORKDIR /work
ENTRYPOINT ["k8smatrixwarden"]
CMD ["check", "--help"]
