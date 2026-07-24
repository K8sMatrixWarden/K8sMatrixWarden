"""
Compliance framework engines (§5.9). Full CIS Kubernetes Benchmark v1.8 coverage (130
controls) via a catalog-driven engine that evaluates every control natively where the K8s
API allows, delegates node/file/process controls to kube-bench, and surfaces the rest as
manual, nothing is silently omitted.
"""
from .cis import CISBenchmarkEngine, render_markdown, render_text
from .cis_catalog import BENCHMARK_TITLE, CIS_1_8, catalog_summary

__all__ = ["CISBenchmarkEngine", "render_text", "render_markdown", "CIS_1_8",
           "catalog_summary", "BENCHMARK_TITLE"]
