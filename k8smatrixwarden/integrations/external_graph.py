"""
Optional passthrough runners for external attack-graph tools (KubeHound, IceKube).

These tools answer a question K8sMatrixWarden deliberately doesn't: multi-hop asset-to-asset
attack-path graphs (shortest path to cluster-admin). If a customer wants that, we shell out
to the real tool and hand back its native output path -- we do NOT parse their graph into our
Findings model (different data shape: asset-graph vs config posture, and re-modelling it would
just be a worse copy of their core product).

ponytail: availability check + subprocess passthrough. No result normalisation, no bundled
graph DB. Both tools need their own backend (KubeHound: JanusGraph/Docker; IceKube: Neo4j),
so "install" here means "point us at an already-installed binary". Deepen only if a customer
actually consumes the output through us rather than the tools' own Jupyter/Neo4j UIs.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Optional

_TOOLS = {
    "kubehound": "https://github.com/DataDog/KubeHound",
    "icekube": "https://github.com/ReversecLabs/IceKube",
}


def available() -> dict[str, bool]:
    """Which external graph tools are installed and on PATH."""
    return {name: bool(shutil.which(name)) for name in _TOOLS}


def _run(name: str, args: list[str], timeout: int) -> subprocess.CompletedProcess:
    exe = shutil.which(name)
    if not exe:
        raise RuntimeError(f"{name} is not installed or not on PATH. See {_TOOLS[name]}")
    # capture, never raise on tool's own non-zero exit -- caller inspects returncode/stderr
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout)


def run_kubehound(kubeconfig: Optional[str] = None,
                  timeout: int = 900) -> subprocess.CompletedProcess:
    """Run KubeHound against the current (or given) cluster. Requires its Docker backend to
    be up (`kubehound backend up`). Returns the completed process; the attack graph lands in
    KubeHound's JanusGraph — query it via its Jupyter notebook, not through us."""
    args = ["dump", "remote"] if kubeconfig is None else ["dump", "remote", "--kubeconfig", kubeconfig]
    return _run("kubehound", args, timeout)


def run_icekube(out_file: str = "icekube.dump",
                timeout: int = 900) -> subprocess.CompletedProcess:
    """Run IceKube enumeration against the current cluster into its Neo4j backend. Query the
    attack paths with Cypher in the Neo4j browser. `out_file` is IceKube's offline dump."""
    return _run("icekube", ["download", "--output", out_file], timeout)


if __name__ == "__main__":
    # smallest runnable check: availability probe never crashes and reports both tools
    avail = available()
    assert set(avail) == set(_TOOLS), avail
    assert all(isinstance(v, bool) for v in avail.values()), avail
    print("external graph tools:", avail)
