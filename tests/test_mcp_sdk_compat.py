"""
The MCP SDK compatibility contract, and the checks that are supposed to enforce it.

This server is written against the v1 SDK: `mcp.server.fastmcp.FastMCP`. mcp 2.x renamed
that class to `MCPServer` and left the old module as a tombstone that raises on import, so
an unbounded `mcp>=1.0` installs an SDK the server cannot start on. The pin is the fix.

The pin alone was not enough, and this file exists because of the gap it left. `doctor`
answered the easy question — does a package named `mcp` import? — which on 2.x is yes, and
reported PASS for an installation that could not serve. A health check that is believed and
wrong is worse than no check at all.

The 2.x failure mode is simulated here rather than installed: an import hook makes
`mcp.server.fastmcp` raise the same `ModuleNotFoundError` the real tombstone raises, while
the top-level package keeps importing. The working SDK in this environment is never touched.
"""
import os
import re
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.mcp.server import (MCP_INSTALL_HINT, REQUIRED_MCP_IMPORT,
                                        REQUIRED_MCP_SPEC, SDK_INCOMPATIBLE, SDK_MISSING,
                                        SDK_OK, sdk_status)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(ROOT, "pyproject.toml")

#: Verbatim from mcp 2.2.0's `mcp/server/fastmcp.py`, which exists only to raise this.
MCP2_MESSAGE = (
    "No module named 'mcp.server.fastmcp'. This is mcp 2.x, where FastMCP was renamed to "
    "MCPServer (from mcp.server.mcpserver import MCPServer) and other APIs changed; see "
    "the migration guide at "
    "https://py.sdk.modelcontextprotocol.io/v2/migration/#fastmcp-renamed-to-mcpserver "
    "or pin 'mcp<2' to keep running v1 code.")


# --------------------------------------------------------------------------- #
# The declared dependency, read from pyproject rather than asserted about
# --------------------------------------------------------------------------- #

def _extras() -> dict:
    """`project.optional-dependencies`, parsed. tomllib is stdlib from 3.11."""
    try:
        import tomllib
    except ModuleNotFoundError:                       # pragma: no cover - 3.10 and older
        import tomli as tomllib                       # type: ignore
    with open(PYPROJECT, "rb") as handle:
        return tomllib.load(handle)["project"]["optional-dependencies"]


def _mcp_requirements(extra: str) -> list:
    return [r for r in _extras()[extra] if re.match(r"^mcp\b", r.strip())]


def test_the_mcp_extra_pins_below_2():
    found = _mcp_requirements("mcp")
    assert found == [REQUIRED_MCP_SPEC], (
        f"[mcp] declares {found}, expected [{REQUIRED_MCP_SPEC!r}]. Without the upper "
        f"bound, pip installs mcp 2.x, where {REQUIRED_MCP_IMPORT} does not exist and "
        f"`k8smatrixwarden mcp` cannot start.")


def test_the_all_extra_pins_below_2():
    found = _mcp_requirements("all")
    assert found == [REQUIRED_MCP_SPEC], (
        f"[all] declares {found}, expected [{REQUIRED_MCP_SPEC!r}]")


def test_every_extra_that_mentions_mcp_carries_the_upper_bound():
    """Catches a NEW extra added without the bound, which the two tests above cannot."""
    for extra, requirements in _extras().items():
        for requirement in requirements:
            if re.match(r"^mcp\b", requirement.strip()):
                assert "<2" in requirement, (
                    f"[{extra}] declares {requirement!r} with no upper bound")


def test_the_pin_and_the_code_constant_agree():
    """One source of truth. The constant drives every message; pyproject must follow it."""
    assert REQUIRED_MCP_SPEC in _extras()["mcp"]
    assert REQUIRED_MCP_SPEC in _extras()["all"]


def test_the_server_still_imports_the_v1_api():
    """If this import ever changes, the pin is describing the wrong contract."""
    import inspect

    from k8smatrixwarden.mcp import server
    source = inspect.getsource(server.serve)
    assert f"from {REQUIRED_MCP_IMPORT} import FastMCP" in source, (
        "serve() no longer imports the v1 FastMCP API; REQUIRED_MCP_IMPORT and the "
        "pin need to be revisited together")


# --------------------------------------------------------------------------- #
# Simulating mcp 2.x without installing it
# --------------------------------------------------------------------------- #

class _Simulated:
    """A stand-in `mcp` package with a chosen shape, for this block only.

    The 2.x case CANNOT be simulated by hooking the installed 1.x package: mcp 1.x's
    `mcp/server/__init__.py` starts with `from .fastmcp import FastMCP`, so blocking that
    submodule also breaks the top-level import and models "the SDK is broken" instead of
    "the SDK is 2.x". The distinction is the entire point of these tests, so the module
    tree is replaced outright and the working SDK is left untouched.

    mode 'mcp2'    `import mcp` succeeds; `mcp.server.fastmcp` raises, exactly as the
                   real 2.x tombstone module does.
    mode 'absent'  nothing named `mcp` is importable.
    """

    def __init__(self, mode, version=None):
        self.mode, self.version = mode, version

    def __enter__(self):
        self.saved = {k: v for k, v in sys.modules.items()
                      if k == "mcp" or k.startswith("mcp.")}
        for name in self.saved:
            del sys.modules[name]

        outer = self

        class _Finder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == REQUIRED_MCP_IMPORT and outer.mode == "mcp2":
                    raise ModuleNotFoundError(MCP2_MESSAGE, name=fullname)
                if outer.mode == "absent" and (fullname == "mcp"
                                               or fullname.startswith("mcp.")):
                    raise ModuleNotFoundError(f"No module named {fullname!r}",
                                              name=fullname)
                return None

        self.finder = _Finder()
        sys.meta_path.insert(0, self.finder)

        if self.mode == "mcp2":
            # 2.x's own __init__ pulls from `mcp_types` and never touches fastmcp, which
            # is why the top-level import keeps working there. A bare stub has the same
            # property without needing the real distribution.
            package = types.ModuleType("mcp")
            package.__path__ = []
            sys.modules["mcp"] = package
            server = types.ModuleType("mcp.server")
            server.__path__ = []
            sys.modules["mcp.server"] = server

        if self.version is not None:
            import importlib.metadata as md
            self.real_version = md.version
            md.version = lambda dist: (self.version if dist == "mcp"
                                       else self.real_version(dist))
        return self

    def __exit__(self, *_):
        sys.meta_path.remove(self.finder)
        for name in [k for k in sys.modules if k == "mcp" or k.startswith("mcp.")]:
            del sys.modules[name]
        if self.version is not None:
            import importlib.metadata as md
            md.version = self.real_version
        sys.modules.update(self.saved)
        return False


def test_a_supported_sdk_reports_ok():
    """A. the environment this suite runs in."""
    found = sdk_status()
    assert found["state"] == SDK_OK, found
    assert found["remediation"] is None
    assert REQUIRED_MCP_IMPORT in found["detail"]


def test_a_missing_sdk_is_reported_as_missing_not_incompatible():
    """B. absent is a fact, and a different fact from present-but-wrong."""
    with _Simulated("absent"):
        found = sdk_status()
    assert found["state"] == SDK_MISSING, found
    assert found["remediation"] == MCP_INSTALL_HINT


def test_mcp_2x_is_reported_incompatible_not_ok():
    """C. THE REGRESSION. Top-level `import mcp` succeeds; the required module does not.

    A check that asks the easier question passes here, which is precisely what happened."""
    with _Simulated("mcp2", version="2.2.0"):
        # The simulation has to be faithful, or the test proves nothing.
        import mcp  # noqa: F401  -- must still import, exactly as on real 2.x
        try:
            __import__(REQUIRED_MCP_IMPORT)
            raise AssertionError("the simulation did not block the required import")
        except ModuleNotFoundError:
            pass
        found = sdk_status()

    assert found["state"] == SDK_INCOMPATIBLE, found
    assert found["state"] != SDK_OK, "mcp 2.x must never be reported as usable"
    assert found["version"] == "2.2.0"
    assert REQUIRED_MCP_SPEC in found["detail"]
    assert found["remediation"] == MCP_INSTALL_HINT


def test_doctor_fails_rather_than_passes_on_mcp_2x():
    """The check an operator actually reads. PASS here was the whole defect."""
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.doctor import FAIL, PASS, _dependencies, _mcp

    platform = build_platform()
    with _Simulated("mcp2", version="2.2.0"):
        sdk = [c for c in _mcp(platform).checks if c.name == "MCP SDK"]
        optional = [c for c in _dependencies().checks if c.name == "mcp"]

    assert sdk and sdk[0].status == FAIL, sdk
    assert sdk[0].status != PASS, "doctor reported a usable SDK on mcp 2.x"
    assert "mcp<2" in sdk[0].detail or REQUIRED_MCP_SPEC in sdk[0].detail
    # The optional-dependency row asked the same easy question and must not disagree.
    assert optional and optional[0].status == FAIL, optional


def test_doctor_calls_a_missing_sdk_optional_not_broken():
    """An absent optional extra is a statement of fact, never a fault."""
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.doctor import NOT_CONFIGURED, _mcp

    with _Simulated("absent"):
        sdk = [c for c in _mcp(build_platform()).checks if c.name == "MCP SDK"]
    assert sdk and sdk[0].status == NOT_CONFIGURED, sdk


def test_doctor_passes_on_the_supported_sdk():
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.doctor import PASS, _mcp

    sdk = [c for c in _mcp(build_platform()).checks if c.name == "MCP SDK"]
    assert sdk and sdk[0].status == PASS, sdk


# --------------------------------------------------------------------------- #
# Remediation must not reinstall the thing that broke you
# --------------------------------------------------------------------------- #

def test_the_install_hint_carries_the_upper_bound():
    assert REQUIRED_MCP_SPEC in MCP_INSTALL_HINT
    assert "<2" in MCP_INSTALL_HINT
    # Quoted, because an unquoted `<` redirects in a POSIX shell and in cmd.exe alike.
    assert f'"{REQUIRED_MCP_SPEC}"' in MCP_INSTALL_HINT, MCP_INSTALL_HINT


def test_serve_does_not_advise_an_unbounded_install():
    """REGRESSION. The old message said `pip install mcp`, which on 2.x reinstalls the
    exact SDK that just failed and reproduces the error."""
    import inspect

    from k8smatrixwarden.mcp import server
    source = inspect.getsource(server.serve)
    assert re.search(r"pip install mcp\\n", source) is None, \
        "serve() still recommends an unbounded `pip install mcp`"
    assert "REQUIRED_MCP_SPEC" in source, \
        "serve()'s remediation no longer names the supported range"


def test_serve_reports_the_required_range_when_it_cannot_start():
    """The message an operator sees must name the contract, the installed version, and a
    command that actually fixes it."""
    from k8smatrixwarden.mcp.server import serve

    with _Simulated("mcp2", version="2.2.0"):
        try:
            serve()
            raise AssertionError("serve() started on a simulated mcp 2.x")
        except SystemExit as exc:
            message = str(exc)

    assert REQUIRED_MCP_SPEC in message, message
    assert "2.2.0" in message, "the installed version is not reported"
    assert f'pip install "{REQUIRED_MCP_SPEC}"' in message
    assert re.search(r"pip install mcp\s*$", message, re.M) is None, \
        "an unbounded install command survives in the message"
    # The SDK's own migration hint travels through, since it is better than ours.
    assert "MCPServer" in message


def test_no_documentation_recommends_an_unbounded_mcp_install():
    """A doc that says `pip install mcp` hands the reader the 2.x problem.

    Scoped to prose and markup. Source is covered by
    test_serve_does_not_advise_an_unbounded_install, and this file necessarily quotes the
    bad command in its own assertion messages -- a scan that flagged those would be
    measuring itself.
    """
    offenders = []
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "__pycache__", "node_modules", ".venv")]
        for name in files:
            if not name.endswith((".md", ".html", ".rst", ".txt")):
                continue
            path = os.path.join(folder, name)
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            for match in re.finditer(r"pip install (?:-U )?mcp(?![\w<>=\-.\"'])", text):
                line = text[:match.start()].count("\n") + 1
                offenders.append(f"{os.path.relpath(path, ROOT)}:{line}")
    assert not offenders, (
        f"unbounded install instruction in: {', '.join(offenders)} -- it installs mcp "
        f"2.x, which cannot run this server. Use {MCP_INSTALL_HINT!r}.")


if __name__ == "__main__":
    import traceback
    failed = 0
    for key, fn in sorted(globals().items()):
        if key.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {key}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
