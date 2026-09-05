"""
The dashboard's inline JavaScript has to parse.

This exists because of a real regression that shipped: an edit inserted a new function
between `async` and `function refreshRuntime`, orphaning the keyword. `refreshRuntime` was
no longer async, its `await` became a syntax error, and the browser refused the whole
script block -- so every interactive element on the dashboard silently stopped working.
Nothing caught it. The tests around it asserted that certain strings appeared in the HTML,
which they all still did; a page whose script never runs looks identical to string matching.

So: parse it. `node --check` when node is on PATH, and a structural check that catches this
same class of damage when it is not, because a check that skips itself on the machine that
matters is not a check.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.web.app import WebApp

_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)


def _pages():
    """Every HTML surface, rendered the way the server renders it."""
    app = WebApp(build_platform(), reports_dir=tempfile.mkdtemp())
    for path in ("/", "/runtime-management", "/runtime-events", "/reports"):
        response = app.route("GET", path)
        if response.status == 200:
            yield path, response.text


def _scripts(html):
    return [body for body in _SCRIPT.findall(html) if body.strip()]


def test_every_inline_script_parses():
    """The check that would have caught the orphaned `async`."""
    node = shutil.which("node")
    checked = 0
    for path, html in _pages():
        for index, body in enumerate(_scripts(html)):
            checked += 1
            if node:
                _node_check(node, body, f"{path} script #{index}")
            _no_orphan_async(body, f"{path} script #{index}")
            _await_only_inside_async(body, f"{path} script #{index}")
    assert checked, "no inline scripts were found -- this test stopped testing anything"


def _node_check(node, body, where):
    # A module, so top-level `await` is legal and only a genuine misplacement fails.
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False,
                                     encoding="utf-8") as handle:
        handle.write(body)
        name = handle.name
    try:
        done = subprocess.run([node, "--check", name], capture_output=True, text=True)
        assert done.returncode == 0, f"{where} does not parse:\n{done.stderr.strip()}"
    finally:
        os.unlink(name)


def _no_orphan_async(body, where):
    """`async` must introduce a function. Anything else means an edit landed inside it."""
    for match in re.finditer(r"\basync\b(.{0,40})", body, re.S):
        tail = match.group(1).lstrip()
        assert tail.startswith(("function", "(", "=>")) or re.match(r"\w+\s*(=>|\()", tail), \
            f"{where}: `async` does not introduce a function -- {tail[:40]!r}"


def _await_only_inside_async(body, where):
    """Every `function NAME(` whose body awaits must be declared `async`."""
    for match in re.finditer(r"(async\s+)?function\s+(\w+)\s*\(", body):
        start = body.index("{", match.end())
        depth, end = 0, start
        for index in range(start, len(body)):
            if body[index] == "{":
                depth += 1
            elif body[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        inner = body[start:end]
        # Strip nested functions: their awaits belong to them, not to this one.
        own = re.sub(r"(async\s+)?function\s*\w*\s*\([^)]*\)\s*\{", "{", inner)
        if re.search(r"\bawait\s", own) and "=>" not in own.split("await")[0][-80:]:
            assert match.group(1), \
                f"{where}: function {match.group(2)} awaits but is not async"


def test_the_dashboard_defines_the_functions_its_markup_calls():
    """A script that fails to parse still contains every string a grep would look for, so
    assert the definitions exist alongside the onclick handlers that need them."""
    html = next(text for path, text in _pages() if path == "/")
    joined = "\n".join(_scripts(html))
    for name in re.findall(r"onclick='(\w+)\(", html):
        # `function f(){}`, `window.f=function(){}` and `const f=(...)=>` all count.
        defined = re.search(rf"\bfunction\s+{name}\s*\(", joined) or re.search(
            rf"\b{name}\s*=\s*(async\s+)?(function\b|\()", joined)
        assert defined, f"markup calls {name}() but no script defines it"


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
