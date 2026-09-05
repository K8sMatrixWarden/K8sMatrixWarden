"""
Every CSS custom property a page uses has to be defined somewhere that page can see it.

CSS fails silently in a specific and expensive way: `border: 1px solid var(--nope)` with
`--nope` undefined does not fall back to a default border, it makes the whole declaration
invalid and the browser drops it. The element gets no border at all, no console error, no
warning. The page renders, just wrong.

That is not hypothetical here. `--line`, `--panel` and `--medium` were written where the
design system's tokens are `--bd`, `--card` and `--med`. The Runtime Management panels had
`border-style: none` and a transparent background, and the `.warn` block lost the coloured
left bar that carried its severity -- a status indicator that had simply stopped existing.

So: read what the server actually serves, and hold every `var(--x)` to a definition.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.web.app import WebApp

USE = re.compile(r"var\(\s*(--[\w-]+)\s*(,[^)]*)?\)")
DEFINE = re.compile(r"(--[\w-]+)\s*:")

#: Pages worth holding to this. Each is rendered exactly as the server renders it.
PATHS = ("/", "/runtime-management", "/runtime-events", "/reports")


def _served():
    app = WebApp(build_platform(), reports_dir=tempfile.mkdtemp())
    for path in PATHS:
        response = app.route("GET", path)
        if response.status == 200:
            yield path, response.text


def test_every_used_custom_property_is_defined():
    """The gate. An undefined property silently deletes the declaration that uses it."""
    for path, html in _served():
        defined = set(DEFINE.findall(html))
        for name, fallback in USE.findall(html):
            assert name in defined or fallback, (
                f"{path} uses {name}, which nothing on that page defines. The whole "
                f"declaration will be dropped and the element rendered without it.")


def test_no_custom_property_is_defined_and_never_used():
    """Dead tokens are how a palette drifts out of step with the pages that read it."""
    for path, html in _served():
        used = {name for name, _ in USE.findall(html)}
        for name in set(DEFINE.findall(html)):
            assert name in used, f"{path} defines {name} but nothing uses it"


def test_the_severity_palette_is_complete_on_every_page():
    """Severity is colour here, so a missing severity token is a missing signal."""
    for path, html in _served():
        defined = set(DEFINE.findall(html))
        for name in ("--crit", "--high", "--med", "--low", "--muted"):
            assert name in defined, f"{path} has no {name}; severity cannot render"


def test_the_tokens_a_severity_notice_reads_all_exist():
    """feedNotice picks its colour from a literal map, so the map is worth naming."""
    html = next(text for path, text in _served() if path == "/")
    notice = html[html.index("function feedNotice"):][:600]
    defined = set(DEFINE.findall(html))
    tones = USE.findall(notice)
    assert tones, "feedNotice no longer names any custom property"
    for name, _ in tones:
        assert name in defined, f"feedNotice uses {name}, which no rule defines"


def test_the_names_that_were_wrong_stay_gone():
    """REGRESSION. These three read like the real tokens and resolve to nothing."""
    for path, html in _served():
        for wrong, right in (("--line", "--bd"), ("--panel", "--card"),
                             ("--medium", "--med")):
            assert f"var({wrong})" not in html, \
                f"{path}: var({wrong}) is undefined here; the token is {right}"


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
