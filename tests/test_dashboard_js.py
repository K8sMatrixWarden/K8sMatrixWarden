"""The dashboard is one big script; a single typo blanks the whole page, so parse it."""
import re
import shutil
import subprocess

import pytest

from k8smatrixwarden.web.pages import dashboard_page


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
def test_every_inline_script_parses(tmp_path):
    for i, src in enumerate(re.findall(r"<script>(.*?)</script>", dashboard_page(has_scan=True), re.S)):
        f = tmp_path / f"s{i}.js"
        f.write_text(src)
        r = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[:400]


def test_wiring_helpers_tolerate_a_view_that_has_no_scan_form():
    """Removing the scan form from a view once threw inside render() and blanked every tab."""
    page = dashboard_page(has_scan=True)
    body = page[page.index("function toggleLive"):page.index("function wireScan")]
    assert "$('#mock').value" not in body, "read through a null check"
