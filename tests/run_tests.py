"""
Zero-dependency test runner (the target env has no pytest).

Discovers `test_*` functions in this directory and runs them. If real pytest is installed,
`python -m pytest tests/` works too, this runner injects a minimal `pytest.raises` shim
only when pytest is absent, so the test files stay pytest-native.
"""
import contextlib
import importlib
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# ---- pytest shim (only if the real thing is missing) -------------------- #
try:
    import pytest  # noqa: F401
except ImportError:
    import types

    shim = types.ModuleType("pytest")

    class _Info:
        """Mimics pytest's ExceptionInfo enough for `with pytest.raises(X) as e:`, 
        `e.value` is the caught exception."""
        value = None

    @contextlib.contextmanager
    def _raises(exc):
        info = _Info()
        try:
            yield info
        except exc as caught:
            info.value = caught
            return
        except Exception as other:  # wrong exception type
            raise AssertionError(f"expected {exc}, got {type(other)}: {other}")
        raise AssertionError(f"expected {exc} to be raised, nothing was")

    shim.raises = _raises
    sys.modules["pytest"] = shim


def main() -> int:
    modules = [f[:-3] for f in os.listdir(HERE)
               if f.startswith("test_") and f.endswith(".py")]
    passed = failed = 0
    failures = []
    for modname in sorted(modules):
        mod = importlib.import_module(f"tests.{modname}")
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            fn = getattr(mod, name)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
                print(f"  PASS  {modname}::{name}")
            except Exception as exc:
                failed += 1
                failures.append((modname, name, exc))
                print(f"  FAIL  {modname}::{name} , {exc}")
    print(f"\n{passed} passed, {failed} failed")
    if failures:
        print("\n--- failure detail ---")
        for modname, name, exc in failures:
            print(f"\n{modname}::{name}")
            traceback.print_exception(type(exc), exc, exc.__traceback__)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
