"""Stdlib-only test runner for environments without pytest installed.

This is NOT part of the shipped package — it's just for validating the build
in environments (like this one) where we can't pip install pytest. In normal
use, run ``pytest tests/`` instead.

Implements just enough of pytest's API to run our tests:
    - Discovers ``test_*.py`` files in ``tests/``.
    - Calls every top-level ``test_*`` function in each module.
    - Provides a ``pytest`` shim module with ``pytest.raises`` and
      ``pytest.fixture``.
    - Supports ``monkeypatch`` fixture by passing in a tiny implementation.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
import sys
import traceback
import types
from contextlib import contextmanager
from pathlib import Path


# --------------------------------------------------------------------- pytest shim


class _PytestRaisesContext:
    def __init__(self, expected):
        self.expected = expected
        self.value = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"Expected {self.expected.__name__} but no exception was raised")
        if not issubclass(exc_type, self.expected):
            return False
        self.value = exc_val
        return True


def _pytest_raises(expected):
    return _PytestRaisesContext(expected)


def _pytest_fixture(*args, **kwargs):
    def decorator(fn):
        return fn
    if len(args) == 1 and callable(args[0]) and not kwargs:
        return args[0]
    return decorator


class _SkippedModule(Exception):
    """Raised by the shimmed ``pytest.importorskip`` when the requested module
    is unavailable. The runner catches this at module import time and reports
    the file as skipped rather than failed — matching real pytest semantics
    when optional dependencies aren't installed.
    """

    def __init__(self, modname: str, reason: str) -> None:
        super().__init__(f"could not import {modname!r}: {reason}")
        self.modname = modname
        self.reason = reason


def _pytest_importorskip(modname, minversion=None, reason=None):
    """Stdlib-runner equivalent of ``pytest.importorskip``.

    Real pytest skips the calling module if the requested package can't be
    imported. We can't suspend a module mid-import, so we raise
    ``_SkippedModule`` and let the runner treat that as a clean skip.
    """
    import importlib
    try:
        return importlib.import_module(modname)
    except ImportError as exc:
        raise _SkippedModule(modname, reason or str(exc)) from exc


pytest_mod = types.ModuleType("pytest")
pytest_mod.raises = _pytest_raises
pytest_mod.fixture = _pytest_fixture
pytest_mod.importorskip = _pytest_importorskip
sys.modules["pytest"] = pytest_mod


# --------------------------------------------------------------------- monkeypatch shim


class MonkeyPatch:
    def __init__(self):
        self._setenv = []
        self._delenv = []

    def setenv(self, key, value):
        prev = os.environ.get(key)
        self._setenv.append((key, prev))
        os.environ[key] = value

    def delenv(self, key, raising=True):
        prev = os.environ.get(key)
        if prev is None and raising:
            raise KeyError(key)
        self._delenv.append((key, prev))
        os.environ.pop(key, None)

    def undo(self):
        for key, prev in reversed(self._setenv):
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev
        for key, prev in reversed(self._delenv):
            if prev is not None:
                os.environ[key] = prev


# --------------------------------------------------------------------- runner


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve cls.__module__.
    sys.modules[path.stem] = mod
    spec.loader.exec_module(mod)
    return mod


def run():
    root = Path(__file__).parent
    test_files = sorted(root.glob("test_*.py"))

    passed = 0
    skipped: list[tuple[str, str]] = []
    failed = []

    for tf in test_files:
        print(f"\n=== {tf.name} ===")
        try:
            mod = load_module(tf)
        except _SkippedModule as exc:
            print(f"  SKIPPED: {exc}")
            skipped.append((tf.name, str(exc)))
            continue
        except Exception as exc:
            print(f"  IMPORT FAILED: {exc}")
            traceback.print_exc()
            failed.append((tf.name, "<import>", exc))
            continue

        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if not name.startswith("test_"):
                continue
            if fn.__module__ != mod.__name__:
                continue
            params = inspect.signature(fn).parameters
            mp = MonkeyPatch() if "monkeypatch" in params else None
            try:
                if mp is not None:
                    fn(mp)
                else:
                    fn()
                print(f"  ✓ {name}")
                passed += 1
            except Exception as exc:
                print(f"  ✗ {name}: {exc}")
                traceback.print_exc()
                failed.append((tf.name, name, exc))
            finally:
                if mp is not None:
                    mp.undo()

    print(f"\n{'=' * 60}")
    summary = f"{passed} passed, {len(failed)} failed"
    if skipped:
        summary += f", {len(skipped)} skipped"
    print(summary)
    if skipped:
        print("\nSkipped:")
        for fname, reason in skipped:
            print(f"  {fname}: {reason}")
    if failed:
        print("\nFailures:")
        for fname, tname, exc in failed:
            print(f"  {fname}::{tname}: {exc!r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
