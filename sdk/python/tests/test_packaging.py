"""
Packaging tests for the Akasha Python SDK.

These build a real wheel from this project and inspect it. They exist because
the failure they pin is silent: a wheel with no code installs successfully and
only fails later, at `import akasha`, in someone else's environment.
"""

import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build_wheel(outdir: Path) -> Path:
    """Build a wheel from the SDK project into outdir and return its path."""
    for mod in ("build", "hatchling"):
        if importlib.util.find_spec(mod) is None:
            pytest.skip(f"{mod} is not installed — cannot build a wheel here")

    # --no-isolation: with isolation, build fetches hatchling from PyPI, which
    # turns this into a network test.
    proc = subprocess.run(
        [
            sys.executable, "-m", "build",
            "--wheel", "--no-isolation",
            "--outdir", str(outdir),
            str(PROJECT_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"wheel build failed:\n{proc.stdout}\n{proc.stderr}"

    wheels = sorted(outdir.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    return wheels[0]


def test_wheel_contains_the_akasha_package(tmp_path):
    """GUARANTEE: the built wheel actually ships the akasha package.

    A repo-root ignore pattern once excluded every source file from the wheel
    while the build still reported success.
    """
    wheel = build_wheel(tmp_path)
    names = zipfile.ZipFile(wheel).namelist()

    for want in [
        "akasha/__init__.py",
        "akasha/client.py",
        "akasha/integrations/__init__.py",
    ]:
        assert want in names, f"{want} missing from wheel; wheel contains {names}"


def test_wheel_is_not_an_empty_shell(tmp_path):
    """GUARANTEE: the wheel is more than dist-info metadata.

    The code-free wheel was 1057 bytes of pure metadata; a wheel that carries
    the SDK is an order of magnitude larger.
    """
    wheel = build_wheel(tmp_path)
    names = zipfile.ZipFile(wheel).namelist()

    code = [n for n in names if n.endswith(".py")]
    assert len(code) >= 5, f"wheel carries only {code}"
    assert wheel.stat().st_size > 10_000, f"wheel is only {wheel.stat().st_size} bytes"


def test_wheel_ships_no_bytecode(tmp_path):
    """GUARANTEE: no __pycache__ or .pyc from the working tree leaks into the wheel."""
    wheel = build_wheel(tmp_path)
    names = zipfile.ZipFile(wheel).namelist()

    for name in names:
        assert "__pycache__" not in name, f"{name} should not be in the wheel"
        assert not name.endswith(".pyc"), f"{name} should not be in the wheel"
