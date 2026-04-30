"""Carrega o script (que tem hifen no nome) como modulo `sdd`."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sensitive-data-detector.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sdd", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["sdd"] = module
    spec.loader.exec_module(module)
    return module


sdd = _load_module()


@pytest.fixture(scope="session")
def module():
    return sdd


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return ROOT / "tests" / "fixtures"
