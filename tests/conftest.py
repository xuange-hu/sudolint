"""Fixtures and shared construction helpers for the sudolint suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from helpers import report_from  # noqa: E402  (path set above)

CLEAN_SUDOERS = "ops ALL = /usr/bin/systemctl status app\n"

BAD_SUDOERS = "Defaults !env_reset\nroot ALL = (ALL) ALL\ndeploy ALL = NOPASSWD: ALL\nops ALL = /bin/bash\n"


@pytest.fixture
def clean_sudoers():
    return report_from(CLEAN_SUDOERS, source="sudoers")


@pytest.fixture
def bad_sudoers():
    return report_from(BAD_SUDOERS, source="sudoers")


@pytest.fixture
def empty_sudoers():
    return report_from("# nothing here\n", source="empty.sudoers")
