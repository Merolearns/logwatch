"""Tests for the logwatch CLI entry point (--top validation)."""

import os

import pytest

from logwatch import main

SAMPLE = os.path.join(os.path.dirname(__file__), "access.log.sample")


def test_top_zero_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--top", "0", SAMPLE])
    assert exc.value.code == 2
    assert "--top must be more than 0" in capsys.readouterr().err


def test_top_negative_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--top", "-3", SAMPLE])
    assert exc.value.code == 2
    assert "--top must be more than 0" in capsys.readouterr().err


def test_top_positive_runs(capsys):
    assert main(["--top", "3", SAMPLE]) == 0
    out = capsys.readouterr().out
    assert "top 3 IPs" in out
