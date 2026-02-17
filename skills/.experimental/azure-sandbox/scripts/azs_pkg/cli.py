"""CLI facade for azs."""

from __future__ import annotations

from . import commands


def main(argv: list[str] | None = None) -> int:
    return commands.main(argv)
