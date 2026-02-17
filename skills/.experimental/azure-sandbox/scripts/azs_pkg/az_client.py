"""Azure CLI execution facade."""

from __future__ import annotations

from .commands import az_json, az_rest, az_tsv, run_az, run_az_operator, run_az_runtime

__all__ = [
    "az_json",
    "az_rest",
    "az_tsv",
    "run_az",
    "run_az_operator",
    "run_az_runtime",
]
