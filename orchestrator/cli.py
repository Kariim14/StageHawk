#!/usr/bin/env python3
"""Thin CLI wrapper around the reusable orchestrator backend."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from orchestrator.core.pipeline import run_full_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m orchestrator",
        description="Automated defensive multi-stage dropper analysis orchestrator.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Run the full backend pipeline for a sample.")
    analyze.add_argument("sample", help="Path to the sample to analyze.")
    analyze.add_argument("--case-name", default=None, help="Human-readable case name.")
    analyze.add_argument("--config", default=None, help="Optional config file path.")
    analyze.add_argument("--max-depth", type=int, default=2, help="Maximum recursive analysis depth.")
    analyze.add_argument(
        "--mode",
        choices=["full", "static", "dynamic"],
        default="full",
        help="Analysis mode: full = Ghidra + CAPE, static = no execution, dynamic = CAPE sandbox only.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        result = run_full_pipeline(
            sample_path=Path(args.sample),
            case_name=args.case_name,
            config_path=Path(args.config) if args.config else None,
            max_depth=args.max_depth,
            mode=args.mode,
            config_overrides=None,
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("current_status") != "failed" else 1

    parser.error(f"unknown command: {args.command}")
    return 2
