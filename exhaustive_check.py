#!/usr/bin/env python3
"""Exhaustive small-sample ordering/withdrawal permutation checker."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from forensic_audit.exhaustive import brute_force_order_cases


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--json-out", type=str)
    args = p.parse_args()
    report = brute_force_order_cases()
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
