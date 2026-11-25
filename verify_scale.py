#!/usr/bin/env python3
"""Independent raw-segment checker for the 60,000-record scale case.

Verification itself imports only the standard library and never imports the
generator.  ``--generate`` is an explicit opt-in that uses the local synthetic
generator before the independent check runs.

Native Windows / Python 3.12.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def read_range(path: Path, start: int, end: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(end - start)


def verify_scale_records(root: Path) -> dict[str, Any]:
    index = json.loads((root / "segment-index.json").read_text(encoding="utf-8"))
    chosen_rev = index["cross_revision"]
    extents = index["extents"][chosen_rev]

    revisions: dict[str, dict[str, Any]] = {}
    with open(root / "calibration-revisions.jsonl", "rb") as f:
        for raw in f:
            if raw.strip():
                obj = json.loads(raw.decode("utf-8"))
                revisions[obj["calib_rev"]] = obj

    # Independent full scan: this is the comparison universe.
    full_records: dict[str, dict[str, Any]] = {}
    full_count = 0
    partition_files = sorted((root / "partitions").glob("partition=*/records.jsonl"))
    for path in partition_files:
        with open(path, "rb") as f:
            for raw in f:
                if not raw.strip():
                    continue
                obj = json.loads(raw.decode("utf-8"))
                full_count += 1
                rid = obj["record_id"]
                if rid in full_records:
                    raise AssertionError(f"duplicate record id in full scan: {rid}")
                full_records[rid] = obj

    expected_cross = [r for r in full_records.values()
                      if r["calib_rev"] == chosen_rev]

    compared = 0
    seen_ids: set[str] = set()
    extent_summaries = []
    for extent in extents:
        path = root / extent["path"]
        actual_size = path.stat().st_size
        need = int(extent["end_offset"])
        if int(extent["start_offset"]) < 0 or need > actual_size:
            raise AssertionError(f"raw extent outside file: {extent}")
        blob = read_range(path, int(extent["start_offset"]), need)
        actual_hash = sha256_hex(blob)
        if actual_hash != extent["raw_sha256"]:
            raise AssertionError(f"raw extent hash mismatch: {extent['path']}")

        lines = [line for line in blob.splitlines() if line.strip()]
        if len(lines) != int(extent["count"]):
            raise AssertionError(
                f"raw count mismatch {extent['path']}: "
                f"read {len(lines)}, index={extent['count']}"
            )

        for raw_line in lines:
            obj = json.loads(raw_line.decode("utf-8"))
            rid = obj["record_id"]
            if rid in seen_ids:
                raise AssertionError(f"record repeated across raw extents: {rid}")
            seen_ids.add(rid)
            full_obj = full_records.get(rid)
            if full_obj is None:
                raise AssertionError(f"raw record missing from full scan: {rid}")
            if canonical_bytes(obj) != canonical_bytes(full_obj):
                raise AssertionError(f"raw/full canonical mismatch: {rid}")

            rev = revisions[obj["calib_rev"]]
            lo = int(obj["local_t"]) + int(rev["offset_lo"])
            hi = int(obj["local_t"]) + int(rev["offset_hi"])
            if lo > hi:
                raise AssertionError(f"invalid calibrated interval: {rid}")
            compared += 1

        extent_summaries.append({
            "partition": extent["partition"],
            "path": extent["path"],
            "raw_bytes": need - int(extent["start_offset"]),
            "records_read": len(lines),
            "sha256": actual_hash,
        })

    expected_ids = {r["record_id"] for r in expected_cross}
    if compared != len(expected_cross) or seen_ids != expected_ids:
        raise AssertionError("raw extent set differs from full-scan revision set")
    if full_count != int(index["total_records"]):
        raise AssertionError(
            f"full count {full_count} != index {index['total_records']}"
        )

    sample = min(expected_cross, key=lambda r: r["global_index"])
    sample_rev = revisions[chosen_rev]
    return {
        "ok": True,
        "verifier": "verify_scale.py standalone stdlib checker",
        "total_partition_records_full_scan": full_count,
        "partition_files_read": len(partition_files),
        "chosen_cross_partition_revision": chosen_rev,
        "revision_scope": sample_rev["scope"],
        "raw_extents_read": len(extents),
        "cross_revision_records_in_full_scan": len(expected_cross),
        "raw_records_read_and_compared_one_by_one": compared,
        "mismatches": 0,
        "sample_record_id": sample["record_id"],
        "sample_partition": sample["partition"],
        "sample_calibrated_interval": [
            int(sample["local_t"]) + int(sample_rev["offset_lo"]),
            int(sample["local_t"]) + int(sample_rev["offset_hi"]),
        ],
        "extent_summaries": extent_summaries,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--generate", action="store_true",
                   help="generate synthetic 60k records before independent verification")
    p.add_argument("--json-out", type=Path)
    args = p.parse_args(argv)

    if args.generate:
        # Imported only for explicit data generation; verification below does
        # not call the generator module's checker.
        from forensic_audit.scale import generate_scale_case
        generate_scale_case(args.root)

    report = verify_scale_records(args.root)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
