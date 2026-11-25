from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex, write_json_atomic

CROSS_REVISION = "CAL-CROSS-REGION-REV-7"
TOTAL_RECORDS = 60_000
PARTITION_COUNT = 24
PER_PARTITION = TOTAL_RECORDS // PARTITION_COUNT  # 2,500


def _fsync_file(f) -> None:
    f.flush()
    os.fsync(f.fileno())


def generate_scale_case(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    part_root = root / "partitions"
    part_root.mkdir(parents=True, exist_ok=True)

    revisions: dict[str, dict[str, Any]] = {
        CROSS_REVISION: {
            "v": 1,
            "kind": "calibration_revision",
            "calib_rev": CROSS_REVISION,
            "revision_of": "CAL-REGION-BASE",
            "scope": "cross-partition",
            "applies_to_partitions": [f"{p:02d}" for p in range(PARTITION_COUNT)],
            "offset_lo": -5,
            "offset_hi": 9,
            "reason": "synthetic cross-region clock revision",
        }
    }
    for p in range(PARTITION_COUNT):
        rev = f"CAL-P-{p:02d}"
        revisions[rev] = {
            "v": 1,
            "kind": "calibration_revision",
            "calib_rev": rev,
            "scope": "partition",
            "offset_lo": -2 - (p % 3),
            "offset_hi": 3 + (p % 4),
        }

    rev_path = root / "calibration-revisions.jsonl"
    with open(rev_path, "wb") as f:
        for rev in revisions.values():
            f.write(canonical_bytes(rev) + b"\n")
        _fsync_file(f)

    cross_extents: list[dict[str, Any]] = []
    total_written = 0

    for p in range(PARTITION_COUNT):
        pname = f"{p:02d}"
        pdir = part_root / f"partition={pname}"
        pdir.mkdir(parents=True, exist_ok=True)
        data_path = pdir / "records.jsonl"

        lo_i = p * PER_PARTITION
        hi_i = lo_i + PER_PARTITION
        cross_indices = [i for i in range(lo_i, hi_i) if i % 100 == 7]
        normal_indices = [i for i in range(lo_i, hi_i) if i % 100 != 7]

        with open(data_path, "wb") as f:
            start = f.tell()
            cross_hasher = hashlib.sha256()
            for line_no, i in enumerate(cross_indices, 1):
                rec = {
                    "v": 1,
                    "kind": "partition_observation",
                    "record_id": f"SCALE-{i:06d}",
                    "global_index": i,
                    "partition": pname,
                    "terminal_id": f"SYNTH-T-{i % 600:04d}",
                    "calib_rev": CROSS_REVISION,
                    "local_t": 10_000 + (i % 5_000),
                    "seq_in_partition": line_no,
                    "byte_class": "cross-revision-block",
                }
                line = canonical_bytes(rec) + b"\n"
                f.write(line)
                cross_hasher.update(line)
            cross_end = f.tell()
            _fsync_file(f)

            cross_extents.append({
                "calib_rev": CROSS_REVISION,
                "partition": pname,
                "path": data_path.relative_to(root).as_posix(),
                "start_offset": start,
                "end_offset": cross_end,
                "count": len(cross_indices),
                "raw_sha256": cross_hasher.hexdigest(),
            })

            for line_no, i in enumerate(normal_indices, len(cross_indices) + 1):
                rec = {
                    "v": 1,
                    "kind": "partition_observation",
                    "record_id": f"SCALE-{i:06d}",
                    "global_index": i,
                    "partition": pname,
                    "terminal_id": f"SYNTH-T-{i % 600:04d}",
                    "calib_rev": f"CAL-P-{p:02d}",
                    "local_t": 10_000 + (i % 5_000),
                    "seq_in_partition": line_no,
                    "byte_class": "partition-revision-block",
                }
                f.write(canonical_bytes(rec) + b"\n")
            _fsync_file(f)

        total_written += PER_PARTITION

    index = {
        "total_records": total_written,
        "partition_count": PARTITION_COUNT,
        "records_per_partition": PER_PARTITION,
        "cross_revision": CROSS_REVISION,
        "extents": {CROSS_REVISION: cross_extents},
    }
    write_json_atomic(root / "segment-index.json", index)
    return index


def _read_range(path: Path, start: int, end: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(end - start)


def verify_scale_case(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    index = json.loads((root / "segment-index.json").read_text(encoding="utf-8"))
    chosen_rev = index["cross_revision"]
    extents = index["extents"][chosen_rev]

    revisions: dict[str, dict[str, Any]] = {}
    with open(root / "calibration-revisions.jsonl", "rb") as f:
        for raw in f:
            obj = json.loads(raw.decode("utf-8"))
            revisions[obj["calib_rev"]] = obj

    # Full scan: the authoritative count and per-record comparison universe.
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
                    raise AssertionError(f"duplicate scale record id {rid}")
                full_records[rid] = obj

    expected_cross = [r for r in full_records.values() if r["calib_rev"] == chosen_rev]

    raw_compared = 0
    raw_extent_summaries = []
    seen_ids: set[str] = set()
    for extent in extents:
        path = root / extent["path"]
        st_size = path.stat().st_size
        if extent["end_offset"] > st_size:
            raise AssertionError(f"extent beyond EOF: {extent}")
        blob = _read_range(path, extent["start_offset"], extent["end_offset"])
        actual_hash = sha256_hex(blob)
        if actual_hash != extent["raw_sha256"]:
            raise AssertionError(f"raw extent hash mismatch at {extent['path']}")
        lines = [line for line in blob.splitlines() if line.strip()]
        if len(lines) != extent["count"]:
            raise AssertionError(
                f"raw count mismatch {extent['path']}: "
                f"read {len(lines)}, index says {extent['count']}"
            )
        for raw_line in lines:
            obj = json.loads(raw_line.decode("utf-8"))
            rid = obj["record_id"]
            if rid in seen_ids:
                raise AssertionError(f"cross revision record repeated in extents: {rid}")
            seen_ids.add(rid)
            full_obj = full_records.get(rid)
            if full_obj is None:
                raise AssertionError(f"raw record absent from full scan: {rid}")
            if canonical_bytes(obj) != canonical_bytes(full_obj):
                raise AssertionError(f"raw/full byte-object mismatch for {rid}")
            rev = revisions[obj["calib_rev"]]
            lo = obj["local_t"] + rev["offset_lo"]
            hi = obj["local_t"] + rev["offset_hi"]
            if not (lo <= hi):
                raise AssertionError(f"bad calibrated interval for {rid}")
            raw_compared += 1
        raw_extent_summaries.append({
            "partition": extent["partition"],
            "path": extent["path"],
            "raw_bytes": extent["end_offset"] - extent["start_offset"],
            "records_read": len(lines),
            "sha256": actual_hash,
        })

    if raw_compared != len(expected_cross):
        raise AssertionError(
            f"cross count mismatch: raw extents {raw_compared}, full scan {len(expected_cross)}"
        )
    if seen_ids != {r["record_id"] for r in expected_cross}:
        raise AssertionError("raw extent id set differs from full-scan cross revision set")
    if full_count != index["total_records"] or full_count != TOTAL_RECORDS:
        raise AssertionError(f"full count {full_count} != expected {TOTAL_RECORDS}")

    # Pick one concrete cross-partition revision record for the report.
    sample = min(expected_cross, key=lambda r: r["global_index"])
    sample_rev = revisions[chosen_rev]
    return {
        "ok": True,
        "total_partition_records_full_scan": full_count,
        "partition_files_read": len(partition_files),
        "chosen_cross_partition_revision": chosen_rev,
        "revision_scope": sample_rev["scope"],
        "raw_extents_read": len(extents),
        "cross_revision_records_in_full_scan": len(expected_cross),
        "raw_records_read_and_compared_one_by_one": raw_compared,
        "mismatches": 0,
        "sample_record_id": sample["record_id"],
        "sample_partition": sample["partition"],
        "sample_calibrated_interval": [
            sample["local_t"] + sample_rev["offset_lo"],
            sample["local_t"] + sample_rev["offset_hi"],
        ],
        "extent_summaries": raw_extent_summaries,
    }
