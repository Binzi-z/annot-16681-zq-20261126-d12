from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, prefix_sha256, sha256_hex, write_json_atomic

SYNTHETIC_RECEIPT_KEY = b"forensic-rehearsal-synthetic-shared-key-v1"


class DurableStore:
    """Append-only synthetic case store with explicit durable publish points."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.sources_dir = self.root / "sources"
        self.receipts_path = self.root / "receipts" / "shared-receipts.jsonl"
        self.wm_history_path = self.root / "watermarks" / "history.jsonl"
        self.wm_current_path = self.root / "WATERMARK.json"
        self.key_path = self.root / "keys" / "receipt-hmac.key"
        self.commit_dir = self.root / "commit-points"
        for p in (self.sources_dir, self.receipts_path.parent,
                  self.wm_history_path.parent, self.key_path.parent, self.commit_dir):
            p.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            self.key_path.write_bytes(SYNTHETIC_RECEIPT_KEY)
        self.key = self.key_path.read_bytes().strip()
        self._line_counts: dict[Path, int] = {}

    def source_path(self, source: str) -> Path:
        if source not in {"A", "B"}:
            raise ValueError(f"synthetic source must be A or B, got {source!r}")
        return self.sources_dir / f"source-{source}.jsonl"

    def _count_lines(self, path: Path) -> int:
        if path in self._line_counts:
            return self._line_counts[path]
        if not path.exists():
            self._line_counts[path] = 0
            return 0
        with open(path, "rb") as f:
            count = sum(1 for _ in f)
        self._line_counts[path] = count
        return count

    def append_jsonl(self, path: Path, obj: dict[str, Any]) -> dict[str, Any]:
        """Append one canonical JSON line and fsync it.

        Returns locator/hash facts for the exact bytes that became durable.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = canonical_bytes(obj)
        with open(path, "ab", buffering=0) as f:
            start = f.tell()
            written = f.write(raw + b"\n")
            if written != len(raw) + 1:
                raise OSError(f"short write on {path}")
            f.flush()
            os.fsync(f.fileno())
            end = f.tell()
        if path in self._line_counts:
            lines = self._line_counts[path] + 1
        else:
            # Cache miss: the append above is already durable on disk, so a
            # direct count yields the new total line number.
            lines = self._count_lines(path)
        self._line_counts[path] = lines
        return {
            "path": path,
            "rel": path.relative_to(self.root).as_posix(),
            "start_offset": start,
            "end_offset": end,
            "line_number": lines,
            "raw_sha256": sha256_hex(raw),
            "raw_bytes": len(raw),
        }

    def next_source_seq(self, source: str) -> int:
        path = self.source_path(source)
        max_seq = 0
        if path.exists():
            with open(path, "rb") as f:
                for raw_line in f:
                    try:
                        obj = json.loads(raw_line.decode("utf-8"))
                        max_seq = max(max_seq, int(obj.get("seq", 0)))
                    except Exception:
                        continue
        return max_seq + 1

    def append_source_record(self, source: str, seq: int, record: dict[str, Any]) -> dict[str, Any]:
        envelope = {"v": 1, "kind": "source_record", "source": source, "seq": seq, **record}
        loc = self.append_jsonl(self.source_path(source), envelope)
        return {**loc, "envelope": envelope}

    def append_receipt(self, receipt_seq: int, prev_receipt_hash: str,
                       attested_sha256: str, issued_tick: int) -> dict[str, Any]:
        core = {
            "v": 1,
            "kind": "shared_receipt",
            "receipt_seq": receipt_seq,
            "prev_receipt_hash": prev_receipt_hash,
            "attested_sha256": attested_sha256,
            "issued_tick": issued_tick,
            "credential": "HMAC-SHA256/shared-synthetic",
        }
        mac = hmac.new(self.key, canonical_bytes(core), "sha256").hexdigest()
        receipt = {**core, "mac": mac}
        loc = self.append_jsonl(self.receipts_path, receipt)
        return {**loc, "receipt": receipt, "receipt_hash": loc["raw_sha256"]}

    def last_receipt_hash_and_seq(self) -> tuple[int, str]:
        last_seq = 0
        last_hash = "0" * 64
        if self.receipts_path.exists():
            from .canonical import iter_jsonl_objects
            for _lineno, raw, obj, err in iter_jsonl_objects(self.receipts_path):
                if err is None and isinstance(obj, dict):
                    last_seq = int(obj["receipt_seq"])
                    last_hash = sha256_hex(raw)
        return last_seq, last_hash

    def prefix_info(self, rel_path: str, line_count: int, end_offset: int) -> dict[str, Any]:
        path = self.root / rel_path
        return {
            "lines": line_count,
            "end_offset": end_offset,
            "prefix_sha256": prefix_sha256(path, end_offset),
        }

    def current_offsets(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for source in ("A", "B"):
            path = self.source_path(source)
            if path.exists():
                st = path.stat()
                lines = self._count_lines(path)
                rel = path.relative_to(self.root).as_posix()
                result[rel] = {"lines": lines, "end_offset": st.st_size}
        if self.receipts_path.exists():
            rel = self.receipts_path.relative_to(self.root).as_posix()
            result[rel] = {
                "lines": self._count_lines(self.receipts_path),
                "end_offset": self.receipts_path.stat().st_size,
            }
        return result

    def publish_watermark(self, label: str, tick: int,
                          table_digests: dict[str, str] | None = None,
                          extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Publish a watermark only after its covered prefixes are fsynced."""
        prefixes: dict[str, Any] = {}
        cursors = {"A": 0, "B": 0}
        for source in ("A", "B"):
            path = self.source_path(source)
            rel = path.relative_to(self.root).as_posix()
            if path.exists():
                end = path.stat().st_size
                lines = self._count_lines(path)
                prefixes[rel] = self.prefix_info(rel, lines, end)
                seq = 0
                from .canonical import iter_jsonl_objects
                for _n, _raw, obj, err in iter_jsonl_objects(path):
                    if err is None and isinstance(obj, dict) and obj.get("source") == source:
                        seq = max(seq, int(obj.get("seq", 0)))
                cursors[source] = seq
            else:
                prefixes[rel] = {"lines": 0, "end_offset": 0,
                                 "prefix_sha256": sha256_hex(b"")}

        receipt_rel = self.receipts_path.relative_to(self.root).as_posix()
        receipt_seq, _prev = self.last_receipt_hash_and_seq()
        if self.receipts_path.exists():
            end = self.receipts_path.stat().st_size
            prefixes[receipt_rel] = self.prefix_info(
                receipt_rel, self._count_lines(self.receipts_path), end
            )
        else:
            prefixes[receipt_rel] = {"lines": 0, "end_offset": 0,
                                     "prefix_sha256": sha256_hex(b"")}

        wm_seq = 1
        if self.wm_history_path.exists():
            wm_seq = sum(1 for _ in open(self.wm_history_path, "rb")) + 1
        wm = {
            "v": 1,
            "kind": "audit_watermark",
            "watermark_seq": wm_seq,
            "label": label,
            "published_tick": tick,
            "source_cursors": cursors,
            "receipt_cursor": receipt_seq,
            "prefixes": prefixes,
            "table_digests": table_digests or {},
        }
        if extra:
            wm.update(extra)
        self.append_jsonl(self.wm_history_path, wm)
        write_json_atomic(self.wm_current_path, wm)
        return wm

    def write_commit_point(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.commit_dir / f"{name}.json"
        write_json_atomic(path, {"commit_point": name, **payload})
        return path
