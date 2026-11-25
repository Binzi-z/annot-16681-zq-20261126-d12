from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import iter_jsonl_objects, sha256_hex


@dataclass
class SourceRow:
    source: str
    seq: int
    raw_sha256: str
    lineno: int
    obj: dict[str, Any]
    parse_error: str | None = None


@dataclass
class LoadedLog:
    rows: list[SourceRow] = field(default_factory=list)
    receipts: dict[int, dict[str, Any]] = field(default_factory=dict)
    receipt_raw_hashes: dict[int, str] = field(default_factory=dict)
    receipt_errors: list[dict[str, Any]] = field(default_factory=list)
    calibrations: dict[str, dict[str, Any]] = field(default_factory=dict)


def load_disk_log(root: str | Path) -> LoadedLog:
    root = Path(root)
    loaded = LoadedLog()

    for source in ("A", "B"):
        path = root / "sources" / f"source-{source}.jsonl"
        for lineno, raw, obj, err in iter_jsonl_objects(path):
            if err or not isinstance(obj, dict):
                loaded.rows.append(SourceRow(source, -1, sha256_hex(raw), lineno,
                                             {"_raw": raw.decode("utf-8", "replace")}, err))
                continue
            seq = int(obj.get("seq", -1))
            row_source = str(obj.get("source", source))
            loaded.rows.append(SourceRow(row_source, seq, sha256_hex(raw), lineno, obj))
            if obj.get("kind") == "calibration":
                rev = obj.get("calib_rev")
                if rev:
                    loaded.calibrations[str(rev)] = obj

    receipt_path = root / "receipts" / "shared-receipts.jsonl"
    for lineno, raw, obj, err in iter_jsonl_objects(receipt_path):
        if err or not isinstance(obj, dict):
            loaded.receipt_errors.append({"lineno": lineno, "error": err,
                                          "raw_sha256": sha256_hex(raw)})
            continue
        seq = int(obj["receipt_seq"])
        loaded.receipts[seq] = obj
        loaded.receipt_raw_hashes[seq] = sha256_hex(raw)

    for path in [root / "calibrations.jsonl", root / "scale" / "calibration-revisions.jsonl"]:
        for _lineno, _raw, obj, err in iter_jsonl_objects(path):
            if not err and isinstance(obj, dict) and obj.get("calib_rev"):
                loaded.calibrations[str(obj["calib_rev"])] = obj
    return loaded


def interval_for(row_or_obj: dict[str, Any], calibrations: dict[str, dict[str, Any]]) -> tuple[int, int]:
    obj = row_or_obj
    if "interval" in obj and isinstance(obj["interval"], list):
        return int(obj["interval"][0]), int(obj["interval"][1])
    rev = str(obj["calib_rev"])
    calib = calibrations[rev]
    local_t = int(obj["local_t"])
    return local_t + int(calib["offset_lo"]), local_t + int(calib["offset_hi"])


def receipt_attests(row_hash: str, receipt_seq: Any, loaded: LoadedLog) -> bool:
    if not isinstance(receipt_seq, int):
        return False
    receipt = loaded.receipts.get(receipt_seq)
    return bool(receipt and receipt.get("attested_sha256") == row_hash)


def order_pair(a: SourceRow, b: SourceRow, loaded: LoadedLog) -> dict[str, Any]:
    """Return definite order using intervals, then shared receipt credentials."""
    ia = interval_for(a.obj, loaded.calibrations)
    ib = interval_for(b.obj, loaded.calibrations)
    if ia[1] < ib[0]:
        return {"order": -1, "method": "disjoint-calibrated-interval", "ia": ia, "ib": ib}
    if ib[1] < ia[0]:
        return {"order": 1, "method": "disjoint-calibrated-interval", "ia": ia, "ib": ib}

    ra = a.obj.get("receipt_seq")
    rb = b.obj.get("receipt_seq")
    ra_ok = receipt_attests(a.raw_sha256, ra, loaded)
    rb_ok = receipt_attests(b.raw_sha256, rb, loaded)
    if ra_ok and rb_ok and isinstance(ra, int) and isinstance(rb, int) and ra != rb:
        return {
            "order": -1 if ra < rb else 1,
            "method": "shared-receipt-order",
            "receipt_seqs": [ra, rb],
            "ia": ia,
            "ib": ib,
        }
    return {
        "order": None,
        "method": "overlap-without-verified-shared-receipt",
        "ia": ia,
        "ib": ib,
        "receipt_ok": [ra_ok, rb_ok],
        "receipt_seqs": [ra, rb],
    }


def _groups(loaded: LoadedLog):
    by_id: dict[str, list[SourceRow]] = {}
    by_seq: dict[tuple[str, int], list[SourceRow]] = {}
    for row in loaded.rows:
        if row.parse_error:
            continue
        key = (row.source, row.seq)
        by_seq.setdefault(key, []).append(row)
        rid = row.obj.get("record_id") or row.obj.get("alert_id")
        if rid:
            by_id.setdefault(str(rid), []).append(row)
    return by_id, by_seq


def reconstruct_tables(loaded: LoadedLog) -> dict[str, Any]:
    by_id, by_seq = _groups(loaded)

    duplicate_groups: list[dict[str, Any]] = []
    tainted_hashes: set[str] = set()
    for (source, seq), rows in sorted(by_seq.items(), key=lambda x: (x[0][0], x[0][1])):
        distinct = {r.raw_sha256 for r in rows}
        if seq >= 0 and len(distinct) > 1:
            terminals = sorted({str(r.obj.get("terminal_id")) for r in rows
                                if r.obj.get("terminal_id")})
            intervals = []
            for r in rows:
                try:
                    intervals.append(interval_for(r.obj, loaded.calibrations))
                except Exception:
                    pass
            group = {
                "kind": "same-sequence-different-bytes",
                "source": source,
                "seq": seq,
                "raw_sha256": sorted(distinct),
                "line_numbers": [r.lineno for r in rows],
                "terminal_ids": terminals,
                "intervals": intervals,
            }
            if intervals:
                group["gap_confirmed_at"] = min(hi for _lo, hi in intervals)
                group["uncertain_span"] = [
                    min(lo for lo, _hi in intervals),
                    max(hi for _lo, hi in intervals),
                ]
            duplicate_groups.append(group)
            tainted_hashes.update(r.raw_sha256 for r in rows)

    withdrawals: list[tuple[SourceRow, str]] = []
    contested: list[dict[str, Any]] = []
    withdrawn_alert_hashes: set[str] = set()
    orphan_withdrawals: list[SourceRow] = []

    for row in loaded.rows:
        if row.parse_error or row.obj.get("kind") != "withdrawal":
            continue
        alert_id = str(row.obj.get("withdraws_alert_id") or row.obj.get("alert_id"))
        matches = [r for r in by_id.get(alert_id, [])
                   if r.obj.get("kind") in {"alert", "isolation_alert"}]
        if not matches:
            orphan_withdrawals.append(row)
            continue
        for alert in matches:
            verdict = order_pair(alert, row, loaded)
            if verdict["order"] == -1:
                withdrawn_alert_hashes.add(alert.raw_sha256)
                withdrawals.append((row, alert_id))
            elif verdict["order"] == 1:
                # A receipt may prove the withdrawal credential was issued first.
                # The pre-registered ID still makes it a valid future retraction
                # once the delayed alert is written.
                withdrawn_alert_hashes.add(alert.raw_sha256)
                withdrawals.append((row, alert_id))
            else:
                contested.append({
                    "kind": "unorderable-alert-withdrawal",
                    "alert": alert,
                    "withdrawal": row,
                    "verdict": verdict,
                    "terminal_id": alert.obj.get("terminal_id"),
                    "gap_confirmed_at": min(verdict["ia"][1], verdict["ib"][1]),
                    "overlap": [max(verdict["ia"][0], verdict["ib"][0]),
                                min(verdict["ia"][1], verdict["ib"][1])],
                })

    terminals: set[str] = set()
    alerts: list[SourceRow] = []
    for row in loaded.rows:
        tid = row.obj.get("terminal_id")
        if tid:
            terminals.add(str(tid))
        if row.parse_error:
            continue
        if row.obj.get("kind") in {"alert", "isolation_alert"}:
            alerts.append(row)

    for g in duplicate_groups:
        terminals.update(g["terminal_ids"])
    for c in contested:
        if c.get("terminal_id"):
            terminals.add(str(c["terminal_id"]))

    isolation_rows: list[dict[str, Any]] = []
    gap_rows: list[dict[str, Any]] = []

    for tid in sorted(terminals):
        eligible: list[dict[str, Any]] = []
        for alert in alerts:
            if str(alert.obj.get("terminal_id")) != tid:
                continue
            reasons = []
            if alert.raw_sha256 in tainted_hashes:
                reasons.append("same-sequence-different-bytes")
            if alert.raw_sha256 in withdrawn_alert_hashes:
                reasons.append("withdrawn-by-verified-receipt-chain")
            contested_here = [c for c in contested if c["alert"].raw_sha256 == alert.raw_sha256]
            if contested_here:
                reasons.append("alert-withdrawal-order-unresolved")
            interval = interval_for(alert.obj, loaded.calibrations)
            if not reasons:
                eligible.append({
                    "alert": alert,
                    "interval": interval,
                    "provable_at": interval[1],
                })

        gap_candidates: list[dict[str, Any]] = []
        for group in duplicate_groups:
            if tid in group["terminal_ids"]:
                gap_candidates.append({
                    "gap_confirmed_at": group.get("gap_confirmed_at"),
                    "kind": group["kind"],
                    "ref": f"{group['source']}#{group['seq']}",
                    "uncertain_span": group.get("uncertain_span"),
                    "basis": "two distinct byte strings share one source sequence",
                })
        for c in contested:
            if str(c.get("terminal_id")) == tid:
                gap_candidates.append({
                    "gap_confirmed_at": c["gap_confirmed_at"],
                    "kind": c["kind"],
                    "ref": f"{c['alert'].obj.get('record_id')}/{c['withdrawal'].obj.get('record_id')}",
                    "overlap": c["overlap"],
                    "basis": "calibrated intervals overlap and shared receipt order is unavailable",
                })

        gap_candidates = [g for g in gap_candidates if g["gap_confirmed_at"] is not None]
        first_gap = min(gap_candidates, key=lambda g: g["gap_confirmed_at"], default=None)
        first_proof = min(eligible, key=lambda e: e["provable_at"], default=None)

        status_parts = []
        if first_proof:
            status_parts.append("isolation-provable")
        if first_gap:
            status_parts.append("gap-confirmed")
        if not status_parts:
            status_parts.append("no-usable-evidence")

        isolation_rows.append({
            "terminal_id": tid,
            "earliest_proven_isolation_at": first_proof["provable_at"] if first_proof else None,
            "earliest_possible_isolation_at": first_proof["interval"][0] if first_proof else None,
            "proof_id": first_proof["alert"].obj.get("record_id") if first_proof else None,
            "proof_source_seq": (
                f"{first_proof['alert'].source}#{first_proof['alert'].seq}"
                if first_proof else None
            ),
            "proof_method": "conservative upper endpoint of calibrated interval",
            "other_eligible_alert_count": max(0, len(eligible) - 1),
            "status": "+".join(status_parts),
        })
        gap_rows.append({
            "terminal_id": tid,
            "earliest_gap_confirmed_at": first_gap["gap_confirmed_at"] if first_gap else None,
            "gap_kind": first_gap["kind"] if first_gap else None,
            "gap_ref": first_gap["ref"] if first_gap else None,
            "uncertain_span": first_gap.get("uncertain_span") if first_gap else None,
            "overlap": first_gap.get("overlap") if first_gap else None,
            "basis": first_gap["basis"] if first_gap else None,
            "candidate_count": len(gap_candidates),
        })

    return {
        "isolation_table": isolation_rows,
        "gap_table": gap_rows,
        "duplicate_groups": duplicate_groups,
        "contested_count": len(contested),
        "orphan_withdrawal_count": len(orphan_withdrawals),
        "receipt_error_count": len(loaded.receipt_errors),
    }


def digest_tables(tables: dict[str, Any]) -> dict[str, str]:
    """Stable digests used to prove historical watermarks replay identically."""
    from .canonical import object_hash

    conclusion_tuples = sorted(
        (
            row["terminal_id"],
            row["earliest_proven_isolation_at"],
            next(
                (g["earliest_gap_confirmed_at"] for g in tables["gap_table"]
                 if g["terminal_id"] == row["terminal_id"]),
                None,
            ),
        )
        for row in tables["isolation_table"]
    )
    slim_gap = [{k: v for k, v in row.items() if k != "basis"}
                for row in tables["gap_table"]]
    return {
        "conclusion_digest": object_hash(conclusion_tuples),
        "isolation_digest": object_hash(tables["isolation_table"]),
        "gap_digest": object_hash(slim_gap),
    }
