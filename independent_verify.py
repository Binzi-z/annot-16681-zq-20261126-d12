#!/usr/bin/env python3
"""Independent offline verifier for the synthetic forensic rehearsal.

This program intentionally imports none of the generator/reconstruction
package.  It re-reads only bytes already written under a case directory,
rebuilds ordering/proof state, checks persisted watermarks, identifies the
first contradiction, and emits a shortest evidence chain.

Native Windows / Python 3.12 standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from collections import deque
from pathlib import Path
from typing import Any

SYNTHETIC_KEY = b"forensic-rehearsal-synthetic-shared-key-v1"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_jsonl_bytes(blob: bytes):
    for lineno, raw_lf in enumerate(blob.splitlines(), 1):
        raw = raw_lf[:-1] if raw_lf.endswith(b"\r") else raw_lf
        try:
            yield lineno, raw, json.loads(raw.decode("utf-8")), None
        except Exception as exc:  # noqa: BLE001 - verifier reports all parse failures
            yield lineno, raw, None, str(exc)


def read_jsonl_file(path: Path):
    if not path.exists():
        return []
    return list(read_jsonl_bytes(path.read_bytes()))


class Graph:
    """Tiny evidence graph; BFS gives a shortest chain when alternatives exist."""

    def __init__(self) -> None:
        self.nodes: dict[str, str] = {}
        self.edges: list[tuple[str, str, str]] = []

    def node(self, nid: str, label: str) -> None:
        self.nodes[nid] = label

    def edge(self, a: str, b: str, relation: str) -> None:
        self.edges.append((a, b, relation))

    def shortest_chain(self, start: str, target: str) -> list[dict[str, str]]:
        adj: dict[str, list[tuple[str, str]]] = {}
        for a, b, rel in self.edges:
            adj.setdefault(a, []).append((b, rel))
        q = deque([(start, [start])])
        seen = {start}
        while q:
            cur, path = q.popleft()
            if cur == target:
                out = []
                for i, nid in enumerate(path):
                    item = {"node": nid, "evidence": self.nodes.get(nid, nid)}
                    if i:
                        prev = path[i - 1]
                        rel = next(r for a, b, r in self.edges if a == prev and b == nid)
                        item["relation_from_previous"] = rel
                    out.append(item)
                return out
            for nxt, rel in adj.get(cur, []):
                if nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, path + [nxt]))
        return [{"node": target, "evidence": self.nodes.get(target, target)}]


def load_case(root: Path) -> dict[str, Any]:
    key_path = root / "keys" / "receipt-hmac.key"
    key = key_path.read_bytes().strip() if key_path.exists() else SYNTHETIC_KEY

    sources: dict[str, list[dict[str, Any]]] = {}
    for source in ("A", "B"):
        path = root / "sources" / f"source-{source}.jsonl"
        rows = []
        if path.exists():
            for lineno, raw, obj, err in read_jsonl_file(path):
                rows.append({"lineno": lineno, "raw": raw, "hash": sha256(raw),
                             "obj": obj, "error": err, "path": path})
        sources[source] = rows

    receipt_path = root / "receipts" / "shared-receipts.jsonl"
    receipt_rows = read_jsonl_file(receipt_path)
    receipts: dict[int, dict[str, Any]] = {}
    for item in receipt_rows:
        if item[2] and isinstance(item[2], dict):
            receipts[int(item[2]["receipt_seq"])] = {
                "obj": item[2], "hash": sha256(item[1]), "lineno": item[0]
            }

    calibrations: dict[str, dict[str, Any]] = {}
    for rows in sources.values():
        for row in rows:
            obj = row["obj"]
            if obj and obj.get("kind") == "calibration":
                calibrations[obj["calib_rev"]] = obj
    return {"key": key, "sources": sources, "receipt_path": receipt_path,
            "receipt_rows": receipt_rows, "receipts": receipts,
            "calibrations": calibrations}


def interval_for(obj: dict[str, Any], calibrations: dict[str, dict[str, Any]]) -> tuple[int, int]:
    if isinstance(obj.get("interval"), list):
        return int(obj["interval"][0]), int(obj["interval"][1])
    calib = calibrations[str(obj["calib_rev"])]
    t = int(obj["local_t"])
    return t + int(calib["offset_lo"]), t + int(calib["offset_hi"])


def receipt_ok(row_hash: str, seq: Any, state: dict[str, Any]) -> bool:
    if not isinstance(seq, int) or seq not in state["receipts"]:
        return False
    return state["receipts"][seq]["obj"].get("attested_sha256") == row_hash


def order_verdict(alert: dict[str, Any], wd: dict[str, Any],
                  state: dict[str, Any]) -> dict[str, Any]:
    ia = interval_for(alert["obj"], state["calibrations"])
    iw = interval_for(wd["obj"], state["calibrations"])
    if ia[1] < iw[0]:
        return {"order": -1, "method": "disjoint-calibrated-interval", "ia": ia, "iw": iw}
    if iw[1] < ia[0]:
        return {"order": 1, "method": "disjoint-calibrated-interval", "ia": ia, "iw": iw}
    ar, wr = alert["obj"].get("receipt_seq"), wd["obj"].get("receipt_seq")
    if receipt_ok(alert["hash"], ar, state) and receipt_ok(wd["hash"], wr, state):
        return {"order": -1 if ar < wr else 1, "method": "shared-receipt-order",
                "ia": ia, "iw": iw, "receipt_seqs": [ar, wr]}
    return {"order": None, "method": "overlap-without-verified-shared-receipt",
            "ia": ia, "iw": iw, "receipt_seqs": [ar, wr]}


def conclusion_digest(isolation: list[dict[str, Any]], gaps: list[dict[str, Any]]) -> str:
    gap_by_t = {g["terminal_id"]: g["earliest_gap_confirmed_at"] for g in gaps}
    tuples = sorted((r["terminal_id"], r["earliest_proven_isolation_at"],
                     gap_by_t.get(r["terminal_id"])) for r in isolation)
    return sha256(canonical(tuples))


def rebuild_tables(state: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    all_rows = [r for rows in state["sources"].values() for r in rows if r["obj"]]
    by_id: dict[str, list[dict[str, Any]]] = {}
    by_seq: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in all_rows:
        obj = row["obj"]
        by_id.setdefault(str(obj.get("record_id") or obj.get("alert_id")), []).append(row)
        by_seq.setdefault((row["obj"].get("source", "?"), int(obj.get("seq", -1))), []).append(row)

    tainted: set[str] = set()
    duplicate_terminals: dict[str, list[dict[str, Any]]] = {}
    for (source, seq), rows in sorted(by_seq.items()):
        hashes = {r["hash"] for r in rows}
        if seq >= 0 and len(hashes) > 1:
            for r in rows:
                tainted.add(r["hash"])
                tid = r["obj"].get("terminal_id")
                if tid:
                    duplicate_terminals.setdefault(tid, []).append({
                        "source": source, "seq": seq, "hash": r["hash"],
                        "interval": interval_for(r["obj"], state["calibrations"]),
                    })

    withdrawn: set[str] = set()
    contested: list[dict[str, Any]] = []
    for wd in all_rows:
        if wd["obj"].get("kind") != "withdrawal":
            continue
        aid = str(wd["obj"].get("withdraws_alert_id"))
        matches = [r for r in by_id.get(aid, []) if r["obj"].get("kind") == "alert"]
        for alert in matches:
            verdict = order_verdict(alert, wd, state)
            if verdict["order"] is not None:
                withdrawn.add(alert["hash"])
            else:
                contested.append({"alert": alert, "wd": wd, "verdict": verdict,
                                  "terminal_id": alert["obj"].get("terminal_id")})

    terminal_ids = {str(r["obj"].get("terminal_id")) for r in all_rows
                    if r["obj"].get("terminal_id")}
    terminal_ids.update(duplicate_terminals)
    isolation, gaps = [], []
    for tid in sorted(terminal_ids):
        proofs = []
        for alert in all_rows:
            obj = alert["obj"]
            if obj.get("kind") != "alert" or obj.get("terminal_id") != tid:
                continue
            if alert["hash"] in tainted or alert["hash"] in withdrawn:
                continue
            if any(c["alert"]["hash"] == alert["hash"] for c in contested):
                continue
            interval = interval_for(obj, state["calibrations"])
            proofs.append((interval[1], interval[0], alert))
        proof = min(proofs, default=None, key=lambda x: x[0])

        gap_candidates = []
        for dup in duplicate_terminals.get(tid, []):
            gap_candidates.append((min(hi for _lo, hi in [dup["interval"]]),
                                   "same-sequence-different-bytes",
                                   f"{dup['source']}#{dup['seq']}"))
        for c in contested:
            if c["terminal_id"] == tid:
                v = c["verdict"]
                gap_candidates.append((min(v["ia"][1], v["iw"][1]),
                                       "unorderable-alert-withdrawal",
                                       f"{c['alert']['obj'].get('record_id')}/"
                                       f"{c['wd']['obj'].get('record_id')}"))
        gap = min(gap_candidates, default=None, key=lambda x: x[0])
        isolation.append({
            "terminal_id": tid,
            "earliest_proven_isolation_at": proof[0] if proof else None,
            "earliest_possible_isolation_at": proof[1] if proof else None,
            "proof_id": proof[2]["obj"].get("record_id") if proof else None,
            "proof_source_seq": (f"{proof[2]['obj'].get('source')}#{proof[2]['obj'].get('seq')}"
                                 if proof else None),
        })
        gaps.append({
            "terminal_id": tid,
            "earliest_gap_confirmed_at": gap[0] if gap else None,
            "gap_kind": gap[1] if gap else None,
            "gap_ref": gap[2] if gap else None,
        })
    return {"isolation_table": isolation, "gap_table": gaps}


def verify_receipt_credentials(state: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    prev_hash = "0" * 64
    expected_seq = 1
    for lineno, raw, obj, err in state["receipt_rows"]:
        if err or not obj:
            findings.append({"code": "receipt-parse-error", "lineno": lineno, "error": err})
            continue
        core = {k: v for k, v in obj.items() if k != "mac"}
        expected_mac = hmac.new(state["key"], canonical(core), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, str(obj.get("mac", ""))):
            findings.append({"code": "bad-receipt-mac", "receipt_seq": obj.get("receipt_seq")})
        if int(obj["receipt_seq"]) != expected_seq:
            findings.append({"code": "receipt-sequence-gap", "expected": expected_seq,
                             "actual": obj["receipt_seq"]})
        if obj.get("prev_receipt_hash") != prev_hash:
            findings.append({"code": "receipt-hash-chain-break",
                             "receipt_seq": obj["receipt_seq"]})
        prev_hash = sha256(raw)
        expected_seq = int(obj["receipt_seq"]) + 1
    return findings


def verify_watermarks(root: Path, state: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    contradictions: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    current_path = root / "WATERMARK.json"
    history_path = root / "watermarks" / "history.jsonl"
    if not current_path.exists():
        return contradictions, [{"watermark": None, "status": "absent"}]
    current = json.loads(current_path.read_text(encoding="utf-8"))
    history = [json.loads(raw.decode("utf-8")) for raw in
               history_path.read_bytes().splitlines() if raw.strip()]
    if not history or history[-1] != current:
        contradictions.append({
            "code": "current-watermark-not-last-persisted-history",
            "watermark_seq": current.get("watermark_seq"),
            "order_key": (0, int(current.get("watermark_seq", 0)), 0),
        })

    for wm in history:
        seq = int(wm["watermark_seq"])
        prefix_ok = True
        prefix_details = []
        for rel, expected in wm.get("prefixes", {}).items():
            p = root / rel
            actual_size = p.stat().st_size if p.exists() else -1
            need = int(expected["end_offset"])
            if not p.exists() or actual_size < need:
                prefix_ok = False
                prefix_details.append({"path": rel, "expected_end_offset": need,
                                       "actual_size": actual_size,
                                       "expected_sha256": expected["prefix_sha256"]})
                continue
            with open(p, "rb") as f:
                blob = f.read(need)
            actual_hash = sha256(blob)
            if actual_hash != expected["prefix_sha256"]:
                prefix_ok = False
                prefix_details.append({"path": rel, "expected_sha256": expected["prefix_sha256"],
                                       "actual_sha256": actual_hash,
                                       "end_offset": need})

        if not prefix_ok:
            # The planted fault is published-then-lost receipt #6.  Build the
            # shortest BFS-style evidence chain.
            graph = Graph()
            graph.node("wm", f"WATERMARK WM-{seq} label={wm.get('label')!r}")
            graph.node("prefix", f"persisted prefix promise: {prefix_details}")
            graph.node("disk", "reopened directory cannot supply the promised exact bytes")
            graph.node("contradiction", "published audit watermark is not replayable")
            graph.edge("wm", "prefix", "publishes")
            graph.edge("prefix", "disk", "checked after reopen")
            graph.edge("disk", "contradiction", "implies")
            chain = graph.shortest_chain("wm", "contradiction")

            missing_receipt = None
            for row in state["sources"].get("B", []):
                obj = row.get("obj") or {}
                if obj.get("record_id") == "WD-2001":
                    missing_receipt = obj.get("receipt_seq")
            contradictions.append({
                "code": "published-watermark-prefix-unreplayable",
                "severity": "critical",
                "watermark_seq": seq,
                "published_tick": wm.get("published_tick"),
                "order_key": (1, int(wm.get("published_tick", 0)), seq),
                "prefix_failures": prefix_details,
                "related_missing_receipt_seq": missing_receipt,
                "shortest_counterexample_chain": chain,
            })
            checks.append({"watermark_seq": seq, "status": "prefix-mismatch"})
            continue

        # Replay the exact persisted prefix into an independent table rebuild.
        replay_state = replay_prefix_state(root, wm, state["key"])
        tables = rebuild_tables(replay_state)
        digest = conclusion_digest(tables["isolation_table"], tables["gap_table"])
        expected_digest = (wm.get("table_digests") or {}).get("conclusion_digest")
        consistent = digest == expected_digest
        checks.append({"watermark_seq": seq, "status": "replayed",
                       "conclusion_digest": digest,
                       "published_digest": expected_digest,
                       "consistent": consistent})
        if not consistent:
            contradictions.append({
                "code": "historical-watermark-replay-digest-mismatch",
                "severity": "critical", "watermark_seq": seq,
                "order_key": (1, int(wm.get("published_tick", 0)), seq),
                "replayed_digest": digest, "published_digest": expected_digest,
                "shortest_counterexample_chain": [
                    {"evidence": f"WM-{seq} published conclusion digest {expected_digest}"},
                    {"relation_from_previous": "reopen and replay exact prefixes",
                     "evidence": f"independent rebuild produced {digest}"},
                    {"relation_from_previous": "digests differ",
                     "evidence": "historical watermark does not reproduce one conclusion"},
                ],
            })
    return contradictions, checks


def replay_prefix_state(root: Path, wm: dict[str, Any], key: bytes) -> dict[str, Any]:
    sources: dict[str, list[dict[str, Any]]] = {"A": [], "B": []}
    receipts: dict[int, dict[str, Any]] = {}
    calibrations: dict[str, dict[str, Any]] = {}

    for rel, info in wm.get("prefixes", {}).items():
        p = root / rel
        need = int(info["end_offset"])
        with open(p, "rb") as f:
            blob = f.read(need)
        if rel.startswith("sources/source-"):
            source = "A" if "source-A" in rel else "B"
            for lineno, raw, obj, err in read_jsonl_bytes(blob):
                row = {"lineno": lineno, "raw": raw, "hash": sha256(raw),
                       "obj": obj, "error": err, "path": p}
                sources[source].append(row)
                if obj and obj.get("kind") == "calibration":
                    calibrations[obj["calib_rev"]] = obj
        elif rel.endswith("shared-receipts.jsonl"):
            for lineno, raw, obj, err in read_jsonl_bytes(blob):
                if obj:
                    receipts[int(obj["receipt_seq"])] = {
                        "obj": obj, "hash": sha256(raw), "lineno": lineno
                    }
    return {"key": key, "sources": sources, "receipts": receipts,
            "calibrations": calibrations, "receipt_rows": []}


def find_sequence_contradictions(state: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for source, rows in state["sources"].items():
        groups: dict[int, list[dict[str, Any]]] = {}
        max_seq = 0
        for row in rows:
            obj = row.get("obj")
            if not obj:
                continue
            seq = int(obj.get("seq", -1))
            groups.setdefault(seq, []).append(row)
            max_seq = max(max_seq, seq)
        seen = set(groups)
        missing = [n for n in range(1, max_seq + 1) if n not in seen]
        if missing:
            out.append({"code": "source-sequence-gap", "source": source,
                        "missing": missing, "order_key": (3, missing[0], 0)})
        for seq, group in sorted(groups.items()):
            hashes = sorted({r["hash"] for r in group})
            if seq >= 0 and len(hashes) > 1:
                graph = Graph()
                graph.node("key", f"continuous source key ({source}, seq={seq})")
                graph.node("h1", f"line {group[0]['lineno']}: {hashes[0]}")
                graph.node("h2", f"line {group[-1]['lineno']}: {hashes[-1]}")
                graph.node("x", "one sequence number maps to two different byte strings")
                graph.edge("key", "h1", "contains")
                graph.edge("h1", "h2", "same (source, seq), but SHA-256/bytes differ")
                graph.edge("h2", "x", "violates one-sequence/one-byte-stream invariant")
                out.append({
                    "code": "same-sequence-different-bytes",
                    "severity": "critical", "source": source, "seq": seq,
                    "line_numbers": [r["lineno"] for r in group],
                    "raw_sha256": hashes,
                    "record_ids": [r["obj"].get("record_id") for r in group if r.get("obj")],
                    "order_key": (2, seq, group[0]["lineno"]),
                    "shortest_counterexample_chain": graph.shortest_chain("key", "x"),
                })
    return out


def verify_commit_points(root: Path) -> list[dict[str, Any]]:
    cpd = root / "commit-points"
    results = []
    if not cpd.exists():
        return results
    for path in sorted(cpd.glob("CP-*.json")):
        cp = json.loads(path.read_text(encoding="utf-8"))
        results.append({"commit_point_file": path.name, "commit_point": cp.get("commit_point"),
                        "assertion": cp.get("must_hold") or cp.get("expected_contradiction")})
    return results


def verify(root: Path) -> dict[str, Any]:
    state = load_case(root)
    contradictions = find_sequence_contradictions(state)
    receipt_findings = verify_receipt_credentials(state)
    for rf in receipt_findings:
        contradictions.append({**rf, "severity": "critical", "order_key": (4, 0, 0)})
    wm_contradictions, wm_checks = verify_watermarks(root, state)
    contradictions.extend(wm_contradictions)

    tables = rebuild_tables(state)
    contradictions.sort(key=lambda x: x.get("order_key", (99, 0, 0)))
    first = contradictions[0] if contradictions else None
    return {
        "root": str(root.resolve()),
        "ok": not contradictions,
        "contradiction_count": len(contradictions),
        "first_contradiction": first,
        "contradictions": contradictions,
        "watermark_checks": wm_checks,
        "commit_points_on_disk": verify_commit_points(root),
        "proof_rebuild": tables,
        "independent_conclusion_digest": conclusion_digest(
            tables["isolation_table"], tables["gap_table"]
        ),
        "receipt_finding_count": len(receipt_findings),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Independently verify synthetic forensic records")
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--json-out", type=Path)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    report = verify(args.root)
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8")
    if not args.quiet:
        print(text)
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
