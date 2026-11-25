from __future__ import annotations

import itertools
from dataclasses import replace
from typing import Any

from .engine import LoadedLog, SourceRow, order_pair, reconstruct_tables


def _row(rid: str, terminal: str, interval: tuple[int, int],
         receipt_seq: int | None, raw_sha: str, kind: str) -> SourceRow:
    return SourceRow(
        source="A" if rid.startswith("ALT") else "B",
        seq=1,
        raw_sha256=raw_sha,
        lineno=1,
        obj={
            "kind": kind,
            "record_id": rid,
            "terminal_id": terminal,
            "interval": list(interval),
            "receipt_seq": receipt_seq,
            "withdraws_alert_id": "ALT-X" if kind == "withdrawal" else None,
        },
    )


def brute_force_order_cases() -> dict[str, Any]:
    """Exhaust a small interval universe and withdrawal/arrival permutations.

    Intervals use endpoints 0..3.  Every legal pair ``lo<=hi`` is enumerated
    (10 x 10 = 100), including touching, containment and equality.  For each
    pair we try both arrival orders, both shared-credential orders and receipt
    loss/presence.  Disk row order is also permuted to prove append order does
    not leak into the conclusion.
    """
    intervals = [(lo, hi) for lo in range(4) for hi in range(lo, 4)]
    checked = 0
    failures: list[dict[str, Any]] = []
    arrival_orders = list(itertools.permutations(("alert", "withdrawal")))
    credential_orders = list(itertools.permutations(("alert", "withdrawal")))

    for ia in intervals:
        for iw in intervals:
            disjoint_alert_first = ia[1] < iw[0]
            disjoint_withdrawal_first = iw[1] < ia[0]

            for arrival in arrival_orders:
                for credential_order in credential_orders:
                    for receipts_present in (True, False):
                        checked += 1
                        h_alert = "a" * 64
                        h_wd = "b" * 64
                        if credential_order == ("alert", "withdrawal"):
                            ar_seq, wr_seq = 11, 12
                            receipts = {
                                11: {"attested_sha256": h_alert},
                                12: {"attested_sha256": h_wd},
                            }
                        else:
                            ar_seq, wr_seq = 12, 11
                            receipts = {
                                11: {"attested_sha256": h_wd},
                                12: {"attested_sha256": h_alert},
                            }
                        if not receipts_present:
                            receipts = {}

                        alert = _row("ALT-X", "T-X", ia, ar_seq, h_alert, "alert")
                        wd = _row("WD-X", "T-X", iw, wr_seq, h_wd, "withdrawal")
                        rows = [alert, wd] if arrival == ("alert", "withdrawal") else [wd, alert]
                        loaded = LoadedLog(rows=rows, receipts=receipts)
                        verdict = order_pair(alert, wd, loaded)

                        if disjoint_alert_first:
                            expected = -1
                            expected_method = "disjoint-calibrated-interval"
                        elif disjoint_withdrawal_first:
                            expected = 1
                            expected_method = "disjoint-calibrated-interval"
                        elif receipts_present:
                            expected = -1 if credential_order == ("alert", "withdrawal") else 1
                            expected_method = "shared-receipt-order"
                        else:
                            expected = None
                            expected_method = "overlap-without-verified-shared-receipt"

                        if verdict["order"] != expected or verdict["method"] != expected_method:
                            failures.append({
                                "ia": ia, "iw": iw,
                                "arrival": arrival,
                                "credential_order": credential_order,
                                "receipts_present": receipts_present,
                                "expected": [expected, expected_method],
                                "actual": [verdict["order"], verdict["method"]],
                            })
                            if len(failures) >= 10:
                                return {"checked": checked, "failures": failures, "ok": False}

                        # Row permutation must produce exactly the same tables.
                        loaded_rev = replace(loaded, rows=list(reversed(rows)))
                        t1 = reconstruct_tables(loaded)
                        t2 = reconstruct_tables(loaded_rev)
                        key1 = [(r["terminal_id"], r["earliest_proven_isolation_at"])
                                for r in t1["isolation_table"]]
                        key2 = [(r["terminal_id"], r["earliest_proven_isolation_at"])
                                for r in t2["isolation_table"]]
                        if key1 != key2:
                            failures.append({"table_order_dependency": key1, "key2": key2})
                            return {"checked": checked, "failures": failures, "ok": False}

    return {
        "ok": not failures,
        "checked": checked,
        "interval_pairs": len(intervals) ** 2,
        "arrival_permutations": len(arrival_orders),
        "credential_permutations": len(credential_orders),
        "receipt_loss_variants": 2,
        "failures": failures,
    }
