from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable

from .canonical import object_hash
from .engine import digest_tables, load_disk_log, reconstruct_tables
from .store import DurableStore


def envelope(source: str, seq: int, **fields: Any) -> dict[str, Any]:
    return {"v": 1, "kind": "source_record", "source": source, "seq": seq, **fields}


def append_envelope(store: DurableStore, env: dict[str, Any]) -> dict[str, Any]:
    source = env["source"]
    return store.append_jsonl(store.source_path(source), env)


def publish_current_digest(store: DurableStore, label: str, tick: int) -> dict[str, Any]:
    loaded = load_disk_log(store.root)
    tables = reconstruct_tables(loaded)
    digests = digest_tables(tables)
    return store.publish_watermark(label=label, tick=tick, table_digests=digests)


def stage_00_calibrations(root: str | Path) -> dict[str, Any]:
    store = DurableStore(root)
    cal_a = envelope(
        "A", 1, kind="calibration", calib_rev="CAL-A-1",
        offset_lo=-3, offset_hi=3, source_clock_unit="synthetic-tick",
        audit_tick=1,
    )
    cal_b = envelope(
        "B", 1, kind="calibration", calib_rev="CAL-B-1",
        offset_lo=-2, offset_hi=4, source_clock_unit="synthetic-tick",
        audit_tick=2,
    )
    la = append_envelope(store, cal_a)
    lb = append_envelope(store, cal_b)
    cp = store.write_commit_point("CP-00-calibrations", {
        "audit_tick": 2,
        "must_hold": "both source sequence 1 calibration records are durable",
        "records": [la["rel"] + "#1", lb["rel"] + "#1"],
    })
    return {"stage": "calibrations", "commit_point": cp.name, "locators": [la, lb]}


def stage_01_withdrawal_first(
    root: str | Path,
    orphan_probe: Callable[[Path], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    store = DurableStore(root)

    # Hashes are known before either fact is delivered to the audit writers.
    # The shared receipt service therefore can sign the alert first even though
    # the withdrawal envelope is written to the audit directory first.
    alert = envelope(
        "A", 2, kind="alert", record_id="ALT-1001", terminal_id="T-01",
        calib_rev="CAL-A-1", local_t=14, receipt_seq=1, audit_tick=11,
        summary="synthetic isolation alert delayed in delivery",
    )
    withdrawal = envelope(
        "B", 2, kind="withdrawal", record_id="WD-1001",
        withdraws_alert_id="ALT-1001", terminal_id="T-01",
        calib_rev="CAL-B-1", local_t=15, receipt_seq=2, audit_tick=10,
        summary="synthetic withdrawal receipt arrives before its alert",
    )
    alert_hash = object_hash(alert)
    wd_hash = object_hash(withdrawal)

    r1 = store.append_receipt(1, "0" * 64, alert_hash, issued_tick=8)
    r2 = store.append_receipt(2, r1["receipt_hash"], wd_hash, issued_tick=9)

    probe_result: dict[str, Any] | None = None

    def probe_orphan_commit_point() -> None:
        nonlocal probe_result
        if orphan_probe is not None:
            probe_result = orphan_probe(store.root)

    # The barrier action runs only after WD-1001 and its CP are durable, but
    # before either worker is released; the alert worker has already reached
    # the barrier and therefore cannot write ALT-1001 until the probe reopens
    # the directory from a separate process.
    orphan_barrier = threading.Barrier(2, action=probe_orphan_commit_point)
    errors: list[BaseException | None] = [None, None]

    def withdrawal_worker() -> None:
        try:
            append_envelope(store, withdrawal)
            store.write_commit_point("CP-01a-withdrawal-orphan-durable", {
                "audit_tick": 10,
                "arrival_order_so_far": ["WD-1001"],
                "credential_order": ["receipt#1:ALT-1001", "receipt#2:WD-1001"],
                "must_hold": "orphan withdrawal is durable and is not yet a contradiction",
                "receipt_hashes": {"1": r1["receipt_hash"], "2": r2["receipt_hash"]},
            })
            orphan_barrier.wait(timeout=30)
        except BaseException as exc:
            errors[0] = exc
            try:
                orphan_barrier.abort()
            except Exception:
                pass

    def delayed_alert_worker() -> None:
        try:
            orphan_barrier.wait(timeout=30)
            append_envelope(store, alert)
        except BaseException as exc:
            errors[1] = exc

    t_wd = threading.Thread(target=withdrawal_worker, name="withdrawal-first-writer")
    t_alert = threading.Thread(target=delayed_alert_worker, name="delayed-alert-writer")
    t_wd.start()
    t_alert.start()
    t_wd.join()
    t_alert.join()
    if any(errors):
        raise RuntimeError(f"withdrawal-first writers failed: {errors!r}")

    cp = store.write_commit_point("CP-01b-delayed-alert-matched", {
        "audit_tick": 11,
        "arrival_order": ["WD-1001", "ALT-1001"],
        "credential_order": ["receipt#1:ALT-1001", "receipt#2:WD-1001"],
        "must_hold": "after reopen, receipt order proves ALT-1001 precedes WD-1001",
        "orphan_probe": probe_result,
        "receipt_hashes": {"1": r1["receipt_hash"], "2": r2["receipt_hash"]},
    })
    return {"stage": "withdrawal-first", "commit_point": cp.name,
            "orphan_probe": probe_result, "errors": errors}


def stage_02_corroborating_proof(root: str | Path) -> dict[str, Any]:
    store = DurableStore(root)
    alt2 = envelope(
        "A", 3, kind="alert", record_id="ALT-1002", terminal_id="T-01",
        calib_rev="CAL-A-1", local_t=33, receipt_seq=3, audit_tick=20,
    )
    alt3 = envelope(
        "B", 3, kind="alert", record_id="ALT-1003", terminal_id="T-01",
        calib_rev="CAL-B-1", local_t=30, receipt_seq=4, audit_tick=21,
    )
    r_prev_seq, r_prev_hash = store.last_receipt_hash_and_seq()
    r3 = store.append_receipt(r_prev_seq + 1, r_prev_hash, object_hash(alt2), 18)
    r4 = store.append_receipt(r3["receipt"]["receipt_seq"] + 1,
                              r3["receipt_hash"], object_hash(alt3), 19)
    append_envelope(store, alt2)
    append_envelope(store, alt3)
    wm = publish_current_digest(store, "WM-1-T01-proof", tick=22)
    cp = store.write_commit_point("CP-02-watermark-1-replayable", {
        "watermark_seq": wm["watermark_seq"],
        "must_hold": "fresh replay of WM-1 reproduces table digests",
        "table_digests": wm["table_digests"],
    })
    return {"stage": "corroborating-proof", "watermark": wm["watermark_seq"],
            "commit_point": cp.name}


def stage_03a_publish_watermark_before_loss(root: str | Path) -> dict[str, Any]:
    store = DurableStore(root)
    alt4 = envelope(
        "A", 4, kind="alert", record_id="ALT-2001", terminal_id="T-03",
        calib_rev="CAL-A-1", local_t=68, receipt_seq=5, audit_tick=30,
    )
    wd4 = envelope(
        "B", 4, kind="withdrawal", record_id="WD-2001",
        withdraws_alert_id="ALT-2001", terminal_id="T-03",
        calib_rev="CAL-B-1", local_t=70, receipt_seq=6, audit_tick=31,
    )
    r_prev_seq, r_prev_hash = store.last_receipt_hash_and_seq()
    r5 = store.append_receipt(r_prev_seq + 1, r_prev_hash, object_hash(alt4), 28)
    r6 = store.append_receipt(r5["receipt"]["receipt_seq"] + 1,
                              r5["receipt_hash"], object_hash(wd4), 29)
    append_envelope(store, alt4)
    append_envelope(store, wd4)

    wm = publish_current_digest(store, "WM-2-before-post-publish-receipt-loss", tick=32)
    before_loss = {
        "receipt_path": store.receipts_path.relative_to(store.root).as_posix(),
        "lost_receipt_seq": 6,
        "watermark_seq": wm["watermark_seq"],
        "watermark_prefix_for_receipts": wm["prefixes"][
            store.receipts_path.relative_to(store.root).as_posix()
        ],
    }
    cp_ok = store.write_commit_point("CP-03-published-before-loss", {
        "watermark_seq": wm["watermark_seq"],
        "must_hold": "WM-2 verifies immediately after atomic publish and reopen",
        "loss_to_inject": before_loss,
        "table_digests": wm["table_digests"],
    })
    return {"stage": "publish-watermark-before-loss",
            "commit_point": cp_ok.name, "watermark": wm, "loss_plan": before_loss}


def stage_03b_lose_published_receipt(root: str | Path) -> dict[str, Any]:
    store = DurableStore(root)
    path = store.receipts_path
    raw_lines = path.read_bytes().splitlines(keepends=True)
    kept: list[bytes] = []
    removed = False
    for line in raw_lines:
        try:
            obj = json.loads(line.decode("utf-8"))
            if obj.get("kind") == "shared_receipt" and int(obj.get("receipt_seq", -1)) == 6:
                removed = True
                continue
        except Exception:
            pass
        kept.append(line)
    if not removed:
        raise RuntimeError("expected receipt #6 was not present before loss injection")
    with open(path, "wb") as f:
        f.write(b"".join(kept))
        f.flush()
        import os
        os.fsync(f.fileno())

    cp_broken = store.write_commit_point("CP-04-after-receipt-loss-reopen", {
        "injected_fault": "published receipt line 6 deleted after WM-2",
        "expected_first_contradiction": "published-watermark-prefix-unreplayable",
        "loss": {
            "receipt_path": path.relative_to(store.root).as_posix(),
            "lost_receipt_seq": 6,
        },
    })
    return {"stage": "publish-then-lose-receipt", "removed": removed,
            "commit_point": cp_broken.name}


def stage_04_same_sequence_different_bytes(root: str | Path) -> dict[str, Any]:
    store = DurableStore(root)
    seq = store.next_source_seq("A")  # deterministic 5 in the rehearsal

    # Both workers observe/plan the same next sequence, meet at a barrier, and
    # only then append two different byte strings for that same source slot.
    variant_one = envelope(
        "A", seq, kind="alert", record_id="ALT-3001-A", terminal_id="T-02",
        calib_rev="CAL-A-1", local_t=43, audit_tick=40,
        body_variant="first-committed-byte-string", severity="high",
    )
    variant_two = envelope(
        "A", seq, kind="alert", record_id="ALT-3001-B", terminal_id="T-02",
        calib_rev="CAL-A-1", local_t=45, audit_tick=41,
        body_variant="different-committed-byte-string", severity="critical",
    )
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    errors: list[BaseException | None] = [None, None]

    def worker(idx: int, env: dict[str, Any]) -> None:
        try:
            planned = store.next_source_seq("A")
            if planned != seq:
                raise RuntimeError(f"worker {idx} planned seq {seq}, next was {planned}")
            barrier.wait()  # both have checked the same free sequence
            with lock:
                append_envelope(store, env)
        except BaseException as exc:
            errors[idx] = exc
            try:
                barrier.abort()
            except Exception:
                pass

    t1 = threading.Thread(target=worker, args=(0, variant_one), name="same-seq-writer-1")
    t2 = threading.Thread(target=worker, args=(1, variant_two), name="same-seq-writer-2")
    t1.start(); t2.start(); t1.join(); t2.join()
    if any(errors):
        raise RuntimeError(f"same-sequence writers failed: {errors!r}")

    # Independent source-B proof for T-02 and a later T-03 proof.
    t02_proof = envelope(
        "B", 5, kind="alert", record_id="ALT-3002", terminal_id="T-02",
        calib_rev="CAL-B-1", local_t=52, audit_tick=42,
    )
    t03_later_proof = envelope(
        "B", 6, kind="alert", record_id="ALT-2002", terminal_id="T-03",
        calib_rev="CAL-B-1", local_t=90, audit_tick=43,
    )
    append_envelope(store, t02_proof)
    append_envelope(store, t03_later_proof)

    cp = store.write_commit_point("CP-05-same-sequence-different-bytes", {
        "source": "A",
        "seq": seq,
        "record_ids": ["ALT-3001-A", "ALT-3001-B"],
        "expected_contradiction": "same-sequence-different-bytes",
        "safe_watermark_policy": "do not advance WATERMARK.json across the fork",
    })
    return {"stage": "same-sequence-different-bytes", "seq": seq,
            "commit_point": cp.name}


def build_all_stages(root: str | Path) -> list[dict[str, Any]]:
    return [
        stage_00_calibrations(root),
        stage_01_withdrawal_first(root),
        stage_02_corroborating_proof(root),
        stage_03a_publish_watermark_before_loss(root),
        stage_03b_lose_published_receipt(root),
        stage_04_same_sequence_different_bytes(root),
    ]
