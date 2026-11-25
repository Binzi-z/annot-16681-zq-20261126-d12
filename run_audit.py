#!/usr/bin/env python3
"""End-to-end offline rehearsal runner.

Native Windows / Python 3.12 standard library only.

It creates only synthetic local data under ``artifacts/``, drives the barred
two-writer reproduction, reopens the case through a fresh independent
verifier process after every commit point, exhausts the small ordering
matrix, and generates/checks 60,000 partition records.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from forensic_audit.engine import digest_tables, load_disk_log, reconstruct_tables
from forensic_audit.exhaustive import brute_force_order_cases
from forensic_audit.scale import generate_scale_case
from forensic_audit import scenario

REPO_ROOT = Path(__file__).resolve().parent
VERIFIER = REPO_ROOT / "independent_verify.py"
SCALE_VERIFIER = REPO_ROOT / "verify_scale.py"


def run_independent_verify(case_root: Path, json_out: Path) -> dict[str, Any]:
    json_out.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), "--root", str(case_root),
         "--json-out", str(json_out), "--quiet"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
        check=False,
    )
    if not json_out.exists():
        raise RuntimeError(
            f"independent verifier did not write {json_out}; "
            f"exit={proc.returncode}, stderr={proc.stderr}"
        )
    report = json.loads(json_out.read_text(encoding="utf-8"))
    report["_subprocess_returncode"] = proc.returncode
    if proc.stderr.strip():
        report["_stderr"] = proc.stderr.strip()
    return report


def assert_clean(check: str, report: dict[str, Any]) -> None:
    if report["_subprocess_returncode"] != 0 or not report.get("ok"):
        raise AssertionError(
            f"{check}: expected clean reopened verification, got "
            f"rc={report['_subprocess_returncode']}, "
            f"first={report.get('first_contradiction')}"
        )


def assert_first_code(check: str, report: dict[str, Any], code: str) -> None:
    first = report.get("first_contradiction") or {}
    if report["_subprocess_returncode"] != 2 or first.get("code") != code:
        raise AssertionError(
            f"{check}: expected first contradiction {code!r}, got "
            f"rc={report['_subprocess_returncode']}, first={first.get('code')!r}"
        )


def write_csv_tables(report: dict[str, Any], reports_dir: Path) -> tuple[Path, Path]:
    proof = report["proof_rebuild"]
    iso_path = reports_dir / "table1_earliest_proven_isolation.csv"
    gap_path = reports_dir / "table2_earliest_confirmed_gap.csv"

    iso_fields = ["terminal_id", "earliest_proven_isolation_at",
                  "earliest_possible_isolation_at", "proof_id", "proof_source_seq"]
    with open(iso_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=iso_fields)
        w.writeheader()
        for row in proof["isolation_table"]:
            w.writerow({k: row.get(k) for k in iso_fields})

    gap_fields = ["terminal_id", "earliest_gap_confirmed_at", "gap_kind", "gap_ref"]
    with open(gap_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=gap_fields)
        w.writeheader()
        for row in proof["gap_table"]:
            w.writerow({k: row.get(k) for k in gap_fields})
    return iso_path, gap_path


def render_markdown(summary: dict[str, Any], out_path: Path) -> None:
    lines: list[str] = []
    lines.append("# 离线取证演练重建报告\n")
    lines.append("所有数据均为合成本地数据；仅使用 Python 3.12 标准库。\n")

    cp_checks = summary["commit_point_checks"]
    lines.append("## 1. 重新打开目录后的承诺点验证\n")
    lines.append("| 步骤 | 新鲜核验进程 | 结果 | 首个矛盾 |")
    lines.append("|---|---:|---|---|")
    for c in cp_checks:
        first = c.get("first_code") or "—"
        result = "通过" if c["passed"] else "未通过"
        lines.append(f"| {c['step']} | `{c['report_file']}` | {result} | `{first}` |")
    lines.append("")

    final = summary["independent_final"]
    lines.append("## 2. 审计室两张表\n")
    lines.append("### 表一：每个合成终端最早可证明隔离时刻\n")
    lines.append("保守承诺时刻取有效告警校时区间的右端点；左端点同时列为最早可能时刻。\n")
    lines.append("| 终端 | 最早可证明隔离时刻 | 最早可能时刻 | 证明记录 | 来源序号 |")
    lines.append("|---|---:|---:|---|---|")
    for r in final["proof_rebuild"]["isolation_table"]:
        lines.append(
            f"| {r['terminal_id']} | {r['earliest_proven_isolation_at'] if r['earliest_proven_isolation_at'] is not None else '—'} "
            f"| {r['earliest_possible_isolation_at'] if r['earliest_possible_isolation_at'] is not None else '—'} "
            f"| {r.get('proof_id') or '—'} | {r.get('proof_source_seq') or '—'} |"
        )
    lines.append("")
    lines.append("### 表二：最早只能确认缺口的时刻\n")
    lines.append("| 终端 | 最早确认缺口时刻 | 缺口类型 | 引用 |")
    lines.append("|---|---:|---|---|")
    for r in final["proof_rebuild"]["gap_table"]:
        lines.append(
            f"| {r['terminal_id']} | {r['earliest_gap_confirmed_at'] if r['earliest_gap_confirmed_at'] is not None else '—'} "
            f"| {r.get('gap_kind') or '—'} | {r.get('gap_ref') or '—'} |"
        )
    lines.append("")

    first = final.get("first_contradiction")
    lines.append("## 3. 第一个矛盾与最短反例链\n")
    if not first:
        lines.append("未发现矛盾。\n")
    else:
        lines.append(f"- 代码：`{first['code']}`")
        lines.append(f"- 严重度：`{first.get('severity')}`")
        if first.get("watermark_seq") is not None:
            lines.append(f"- 水位：WM-{first['watermark_seq']}")
        if first.get("source"):
            lines.append(f"- 来源/序号：{first['source']}#{first.get('seq')}")
        lines.append("")
        lines.append("最短反例链：\n")
        for i, node in enumerate(first.get("shortest_counterexample_chain", []), 1):
            rel = node.get("relation_from_previous")
            prefix = f"{i}. "
            if rel:
                prefix += f"〔{rel}〕 "
            lines.append(f"{prefix}{node['evidence']}")
        lines.append("")
        lines.append("全部矛盾排序：\n")
        for c in final.get("contradictions", []):
            lines.append(f"- `{c['code']}` order_key={c.get('order_key')}")
        lines.append("")

    lines.append("## 4. 历史水位重放\n")
    lines.append("| 水位 | 重放状态 | 结论摘要一致 |")
    lines.append("|---|---|---|")
    for w in final.get("watermark_checks", []):
        lines.append(f"| WM-{w.get('watermark_seq')} | {w.get('status')} | {w.get('consistent', '—')} |")
    lines.append("")
    lines.append("WM-2 在发布后立即由独立进程重放通过；随后注入“发布后回执 #6 丢失”，最终重开时如实验证为前缀不可重放。WM-1 的精确前缀仍可重放出相同结论摘要。\n")

    ex = summary["exhaustive"]
    lines.append("## 5. 小样本穷举\n")
    lines.append(f"- 结果：{'通过' if ex['ok'] else '失败'}")
    lines.append(f"- 用例数：{ex['checked']}")
    lines.append(f"- 校时区间对：{ex['interval_pairs']}（端点 0..3 的全部合法区间）")
    lines.append(f"- 到达顺序排列：{ex['arrival_permutations']}")
    lines.append(f"- 签收凭据顺序排列：{ex['credential_permutations']}")
    lines.append(f"- 回执存在/丢失变体：{ex['receipt_loss_variants']}\n")

    sc = summary["scale"]
    lines.append("## 6. 六万条分区记录跨区校时修订核对\n")
    if sc.get("skipped"):
        lines.append("本次运行指定了 `--skip-scale`，未生成六万元数据。\n")
    else:
        lines.append(f"- 全量扫描记录数：{sc['total_partition_records_full_scan']}")
        lines.append(f"- 分区数据文件数：{sc['partition_files_read']}")
        lines.append(f"- 选中跨区校时修订：`{sc['chosen_cross_partition_revision']}`")
        lines.append(f"- 实测原始区段数：{sc['raw_extents_read']}")
        lines.append(f"- 跨区修订记录数（全量）：{sc['cross_revision_records_in_full_scan']}")
        lines.append(f"- 原始区段实读并逐条核对：{sc['raw_records_read_and_compared_one_by_one']}")
        lines.append(f"- 不一致条数：{sc['mismatches']}")
        lines.append(f"- 样本：{sc['sample_record_id']} / partition={sc['sample_partition']} / interval={sc['sample_calibrated_interval']}\n")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--artifacts", type=Path, default=REPO_ROOT / "artifacts")
    p.add_argument("--skip-scale", action="store_true")
    args = p.parse_args()

    artifacts = args.artifacts
    case_root = artifacts / "rehearsal-case"
    scale_root = artifacts / "scale-case"
    reports_dir = artifacts / "reports"
    for d in (case_root, scale_root, reports_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    checks: list[dict[str, Any]] = []

    def verify_step(step: str, file_stem: str, expected: str | None = None,
                    expected_code: str | None = None) -> dict[str, Any]:
        report_file = reports_dir / f"{file_stem}.json"
        report = run_independent_verify(case_root, report_file)
        passed = True
        error = None
        try:
            if expected == "clean":
                assert_clean(step, report)
            elif expected == "code":
                assert_first_code(step, report, expected_code or "")
        except AssertionError as exc:
            passed = False
            error = str(exc)
            raise
        finally:
            checks.append({
                "step": step,
                "report_file": report_file.name,
                "returncode": report.get("_subprocess_returncode"),
                "passed": passed,
                "first_code": (report.get("first_contradiction") or {}).get("code"),
                "error": error,
            })
        return report

    # Stage 00
    scenario.stage_00_calibrations(case_root)
    verify_step("CP-00 校时基线", "verify-00-calibrations", "clean")

    # Stage 01 with an in-barrier independent orphan probe.
    def orphan_probe(root: Path) -> dict[str, Any]:
        rep = run_independent_verify(root, reports_dir / "verify-01a-orphan.json")
        assert_clean("CP-01a withdrawal orphan", rep)
        checks.append({
            "step": "CP-01a 撤回先写/孤儿回执",
            "report_file": "verify-01a-orphan.json",
            "returncode": rep["_subprocess_returncode"],
            "passed": True,
            "first_code": None,
            "error": None,
        })
        return {"returncode": rep["_subprocess_returncode"], "ok": rep["ok"]}

    scenario.stage_01_withdrawal_first(case_root, orphan_probe=orphan_probe)
    verify_step("CP-01b 延迟告警匹配", "verify-01b-matched", "clean")

    scenario.stage_02_corroborating_proof(case_root)
    verify_step("CP-02 WM-1", "verify-02-wm1", "clean")

    scenario.stage_03a_publish_watermark_before_loss(case_root)
    immediate_wm2 = verify_step("CP-03 WM-2 发布后即时重开", "verify-03-wm2-immediate", "clean")

    scenario.stage_03b_lose_published_receipt(case_root)
    verify_step("CP-04 发布后回执丢失", "verify-04-receipt-lost", "code",
                "published-watermark-prefix-unreplayable")

    scenario.stage_04_same_sequence_different_bytes(case_root)
    final = verify_step("CP-05 同序号异内容", "verify-05-same-seq", "code",
                        "published-watermark-prefix-unreplayable")

    iso_csv, gap_csv = write_csv_tables(final, reports_dir)

    # Cross-check the independent verifier's conclusion digest against the
    # primary reconstruction implementation in this package.
    loaded = load_disk_log(case_root)
    primary_tables = reconstruct_tables(loaded)
    primary_digest = digest_tables(primary_tables)["conclusion_digest"]
    if primary_digest != final["independent_conclusion_digest"]:
        raise AssertionError(
            f"primary/independent conclusion digest mismatch: "
            f"{primary_digest} != {final['independent_conclusion_digest']}"
        )
    (reports_dir / "primary-reconstruction.json").write_text(
        json.dumps(primary_tables, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )

    exhaustive = brute_force_order_cases()
    if not exhaustive["ok"]:
        raise AssertionError(f"exhaustive checks failed: {exhaustive['failures'][:3]}")
    (reports_dir / "exhaustive-report.json").write_text(
        json.dumps(exhaustive, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    if args.skip_scale:
        scale_report = {"skipped": True}
    else:
        generate_scale_case(scale_root)
        scale_json = reports_dir / "scale-report.json"
        scale_proc = subprocess.run(
            [sys.executable, str(SCALE_VERIFIER), "--root", str(scale_root),
             "--json-out", str(scale_json)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            check=False,
        )
        if scale_proc.returncode != 0 or not scale_json.exists():
            raise AssertionError(
                "independent scale verifier failed: "
                f"rc={scale_proc.returncode}, stderr={scale_proc.stderr}"
            )
        scale_report = json.loads(scale_json.read_text(encoding="utf-8"))

    summary = {
        "case_root": str(case_root),
        "scale_root": str(scale_root),
        "commit_point_checks": checks,
        "independent_final": final,
        "primary_independent_digest_match": True,
        "exhaustive": exhaustive,
        "scale": scale_report,
        "csv_tables": [str(iso_csv), str(gap_csv)],
        "immediate_wm2_watermark_checks": immediate_wm2.get("watermark_checks"),
    }
    (reports_dir / "run-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    render_markdown(summary, reports_dir / "audit-report.md")

    print("Offline rehearsal completed.")
    print(f"  case:       {case_root}")
    print(f"  reports:    {reports_dir}")
    print(f"  table 1:    {iso_csv}")
    print(f"  table 2:    {gap_csv}")
    print(f"  markdown:   {reports_dir / 'audit-report.md'}")
    print(f"  first issue: {(final.get('first_contradiction') or {}).get('code')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
