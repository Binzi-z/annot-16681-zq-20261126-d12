# 离线取证室：隔离告警重建与矛盾核验

本目录提供一个**只使用 Python 3.12 标准库、完全离线**的合成数据演练工具包。它复现：

- 两个来源各自连续编号、各自校时区间；
- 区间交叠时，仅由共享 HMAC 签收凭据确定先后；
- 撤回回执先于对应告警落盘；
- 审计水位只在精确字节前缀 `fsync` 后原子发布；
- 发布后签收回执丢失，重开目录即可证明水位不可重放；
- 两个写入工在屏障后产生同一 `(source, seq)` 但字节不同的记录；
- 重新打开目录后逐步核验承诺点；
- 独立核验程序从原始字节重建证明、定位第一个矛盾并输出最短反例链；
- 小样本穷举区间顺序、到达顺序和凭据顺序；
- 60,000 条分区记录中挑选一条跨区校时修订，按原始字节区段实读并逐条与全量结果核对。

所有输入均为本工具生成的合成本地数据；没有网络、第三方包或真实终端数据。

## 一条命令运行

在原生 Windows 中打开 PowerShell 或命令提示符：

```bat
py -3.12 run_audit.py
```

如果 `py` 启动器不可用，但 `python --version` 显示 `Python 3.12.x`：

```bat
python run_audit.py
```

也可以双击或执行：

```bat
run_all.bat
```

默认输出到：

```text
artifacts\
  rehearsal-case\          小规模取证案例（含故意注入的矛盾）
  scale-case\              60,000 条分区合成记录
  reports\
    audit-report.md        给安全复盘阅读的总报告
    run-summary.json       机器可读汇总
    table1_earliest_proven_isolation.csv
    table2_earliest_confirmed_gap.csv
    verify-00-calibrations.json ... verify-05-same-seq.json
    exhaustive-report.json
    scale-report.json
```

CSV 使用 `utf-8-sig`，Windows Excel 直接打开不会乱码。

## 独立核验程序

`independent_verify.py` 不导入生成器或主重建包；它只读取已经写下的字节、密钥、水位和提交点。

```bat
py -3.12 independent_verify.py --root artifacts\rehearsal-case --json-out verify.json
echo ExitCode=%ERRORLEVEL%
```

退出码约定：

- `0`：未发现矛盾；
- `2`：核验程序成功运行，但发现了已注入/真实存在的矛盾；
- 其他：程序或输入本身发生操作错误。

因此对演练案例，最终独立核验返回 `2` 是**预期且成功检出**，不是工具崩溃。

单独运行穷举：

```bat
py -3.12 exhaustive_check.py --json-out artifacts\reports\exhaustive-standalone.json
```

单独生成并核对六万个分区记录：

```bat
py -3.12 verify_scale.py --root artifacts\scale-case --generate --json-out scale.json
```

## 两张审计表的判定口径

校时区间为闭区间 `[lo, hi]`。在没有额外信任假设时：

- 事件最早可能发生在 `lo`；
- 到 `hi` 时刻，保守上界承诺该事件已经发生。

因此“最早能被证明确实处于隔离的时刻”取所有有效告警中最小的 `hi`，并同时保留 `lo` 作为“最早可能时刻”。

有效告警必须：

1. 原始 JSON 可解析、哈希可计算；
2. 未卷入同序号异内容分叉；
3. 未被顺序明确的撤回回执撤销；
4. 若告警/撤回区间交叠，必须有可验证的共享签收凭据决定顺序；否则该告警不能作为证明，只形成缺口结论。

演练数据的预期表如下。

### 表一：最早可证明隔离

| 终端 | 最早可证明时刻（保守上界） | 最早可能时刻 | 证明 |
|---|---:|---:|---|
| `T-01` | `34` | `28` | `ALT-1003` / `B#3` |
| `T-02` | `56` | `50` | `ALT-3002` / `B#5` |
| `T-03` | `94` | `88` | `ALT-2002` / `B#6` |

`T-01` 的 `ALT-1001` 虽被先到的 `WD-1001` 引用，但共享签收链证明凭据顺序是 `ALT-1001` 先、`WD-1001` 后，所以该告警被有效撤回；后续独立告警仍给出最早证明 `34`。

### 表二：最早只能确认缺口

| 终端 | 最早确认缺口时刻 | 类型 | 引用 |
|---|---:|---|---|
| `T-01` | `null` | — | — |
| `T-02` | `46` | `same-sequence-different-bytes` | `A#5` |
| `T-03` | `71` | `unorderable-alert-withdrawal` | `ALT-2001/WD-2001` |

`T-03` 的 `ALT-2001` 与 `WD-2001` 校时区间交叠；决定顺序的签收回执 `receipt#6` 在 WM-2 发布后被注入丢失，因此只能确认顺序/证据缺口，不能采用该告警。后续 `ALT-2002` 仍可在 `94` 证明隔离。

## 承诺点与重开目录

`run_audit.py` 在每个阶段后都会启动一个**新的 Python 子进程**运行 `independent_verify.py`，因此不是同一进程内缓存造成的“假重放”。

承诺点顺序：

1. `CP-00`：A/B 两来源的 `seq=1` 校时基线持久化；
2. `CP-01a`：屏障动作中，撤回 `WD-1001` 已先持久化为孤儿回执；独立子进程重开目录确认无矛盾后，屏障才放行延迟告警；
3. `CP-01b`：`ALT-1001` 落盘，共享签收凭据确定告警/撤回顺序；
4. `CP-02 / WM-1`：发布审计水位，独立进程重放摘要一致；
5. `CP-03 / WM-2`：发布包含 `ALT-2001/WD-2001` 的水位，发布后立即用新进程验证通过；
6. `CP-04`：注入“WM-2 已发布后，`shared-receipts.jsonl` 第 6 条回执丢失”；重开后首个矛盾为 `published-watermark-prefix-unreplayable`；
7. `CP-05`：两个写入工在同一屏障后写入 `A#5` 的两个不同字节串；独立核验同时报出 `same-sequence-different-bytes`。

水位文件保存每个被覆盖文件的：

```json
{
  "lines": 6,
  "end_offset": 1234,
  "prefix_sha256": "..."
}
```

重放时不是相信当前整文件哈希，而是按 `end_offset` 读取**精确原始前缀**并核对 SHA-256。这样后续追加不会破坏旧水位，而已发布前缀被截断、删除或改字节会立即暴露。

## 第一个矛盾与最短反例链

最终案例中的第一个矛盾按审计时间排序是：

```text
published-watermark-prefix-unreplayable @ WM-2
```

最短链为：

1. `WATERMARK WM-2` 发布了精确前缀承诺；
2. 该承诺包含回执文件的 `end_offset + prefix_sha256`；
3. 重新打开目录后，文件无法提供承诺长度的原始字节；
4. 因而“已持久化水位必须可重放”被违反。

其后才是 `A#5` 同序号异内容矛盾。该矛盾自己的最短反例链是：

1. 连续来源键 `(A, seq=5)`；
2. 第一行原始 SHA-256；
3. 同一键下另一行不同 SHA-256；
4. 违反“一个连续序号只能对应一个规范字节流”。

完整链和所有矛盾排序见 `artifacts/reports/audit-report.md` 与 `verify-05-same-seq.json`。

## 穷举与六万条规模核对

### 小样本穷举

`exhaustive.py` 枚举端点 `0..3` 内全部 10 个合法区间，形成 `10 × 10 = 100` 对区间；再乘：

- 2 种告警/撤回到达顺序；
- 2 种共享凭据顺序；
- 2 种回执存在/丢失状态。

总计：

```text
100 × 2 × 2 × 2 = 800 个用例
```

并额外反转记录列表，确认结论不依赖磁盘读入顺序。

### 60,000 条分区记录

规模数据位于 `artifacts/scale-case/partitions/partition=00..23/records.jsonl`，每个分区 2,500 条，共 60,000 条。

选中的跨区校时修订为：

```text
CAL-CROSS-REGION-REV-7
```

它在每个分区形成一个连续原始字节段，共 24 个原始区段、600 条记录。核对程序：

1. 全量扫描 24 个文件、60,000 条记录；
2. 从 `segment-index.json` 取得跨区修订的 `start_offset/end_offset/count/raw_sha256`；
3. `seek` 到每个原始区段并精确读取指定字节数；
4. 实测换行数和 SHA-256；
5. 将区段中的每条记录与全量扫描对象按 `record_id` 逐个规范化比对；
6. 核对跨区修订 ID 集合、条数和总记录数。

预期结果：

```text
total_partition_records_full_scan = 60000
partition_files_read              = 24
raw_extents_read                  = 24
cross_revision_records            = 600
raw_records_compared_one_by_one   = 600
mismatches                        = 0
```

## 代码布局

```text
run_audit.py             端到端编排、子进程重开验证、CSV/Markdown 输出
independent_verify.py    独立原始字节核验、矛盾与最短链
exhaustive_check.py      800 个小区间/撤回排列用例入口
verify_scale.py          60k 分区规模核对入口
run_all.bat              原生 Windows 便捷启动器
forensic_audit/
  canonical.py           规范 JSON、SHA-256、原子 JSON 发布
  store.py               追加日志、fsync、精确前缀水位、提交点
  engine.py              主重建与摘要
  scenario.py            屏障双写入工和三个故障场景
  exhaustive.py          穷举模型
  scale.py               60k 合成数据与原始区段核对
```

## 安全边界

- 工具不访问网络；
- 不读取本目录之外的业务数据；
- 不删除或修改 `artifacts/` 之外的文件；
- `artifacts/` 已在 `.gitignore` 中；
- HMAC 密钥是明确写在代码中的**合成演练密钥**，不用于真实身份认证；
- 输出只用于安全复盘、审计程序验证和教学。
