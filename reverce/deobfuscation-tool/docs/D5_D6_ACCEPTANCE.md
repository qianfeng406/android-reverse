# D5/D6 demo 验收记录

## 环境与输入

- 日期：2026-11-22；目标：`lesson_score`，ARM64 `libflatten_fla_android.so`。
- 原件 SHA-256：`255012def2298be947eae9ba5177e06d41f7f1a6ff5f8fa6b195bf3b18ee6888`。
- D0–D4 输入来自本机已保存的 `work/experiments/demo-d3-opt-20261122/results`。D3 为设备定点采集，D4 有 14 条规则、18 个转移选项、0 个未解项；详情见 [D3/D4 验收](D3_D4_ACCEPTANCE.md)。

## 执行记录

在 `deobfuscation-tool` 目录运行：

```powershell
python cli.py plan-patch --binary tests/fixtures/lesson_score/libflatten_fla_android.so --output work/experiments/demo-d3-opt-20261122/results
python cli.py stage --output work/experiments/demo-d3-opt-20261122/results --from-stage 5
python cli.py verify-patch --binary tests/fixtures/lesson_score/libflatten_fla_android.so --patched-binary work/experiments/demo-d3-opt-20261122/results/libflatten_fla_android_patched.so --runner-spec work/experiments/demo-d3-opt-20261122/results/runner_spec.json --output work/experiments/demo-d3-opt-20261122/results
python cli.py stage --output work/experiments/demo-d3-opt-20261122/results --from-stage 6
```

Android runner 由 `android_runner.c` 使用 Kali 上 Android NDK r29 的 `aarch64-linux-android25-clang` 编译，随后把 runner、原件和修复副本推送到设备 `/data/local/tmp`。测试设备由 `adb devices` 识别为 Pixel 8 Pro；设备上两份 `.so` 的 `sha256sum` 与下列本地哈希一致。`runner_spec.json` 指定 `adb shell <runner> {binary} {input}`，以及设备上的两份库路径和输入组。实验 JSON、修复 `.so` 和运行日志留在忽略的 `work/` 中。

## 结果

| 检查 | 结果 |
| --- | --- |
| D5 计划 | 13 个 ready 来源，0 个未解；返回块无需修改 |
| 修改 | 17 条 ARM64 指令：入口 1 条，8 个单后继各 1 条，4 个双后继各 2 条 |
| D6 静态重建 | 修复后从入口可达的分发区域块数为 0；每条新分支的解码目标与计划相符 |
| 原件与撤销 | 原件哈希未变；在修复副本上撤销全部修改后的哈希等于原件 |
| 设备差分 | 27 个输入全部一致，返回值、退出码、标准错误相同；报告为 `passed` |
| 修复副本 SHA-256 | `f2b10e3d258a8bf0ebc3cbb061ba5048af1c7ee0e88d043fbfdf7e89612cde18` |

27 个输入包含先前 trace 的 7 个值，以及负数、零附近、分支边界附近和 `INT32_MAX`。这些样例是运行证据，不构成所有输入等价的形式化证明。D5 的静态安全审计限定在可识别的栈状态槽与当前分发模式；遇调用、间接跳转或未知内存影响会保留未解项。D6 当前比较返回值、退出码和标准错误；对具有外部副作用的函数，需要扩展 runner 与对比字段。

2026-11-23 再次执行 D5 后，修复副本的 SHA-256 仍为上表所列值。设备一度从 `adb devices` 消失，期间的 D6 报告正确标为 `failed`；恢复连接并再次核对设备文件哈希后，重新运行 D6，27 组输入全部一致，当前本机 `verification_report.json` 为 `passed`，`stage --from-stage 6` 通过。

## 修改清单摘要

| 来源块 | 指令地址 | 恢复目标 |
| --- | --- | --- |
| `0x15fc` | `0x161c` | `0x1760` |
| `0x1760` | `0x177c`, `0x1780` | `0x1784`, `0x17a4` |
| `0x1784`, `0x17a4` | `0x17a0`, `0x17b8` | `0x17a4`, `0x17bc` |
| `0x17bc`, `0x17e0` | `0x17d8`/`0x17dc`, `0x17fc`/`0x1800` | `0x17e0`/`0x188c`, `0x1804`/`0x182c` |
| `0x1804`, `0x182c`, `0x1854`, `0x1870` | `0x1828`, `0x1850`, `0x186c`, `0x1888` | `0x1854`, `0x1854`, `0x1870`, `0x17bc` |
| `0x188c` | `0x18a8`, `0x18ac` | `0x18b0`, `0x18d0` |
| `0x18b0`, `0x18d0` | `0x18cc`, `0x18e8` | `0x18ec`, `0x18ec` |

逐条旧/新字节、条件码、证据及安全检查见本机 `patch_plan.json`；修复 CFG、每个测试输入的原件和副本输出见 `verification_report.json`。


## 2026-11-23 清理回归

实验目录：[demo-cleanup-20261123](../work/experiments/demo-cleanup-20261123/)，设备差分和 CFG 数据见 [verification_report.json](../work/experiments/demo-cleanup-20261123/verification_report.json)；可单独查看[真实入口可达图](../work/experiments/demo-cleanup-20261123/reachable_cfg.dot)和[折叠展示图](../work/experiments/demo-cleanup-20261123/display_cfg.dot)。27 个输入全部一致，回滚校验通过。真实 CFG 全量块 46、入口可达块 18 均不变；可达非 NOP 指令 111→56，状态槽可达读取 0→0、写入 8→0。展示图折叠 NOP-only 节点，不能当作二进制真实 CFG；原位 NOP 不缩小 ELF 或符号。

## 2026-11-23 手工表对照与条件分支位置

[本地对照实验](../work/experiments/demo-manual-20261123/README.md)逐条执行此前的手工 patch 表，并与工具版比较。原表把 `0x1828`、`0x1850` 直接跳到 `0x1870`，漏掉了 `0x1854` 的业务右移；原表版仅 1/27 输入与原件一致。把两条目标修正为 `0x1854` 后为 27/27，但仍有 107 条可达非 NOP 指令和 8 处状态写入。

D5 现对“条件真目标紧邻当前块”的已证明模式优先在 `CSEL` 处放置取反后的条件跳转，并将状态写入与旧分发器跳转改为指向下一指令的分支，后续清理成 NOP。新版修复库的入口可达 CFG 为 18 块、56 条非 NOP 指令、状态槽读写 0/0，设备 27/27 输入一致；展示图仍为 14 个节点。独立 `route_score` 样本也重跑 D5/D6，12/12 输入一致。该调整改变分支落点和指令布局，不会删除 ELF 中入口不可达的全部分发块。
