# 控制流反混淆工具

本目录用于开发基于静态分析与运行时 trace 的控制流反混淆工具。首个验证对象是 `demo/lesson_score` 的 ARM64 OLLVM 平坦化样本；后续通过策略扩展支持间接跳转、多分发器和混合块。

当前 D0–D4 已实现 demo 首版，D3/D4 的数据契约见 [详细设计](docs/D3_D4_DESIGN.md)，实测结果见 [D3/D4 验收](docs/D3_D4_ACCEPTANCE.md)。阶段接口见 [开发文档](docs/DEVELOPMENT.md)，后续里程碑见 [开发计划](docs/ROADMAP.md)，命令和适用范围见 [使用说明](docs/USAGE.md)。原始实验脚本仍位于本机的 `../demo/`；可复现的 demo 样本已收录在 `tests/fixtures/lesson_score/`。

默认大模型配置见 [config/default.toml](config/default.toml)：可选 Codex CLI 调用使用 `gpt-6-sol`，推理强度为 `high`。D2 已加入只读在线提案接口；模型提案不直接改变结构结论。

## 开发原则

- 地址统一为二进制标识与模块偏移；每项结论保留来源证据。
- 动态观察、静态推导和已验证修改分别记录，不互相替代。
- 固定阶段接口；分发器识别、状态溯源和修复方式使用可扩展策略。
- 大模型可提出规则和解释异常，工具必须独立核查规则与修改效果。
- 先生成可审阅、可撤销的修复方案，再考虑写入二进制文件。

## D0/D1 原型运行

Python 3.8+，安装 `tomli`、`pyelftools`、`capstone`；实时采集另需 `frida` 和目标设备上的 Frida server。以下示例在 `reverce` 目录运行，详细前提见[使用说明](docs/USAGE.md)：

```powershell
python deobfuscation-tool/cli.py init --binary deobfuscation-tool/tests/fixtures/lesson_score/libflatten_fla_android.so --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py static --binary deobfuscation-tool/tests/fixtures/lesson_score/libflatten_fla_android.so --disasm deobfuscation-tool/tests/fixtures/lesson_score/lesson_score_trace_disasm.txt --function lesson_score --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py import-legacy --binary deobfuscation-tool/tests/fixtures/lesson_score/libflatten_fla_android.so --log deobfuscation-tool/tests/fixtures/lesson_score/lesson_score_trace_raw.log --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 1
python deobfuscation-tool/cli.py discover --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 2
python deobfuscation-tool/cli.py plan-probes --output deobfuscation-tool/work/lesson
# 完成设备采集后导入本次的 JSONL：
python deobfuscation-tool/cli.py import-probes --capture deobfuscation-tool/work/probes.jsonl --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 3
python deobfuscation-tool/cli.py infer --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 4
python -m unittest discover -s deobfuscation-tool -p 'test_*.py' -v
```

静态导出以保存的反汇编确定函数范围，并核对 ELF 中对应指令助记符，实际操作数和字节从 Capstone 读取。它支持直接分支及条件分支，间接跳转保留 unresolved。静态块的 end 是排他地址。反汇编必须覆盖 ELF 符号表中指定函数的完整范围；缺失或有歧义的符号会报错。BL/BLR 显式记录调用及假设返回后的续行，间接调用目标保留 unresolved。产物带版本、SHA-256、指令和事件引用。旧日志没有线程、调用 ID、块终点、调用和返回事件，这些字段为 null 或在 missing_fields 中明确列出，不能根据相邻块推断直接边。

实时采集示例（目标先加载库）：

```powershell
python deobfuscation-tool/host_collect.py --device 127.0.0.1:27042 --pid 1234 --script deobfuscation-tool/collect.js --module libflatten_fla_android.so --symbol lesson_score --run-id capture-1 --output capture.jsonl
python deobfuscation-tool/cli.py import-capture --binary build/artifacts/libflatten_fla_android.so --module libflatten_fla_android.so --capture capture.jsonl --output work/lesson
```

同二进制后续 D1 采集可加 `--merge`，run-id 必须唯一。采集保留模块外事件和 Stalker 原始数组；不属于目标模块的地址只保留其模块名与偏移或绝对地址，不赋目标 binary_id。采集方须自行确认设备上的库与本地二进制一致；本次实测已核对设备与本地 SHA-256。相同线程的嵌套调用明确报错，不支持递归目标。D3/D4 的新采集命令见[使用说明](docs/USAGE.md)。D5/D6 尚未实现；`stage` 只检查已保存输入，不会生成伪造阶段结果。模型提案可重放，在线调用需显式加 `discover --use-model`。默认配置从 `config/default.toml` 加载，也可通过顶层 `--config` 指定。验收见 [D0/D1](docs/D0_D1_ACCEPTANCE.md)、[D2](docs/D2_ACCEPTANCE.md) 与 [D3/D4](docs/D3_D4_ACCEPTANCE.md)。
