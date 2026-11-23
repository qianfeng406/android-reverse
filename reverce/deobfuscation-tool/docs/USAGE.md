# D0–D6 使用说明

## 当前工具能做什么

D0/D1 可为一个 **ARM64 ELF `.so` 中的已知函数**建立静态指令与 CFG，采集该函数一次调用期间执行线程的 Stalker block/call/ret 事件，并将多次运行归一化到同一二进制偏移。D2 根据图和状态读写提出分发结构候选。D3 编译定点探针计划并归一化同轮采集；D4 依据静态指令推导转移并核对观测。D5 对可证明安全的直接边生成补丁计划；D6 在副本上实施、重建 CFG，并用指定 runner 做行为差分。

**安装了 APK 并不等于可以直接运行本工具 trace。** 当前采集器需要：

| 条件 | 当前要求 |
| --- | --- |
| 进程 | 应用已启动，已知 PID，Frida host 能连接该进程 |
| 目标库 | 目标 `.so` 已加载；提供模块名及本地同版本 `.so` 文件 |
| 目标函数 | 提供可由 Frida `getExportByName` 找到的导出符号；尚不支持只给地址或自动枚举 APK 内全部函数 |
| 静态导出 | ELF 有带大小的函数符号，并提供覆盖完整函数的同版 `llvm-objdump` 风格反汇编文本 |
| 采集时机 | 先附加并加载脚本，再触发目标函数调用；当前脚本不会替应用主动调用函数 |
| 参数与返回 | 首版把第一个参数和返回值按有符号 32 位整数记录，适合 `lesson_score(int32_t)`；其他签名需要扩展采集策略 |
| 调用结构 | 同一线程的目标函数递归/嵌套调用会报错；跨线程调用按线程和调用 ID 区分 |

采集范围由**函数入口到本次函数返回**决定，当前没有要求用户配置地址范围的 `--size` 参数。Stalker 在此期间跟踪整个执行线程，包括进入其他模块的事件；后续分析才按模块或函数范围筛选。若 `.so` 尚未加载、函数不是导出符号，或 Frida 无法附加进程，当前命令会失败。设备文件与本地 `.so` 的哈希须在采集前自行核对；工具尚未远程读取设备文件来自动核对。

## 离线运行与验收

在 `reverce` 目录准备 Python 3.8+，安装 `tomli`、`pyelftools`、`capstone`。仓库内 `tests/fixtures/lesson_score` 保存自编译 demo 样本、同版本反汇编、旧 trace 和源码，便于干净克隆后重复运行：

```powershell
python -m pip install tomli pyelftools capstone
python deobfuscation-tool/cli.py init --binary deobfuscation-tool/tests/fixtures/lesson_score/libflatten_fla_android.so --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py static --binary deobfuscation-tool/tests/fixtures/lesson_score/libflatten_fla_android.so --disasm deobfuscation-tool/tests/fixtures/lesson_score/lesson_score_trace_disasm.txt --function lesson_score --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py import-legacy --binary deobfuscation-tool/tests/fixtures/lesson_score/libflatten_fla_android.so --log deobfuscation-tool/tests/fixtures/lesson_score/lesson_score_trace_raw.log --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 1
python deobfuscation-tool/cli.py discover --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 2
python -m unittest discover -s deobfuscation-tool -p 'test_*.py' -v
```

成功后输出目录包含 `binary_manifest.json`、`instruction_table.json`、`static_cfg.json`、`raw_trace.json`、`structure_candidates.json`、`probe_plan.json` 和 `observed_graph.dot`。安装 Graphviz 后可用 `dot -Tsvg deobfuscation-tool/work/lesson/observed_graph.dot -o deobfuscation-tool/work/lesson/observed_graph.svg` 查看图；虚线只代表相邻观察事件，不代表已证明的直接 CFG 边。`stage --from-stage 2` 只验证 D2 保存的产物，不会自动运行 D3。旧 trace 缺少的线程、调用和块终点字段保持缺失标记。

## D2 结构发现

`discover` 默认使用 `stack_comparison_chain_v1` 结构策略，启用 `fanin,recurrence,routing,state_read,state_write,provenance,side_effect` 七条原子证据规则。`--strategy` 指定结构机制，当前只有这一种已登记；未知策略明确报错。可用 `--rules fanin,routing,state_read,state_write` 为本次运行选择证据子集；缺少图与状态证据时输出 `unresolved`，不会仅凭高频循环认定分发器。规则配置保存在 `structure_candidates.json`，不修改全局变量。`observed_graph.observed_transitions` 的相邻事件只表示观察顺序，`direct_cfg_edge` 保持 `null`，不能据此断言是直接 CFG 边。

首版针对共享回跳与栈状态槽比较链：从多来源汇入点寻找多个回流写入块，再检查其状态槽是否在下游路由区被读取和比较。候选包含状态位置、别名、分发块、执行入口、证据及潜在副作用；`probe_plan` 列出同块内 `CMP/TST → CSEL → 状态写入` 的条件探针。此阶段只输出候选，不证明完整转移和可 patch 性。分层分发、跨块状态更新和复杂 `BR/BLR` 仍待增强。

可选运行 `python deobfuscation-tool/cli.py discover --output deobfuscation-tool/work/lesson --use-model`，使用本机 Codex CLI 按 `config/default.toml` 发起独立的只读结构提案；长任务可追加 `--model-timeout 240`。提案经引用和函数范围校验后保存为 `model_proposal.json`。模型可在 `checks_requested` 中列出 `rule:<规则名>` 来选择可选规则；图、复现与状态证据所需的五条核心规则始终执行，最终产物记录实际规则。模型不能直接修改 CFG 或探针地址；不加开关时完全离线运行。Codex 退出、超时或输出不合格式会明确失败。在线调用需要本机 CLI 可用及其登录状态；回归测试使用模拟子进程，不依赖实时模型输出。

## 对正在运行的应用采集

1. 从目标 APK 或设备取得与运行版本一致的 ARM64 `.so`，确定导出函数名，并准备该函数的完整反汇编文本。对照本地和设备文件的 SHA-256。
2. 启动应用，取得 PID；确认目标库已经加载。启动可连接的 Frida server，或使用环境已有的 Frida 连接方式。在 host 上安装与 server 兼容的 `frida` Python 包。
3. 在目标函数**下一次调用之前**启动采集命令。这里的 `--device` 是 Frida host 可到达的 server 地址，`--run-id` 是本次采集的唯一标识：

```powershell
python deobfuscation-tool/host_collect.py --device 127.0.0.1:27042 --pid 1234 --script deobfuscation-tool/collect.js --module libtarget.so --symbol target_function --run-id capture-1 --output deobfuscation-tool/work/capture-1.jsonl
```

4. 操作应用触发函数。函数调用完成后，结束采集进程；只导入包含完整 `enter → events → leave` 的采集文件。先用目标 `.so` 执行 `init` 和 `static`，再导入：

```powershell
python deobfuscation-tool/cli.py import-capture --binary path/to/libtarget.so --module libtarget.so --capture deobfuscation-tool/work/capture-1.jsonl --output deobfuscation-tool/work/target
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/target --from-stage 1
```

同一二进制的新采集使用新的 `--run-id`，导入时加 `--merge`。工具拒绝重复 run ID、缺失或乱序事件、跨调用事件，以及不匹配的本地二进制产物。采集错误会写入 JSONL；导入遇到错误记录时失败。

## D3 定点采集与 D4 转移推导

先完成上面的 D0–D2 命令。`plan-probes` 从已选结构候选、指令和 CFG 自动补齐入口及状态写入点；`compiled_probe_plan.json` 是采集脚本的精确配置。运行中的目标进程须已加载同版 `.so`，且目标函数是可查到的导出符号。采集进程必须先附加，再触发函数调用：

```powershell
python deobfuscation-tool/cli.py plan-probes --output deobfuscation-tool/work/lesson
python deobfuscation-tool/host_probe.py --device 127.0.0.1:27042 --pid 1234 --script deobfuscation-tool/collect_probes.js --plan deobfuscation-tool/work/lesson/compiled_probe_plan.json --module libflatten_fla_android.so --symbol lesson_score --run-id probe-1 --output deobfuscation-tool/work/probe-1.jsonl
```

`--pid` 是运行中进程的 PID，`--device` 是 Frida host 可达的 server 地址；`--module` 和 `--symbol` 必须对应加载的库和导出函数。`--run-id` 标识这一轮采集；`--output` 必须是尚不存在的 JSONL 路径。采集器一直等待直至进程脱离或按 Ctrl+C 结束。采集结束后再运行：

```powershell
python deobfuscation-tool/cli.py import-probes --capture deobfuscation-tool/work/probe-1.jsonl --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 3
python deobfuscation-tool/cli.py infer --output deobfuscation-tool/work/lesson
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/lesson --from-stage 4
```

产物是 `transition_observations.json`、`transition_rules.json` 和 `unresolved_rules.json`。原始 JSONL 留在采集路径，归一化产物保存其路径和 SHA-256；转移观测按运行、线程、调用及来源块出现序号配对，并要求探针事件发生在该次来源块与下个块事件之间。`router_observations` 保留分发读取事件，`route.dispatch_reads` 将其关联到转移；D4 遇到读取值与写入值冲突会标记 `contradicted`。`quality` 标明缺失或歧义。

新编译的计划使用 `stack_slot_v1` 策略，支持 `SP/X29` 栈槽的 `STR/STUR` 写入及 `LDR/LDUR` 读取。计划中的 `unsupported` 明确列出没有匹配写入、同块多次写入或缺少分发读取的来源；无可用写入时命令直接报错。D4 的 `route_path` 列出静态求出的分发路径及最终目标，供 D5 审计路径上的指令。`static_proven` 表示在当前支持的指令语义和 D2 候选区域内静态推导闭合，遇到 `unknown` 条件不会给出该状态；`observed_and_static_proven` 还表示本轮采集与之吻合。它尚不代表绕过分发器安全，副作用审计属于 D5。

需要模型辅助审查时，指定一条已生成规则：

```powershell
python deobfuscation-tool/cli.py review-rules --output deobfuscation-tool/work/lesson --source 0x17e0 --use-model --model-timeout 240
```

该命令按 `config/default.toml` 启动独立、只读的 Codex CLI 任务，将该规则的指令切片和有限条观测提交给模型。模型的意见保存在 `rule_reviews.json`，可报告疑点和建议补采的指令地址；它不修改 `transition_rules.json`，也不充当静态证明。离线重放用 `--saved path/to/review.json` 替代 `--use-model`，保存文件须含与当前请求完全相同的 `request` 和已核查证据引用的 `proposal`。不同来源重复执行会在 `rule_reviews.json` 中累计，D4 规则变化时旧审查自动失效。

首版只验证 demo 的共享回跳、栈状态槽、同块条件选择和比较链。间接 `BR/BLR`、跨块状态计算、多局部分发及递归目标函数会保持未解或采集报错。D3 采集的是原始位向量与执行路径，不记录函数参数和返回值；需结合 D1 结果判断测试输入覆盖。单次采集目前覆盖一个 PID，重新采集时用新 `--run-id` 和新 JSONL 路径；`import-probes` 会以本轮文件替换旧 D3 产物。

可复现的设备验收、实际观测数量和局限见 [D3/D4 验收](D3_D4_ACCEPTANCE.md)。

## D5 补丁规划与 D6 验证

先完成 D0–D4，并确认 `stage --from-stage 4` 通过。本版 D5 使用 `arm64_direct_edges_v1`，只处理 demo 形态的入口状态写入、单后继回跳和 `CSEL → STR → B` 双后继回跳。它核对 ELF 原字节、D4 规则、分发路径指令、状态栈槽别名和目标块活跃值；无法证明安全时在 `patch_plan.json` 保留 `unresolved`，D6 拒绝实施不完整计划。

```powershell
python deobfuscation-tool/cli.py plan-patch --binary path/to/original.so --output path/to/results
python deobfuscation-tool/cli.py stage --output path/to/results --from-stage 5
python deobfuscation-tool/cli.py verify-patch --binary path/to/original.so --patched-binary path/to/results/patched.so --runner-spec path/to/runner_spec.json --output path/to/results
python deobfuscation-tool/cli.py stage --output path/to/results --from-stage 6
```

`--patched-binary` 必须与原件是不同路径；补丁只写入新文件。D6 核对输入哈希、补丁旧字节、新分支的解码目标及撤销哈希，并在 `verification_report.json` 内保存修复指令表、CFG 与逐输入差分。`stage --from-stage 6` 只有报告为 `passed` 且修复文件哈希仍匹配时通过。

Android demo 的 runner 可用 `android_runner.c` 经 NDK 编译，推送到设备后写入以下 JSON；本机实际执行示例见 [D5/D6 验收](D5_D6_ACCEPTANCE.md)。

```json
{
  "command": ["adb", "shell", "/data/local/tmp/deobf_android_runner", "{binary}", "{input}"],
  "original_binary": "/data/local/tmp/deobf_original.so",
  "patched_binary": "/data/local/tmp/deobf_patched.so",
  "inputs": [0, 1, 2, 5, 10, 30, -5],
  "timeout": 15
}
```

设备上两份库须分别对应当前原件与新生成的修复文件；runner 以独立进程加载指定库并输出 `RESULT:<整数>`。省略 `--runner-spec` 时仍可完成静态检查，但行为状态为 `not_run`，不能通过 D6 闸门。当前行为对比只覆盖返回值、退出码和标准错误；需要检查文件、网络或全局状态副作用的函数应扩展 runner 和比较字段。首版遇到未知内存操作、调用、间接跳转或其他分发结构会拒绝自动补丁，保留证据供新策略处理。

## 每阶段的维护要求

每完成一个功能或阶段，同时更新本说明的命令、适用范围和失败处理，更新开发计划中的完成状态，并留下可复现的验收结果。先运行固定测试和相应样本，再提交源码、文档和小型夹具到 Git；本地 `work/`、依赖缓存和设备原始数据不提交。
