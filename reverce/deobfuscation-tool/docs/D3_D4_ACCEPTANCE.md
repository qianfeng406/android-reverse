# D3/D4 首版验收：lesson_score

## 1. 验收对象与范围

对象为 `tests/fixtures/lesson_score/libflatten_fla_android.so` 中的 ARM64 导出函数 `lesson_score`。本轮使用 D0–D2 已保存的静态指令、CFG、粗 trace 和选定结构候选，编译 13 个状态写入来源（含入口）与 18 个定点探针：13 个写前值、4 个条件输入、1 个分发读取。D3/D4 首版覆盖栈状态槽、同块 `CMP/TST → CSEL → STR` 和比较链分发。

真实采集使用 Android 设备上的 Frida server、Kali 主机的 Frida Python，以及加载同版 `.so` 的 `trace_runner_android`。测试输入依次为 `0, 1, 2, 5, 10, 30, -5`；设备返回值依次为 `13, 14, 14, 17, 23, 107, 17`。这组返回值用于对照调用执行，D3 本身未采集函数参数和返回值。

## 2. 实际执行顺序

在 `reverce` 目录运行 D0–D2 命令（见[使用说明](USAGE.md)），然后编译探针计划：

```powershell
python deobfuscation-tool/cli.py plan-probes --output deobfuscation-tool/work/experiments/demo-d2-20261122/results
```

将 `host_probe.py`、`collect_probes.js` 和 `compiled_probe_plan.json` 复制到 Kali。设备启动 runner 后记下 PID，先在 Kali 附加并等待，再触发七次函数调用。该次设备 Frida server 监听 `127.0.0.1:27142`，通过 ADB forward 和 SSH reverse forward 连到 Kali；具体端口可按实际环境替换。Kali 端采集命令为：

```bash
PYTHONPATH=/home/kali/Downloads/demo/tools/frida-python python3 /tmp/d3_tool/host_probe.py --device 127.0.0.1:27142 --pid 7828 --script /tmp/d3_tool/collect_probes.js --plan /tmp/d3_tool/compiled_probe_plan.json --module libflatten_fla_android.so --symbol lesson_score --run-id d3-live-3 --output /tmp/d3_tool/d3-live-3.jsonl
```

将原始 JSONL 复制回本地 `work/live-d3-3.jsonl`，导入并推导：

```powershell
python deobfuscation-tool/cli.py import-probes --capture deobfuscation-tool/work/live-d3-3.jsonl --output deobfuscation-tool/work/experiments/demo-d2-20261122/results
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/experiments/demo-d2-20261122/results --from-stage 3
python deobfuscation-tool/cli.py infer --output deobfuscation-tool/work/experiments/demo-d2-20261122/results
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/experiments/demo-d2-20261122/results --from-stage 4
```

这些原始设备记录与生成产物保留在本机被 Git 忽略的 `work/` 中；仓库内回归测试使用可重建的小型夹具，干净克隆不依赖设备记录。

## 3. 产物检查

| 检查项 | 实测结果 |
| --- | ---: |
| 原始 JSONL 事件 | 3585 |
| 完整目标调用 | 7 |
| 来源块逐次观测 | 183 / 183 完整 |
| 分发状态读取事件 | 183 |
| 未配对事件、采集诊断 | 0、0 |
| D4 来源规则 | 14（入口 1、业务状态写入 12、返回 1） |
| 静态转移或返回选项 | 18 |
| 四个双后继来源 | 每处两个选项均有动态观测 |
| 未解规则 | 0 |

入口原始 Stalker 块从 `0x160c` 开始，落在静态入口块 `0x15fc–0x1620` 内。采集前还出现模块外的绝对地址块。D3 仅将首个**目标模块**块映射到入口，避免模块外事件抢占配对。入口后 Stalker 报告的下一个块是 `0x1638`，静态 CFG 则先从 `0x15fc` 落到 `0x1620`；D4 具体求值证明 `0x1620` 的条件不跳转、随后落到 `0x1638`，才接受这条观测。其他不匹配的后继仍保留未解。

例如 `0x17e0` 的两条静态规则：条件输入最低位为 0 时写入 `0x81fc94e6`，经分发到 `0x1804`；否则写入 `0xe6e37d04`，经分发到 `0x182c`。两条在七次调用的重复执行中都被观察到。`transition_rules.json` 中它们是 `observed_and_static_proven`；这只证明当前语义策略与观测一致，尚未审计绕过分发器时的副作用。

## 4. 回归与边界

运行 `python -m unittest discover -s deobfuscation-tool -p 'test_*.py' -v`。D3 测试覆盖同调用重复来源、入口块内部起点、模块外块、探针缺失和嵌套错误；D4 测试覆盖两支静态推导、观测冲突、错误目标、入口及返回；端到端测试从 D0–D2 产物经 `plan-probes → import-probes → infer → stage 4` 走通命令边界。

本轮结果只针对该 demo 和这七组输入。返回规则目前由静态 `RET` 得到，未与 D3 返回值观测绑定。间接跳转、跨块状态计算、多分发器和混合块不在本轮已证明范围；D5 副作用审计、patch 计划和修复后差分验证尚未开发。
