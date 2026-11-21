# D0 和 D1 使用说明

## 当前工具能做什么

D0/D1 可为一个 **ARM64 ELF `.so` 中的已知函数**建立静态指令与 CFG，采集该函数一次调用期间执行线程的 Stalker block/call/ret 事件，并将多次运行归一化到同一二进制偏移。它还不会识别分发器、推导真实业务边或自动 patch；这些属于 D2–D5。

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
python -m unittest discover -s deobfuscation-tool -p test_tool.py -v
```

成功后输出目录包含 `binary_manifest.json`、`instruction_table.json`、`static_cfg.json` 和 `raw_trace.json`。`stage --from-stage 1` 只验证这些已保存的输入，不会运行尚未实现的 D2。旧 trace 缺少的线程、调用和块终点字段保持缺失标记。

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

## 每阶段的维护要求

每完成一个功能或阶段，同时更新本说明的命令、适用范围和失败处理，更新开发计划中的完成状态，并留下可复现的验收结果。先运行固定测试和相应样本，再提交源码、文档和小型夹具到 Git；本地 `work/`、依赖缓存和设备原始数据不提交。
