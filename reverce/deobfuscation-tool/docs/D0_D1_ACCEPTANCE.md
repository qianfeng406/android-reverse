# D0 和 D1 开发验收记录

## 范围与结论

D0 的 CLI、配置读取、版本化产物校验、证据引用和提案重放，以及 D1 的 ARM64 静态导出、旧日志导入与新 Frida 采集已实现。D2–D5 尚未开发；当前 `stage` 命令只验证保存的阶段输入，不运行后续分析。

## 离线验收

在仓库 `reverce` 目录运行：

```powershell
python -m unittest discover -s deobfuscation-tool -p test_tool.py -v
```

9 项测试通过，覆盖真实 demo 的 CLI `init → static → import-legacy → stage`、产物缺失/版本不符/损坏地址拒绝、截断反汇编拒绝、关键静态 CFG 边、`TBZ/TBNZ` 目标解析、`BL/BLR` 边界、两份新版采集导入合并，以及自定义配置下的提案重放。

同版本 `lesson_score` 静态导出得到 192 条 ARM64 指令、42 个基本块；`0x18F8 → 0x1620`、`0x17E0 → 0x18F8` 和 `0x1620 → 0x1804` 均存在。旧日志导入得到 7 次调用、2834 个目标函数块事件；旧日志缺少的块终点、线程/调用 ID 和 call/ret 事件保持缺失标记。

## 真实设备采集

2026-11-21 使用已安装 demo 的 Android 设备和 Kali `192.168.24.142`。设备和本地 `libflatten_fla_android.so` 的 SHA-256 均为 `255012def2298be947eae9ba5177e06d41f7f1a6ff5f8fa6b195bf3b18ee6888`。设备端 `hluda-server` 为 17.17.0；Kali 通过本机 SSH 反向转发连接设备 Frida server。新版 `collect.js` 和 `host_collect.py` 完成一次七组输入的真实采集，调用程序返回：

```text
0→13, 1→14, 2→14, 5→17, 10→23, 30→107, -5→17
```

采集文件共 3072 条 JSONL 记录：7 条 enter、7 条 leave、2988 条 block、35 条 call、35 条 ret。目标模块内有 2834 条 block 事件、40 种块起点，与旧日志的目标函数块总数相符。新日志的首个目标函数块含起点 `0x160C` 和终点 `0x1638`。`import-capture` 和 `stage --from-stage 1` 对这份真实采集均成功。采集文件保存在本地 `deobfuscation-tool/work/live-d1-1.jsonl`，规范化产物在 `deobfuscation-tool/work/live-artifacts/`；两者属于本地实验数据，不纳入 Git。

## 已知边界

- 静态导出目前要求 ELF 中有带大小的目标函数符号，以及覆盖完整符号范围的同版本反汇编。
- 新采集器以本地二进制哈希标注目标模块地址；设备文件与本地文件的 SHA-256 仍需在采集前核对。此次实测已核对。
- 同一线程的目标函数递归调用会明确报错；复杂嵌套调用不在 D1 支持范围内。
- D1 保存执行证据，不识别分发器或推导真实后继；这些属于 D2–D4。
