# route_score：第二个平坦化实验样本

`route_score(int32_t)` 含负数处理、两轮不同长度的循环、嵌套条件及三种返回路径。所有计分运算使用 `uint32_t`，避免有符号溢出导致对照结果不稳定。同库的 `route_identity` 独立编译，不经过 OLLVM pass；平坦化只施加到 `route_score` 所在的 IR 模块。

在已配置经典 OLLVM 的 Kali 环境执行：

```bash
bash build.sh /tmp/route-score-build
```

默认读取 `/home/kali/Downloads/demo` 中的 LLVM 4 OLLVM `opt`、Clang 11 和 Android sysroot。可通过 `OLLVM_DEMO_ROOT` 指定另一位置。脚本生成 Android ARM64 未混淆与 `opt -O0 -fla` 版本、反汇编、IR、行为 runner 和 trace runner。每次构建的随机状态常量可能不同；分析时必须让 ELF、反汇编和设备库来自**同一次构建**。

`runner` 接收 `库路径 输入整数` 并输出 `RESULT:<值>`。`trace_runner` 固定加载设备上的 `/data/local/tmp/libroute_fla.so`，打印 PID 后等待 Enter，再执行九组输入，便于先附加 Frida。完整独立工具实验见 [泛化测试记录](../../docs/GENERALIZATION_ROUTE_SCORE.md)。
