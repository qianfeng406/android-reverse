# 按需模型诊断验收

## 实现范围

`--model-policy on_blocker` 已接入 D2 `discover`、D3 `plan-probes`、D4 `infer`、D5 `plan-patch` 和 D6 `verify-patch`。`model_policy.py` 对阶段产物分类；`model_diagnostics.py` 从相关块截取有界证据，调用独立只读 Codex CLI 或严格的离线 replay。有效提案和调用失败均保存为 `model_diagnostic_reviews.json`。提案只能包含证据引用、已登记规则 ID、请求中可用的探针地址和建议动作，不改写阶段产物。

## 验收路径

1. 固定测试覆盖 D2–D6 的触发与排除条件、无效提案拒绝、请求证据限量、离线 replay 与缓存、模型/产物错误隔离。完整测试命令：`python -m unittest discover -p 'test_*.py' -q`；66 项通过。
2. 对已保存的 `lesson_score` 真实设备产物，用不存在的 `--model-saved` 文件运行 D4、D5、D6 的 `on_blocker`。三阶段均成功，D6 保持 27 组输入一致、`stage --from-stage 6` 通过，且**没有**生成 `model_diagnostic_reviews.json`：成功路径未读取模型文件或调用模型。
3. 在忽略的 `work/experiments/model-trigger-smoke-20261123/` 中，给真实 `0x17e0` 指令表加入一条**人为构造的** D4 `unsupported_instruction` 阻塞。独立只读 `codex exec` 使用 `gpt-6-sol`、`high` 返回经验证的 `inspect` 提案，并引用该块及相应指令。模型指出人为标签缺少实际不支持指令的证据；转移规则和补丁计划未被修改。该实验只证明按需调用与证据校验通路，不证明新混淆策略已被模型解决。

## 保留边界

模型建议目前不自动应用为新规则、探针或补丁；需要分析人员审查或后续策略开发。D0/D1 的环境与采集问题不触发模型。模型不可用时确定性结果照常保存，诊断错误单独记录或报告。IDA MCP 证据适配器、自动策略登记和修复前后 trace 对比仍未接入。
