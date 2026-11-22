# D3/D4 健壮性优化记录

## 目标与实现

本轮没有扩展到所有混淆变体，重点是让首版的失败保持可见，并固定后续策略的接入位置。

| 部位 | 修改 | 保护的性质 |
| --- | --- | --- |
| D2 结构 | `DISCOVERY_STRATEGIES` 登记当前比较链识别器，原有原子证据规则仍可组合 | 新路由机制增加识别策略，保持候选及证据契约 |
| D3 计划 | `PROBE_PLANNERS` 登记 `stack_slot_v1`；解析 `SP/X29` 栈槽，匹配 `STR/STUR` 与 `LDR/LDUR`；将缺失或同块多次写入列在 `unsupported` | 变种新增规划器；现有规划器不默选错误写点 |
| D3 配对 | 探针必须落在该次来源块与下一块事件之间；区间外事件进入 `unpaired_events`；分发读取按事件区间写入 `route.dispatch_reads` | 延迟或错序事件不成为完整观测 |
| D4 证明 | `INFERENCE_STRATEGIES` 登记当前栈槽策略；条件 AST 含 `unknown` 时输出未解；计划已标记不支持的来源不能证明；分发读取与写入值冲突时标为 `contradicted`；规则保存 `state_location`，选项保存 `route_path` | 新机制可增加推导策略；未解释的状态更新不能进入后续修复准入，D5 可逐块审计分发路径 |
| 阶段依赖 | 重算计划内容哈希与 D2 选定结构 ID；新 D4 规则保存静态指令、CFG、结构及观测的输入哈希 | 旧结果不能无声地配到新输入 |
| 模型复核 | `review-rules` 可对指定规则调用只读 Codex CLI 或重放保存的回应；引用和建议采点地址均校验；请求按不同条件值抽样并附观测分布 | 审查意见独立保存，不改变规则证明状态 |

既有 D3 计划与观测仍可读取。新计划记录 `strategy=stack_slot_v1`；当前采集脚本只实现 `phase=before`，遇到其他阶段会明确失败。`unsupported` 目前是规划器的失败记录，不是已实现其他机制的声明。

## 验证

38 项回归测试包含：不受支持的条件输入不能得到 `static_proven`；`Wn/Xn` 别名写入不会被错当作未变化的输入，常量条件只保留可达分支；分发读取值冲突不能得到已核对规则；`X29/STUR` 选点；同块多次或无写入的诊断；探针落在块外的未配对；规则审查的离线重放、证据引用限制和只读模型调用；修改 D4 输入后阶段闸门拒绝过期规则。

使用同版 Android demo 在真实设备重新采集七次调用，原始文件在本机 `work/d3-opt-1.jsonl`，SHA-256 为 `aabf500fbaf728183a1e2ae66fce79f3e21d592d47733ba6c28b6920bde89deb`。计划 ID 为 `3519e84c96ed2dac6dce7552789e6d6228f6741a55a3ddb1cb8c2973204d4f1b`。采集仍为 3585 个事件；D3 得到 183/183 条完整观测、183 条关联的分发读取、0 个未配对与诊断；D4 得到 14 条规则、18 个选项、0 个未解项。七组设备返回值为 `13, 14, 14, 17, 23, 107, 17`。原始设备数据在被 Git 忽略的 `work/`，仓库测试不依赖该文件。

真实调用 `review-rules --source 0x17e0 --use-model` 后，第一轮意见促成 `state_location` 和 `route_path` 字段。针对最终规则的审查仍为 `needs_check`：模型认为奇偶条件、状态值与到达目标同观测一致，同时指出分发器还把状态复制到 `[sp]`，这项路径副作用必须由 D5 审计。模型回应没有改写 D4 规则；本机 `work/experiments/demo-d3-opt-20261122/results/rule_reviews.json` 的规则哈希与最终规则一致。审查请求按九种不同条件输入摘要采样，避免只看最先到达的重复观测。

复验命令：

```powershell
python -m unittest discover -s deobfuscation-tool -p 'test_*.py' -v
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/experiments/demo-d3-opt-20261122/results --from-stage 3
python deobfuscation-tool/cli.py stage --output deobfuscation-tool/work/experiments/demo-d3-opt-20261122/results --from-stage 4
```

## 后续扩展契约

新 D2 机制在 `DISCOVERY_STRATEGIES` 登记识别函数，保持候选和证据格式；现有原子规则只组合栈槽比较链证据。新 D3 机制增加一个规划器，输出相同的 `sources/probes/unsupported` 契约；采集器按已登记的 `strategy` 和 `phase` 执行。新 D4 机制在 `INFERENCE_STRATEGIES` 登记推导函数，指令语义必须同时给出成功与反例测试；任何不支持的表达式留在 `unresolved_rules`。D2 候选身份、D3 计划、D4 输入哈希应贯穿新策略。模型可提出审查意见或补采点，但能否证明规则仍由静态语义和动态核对决定。

当前仍待扩展：寄存器状态、跨块计算、间接 `BR/BLR`、多分发器、写后探针、调用副作用和采集性能预算。D5 将另行检查绕过指令的副作用及 patch 安全性。
