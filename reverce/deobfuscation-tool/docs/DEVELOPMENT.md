# 控制流反混淆工具开发文档

## 目标与首版范围

工具从目标函数的静态指令和多次运行 trace 中恢复可解释的条件转移关系，生成有证据、可撤销的修复方案，并验证修复前后的行为。首版只实现 Android ARM64 `lesson_score` 的状态变量与比较链分发器。间接 `BR`、跨函数目标计算、多分发器和混合块通过同一接口逐步加入策略。

首版完成的标准不是“看起来像原始 CFG”，而是每条拟修复边都有条件、目标、静态依据、动态观测和对待跳过指令副作用的检查结果。

## 统一数据约定

地址使用 `binary_id + module_offset`；`binary_id` 来自样本哈希。一次采集使用 `run_id + thread_id + invocation_id` 区分调用，事件使用单调递增的 `event_index` 排序。所有阶段保留来源事件或指令地址，不把推断覆盖到原始证据上。

D3 的单次观测与 D4 的转移规则使用不同但衔接的统一模板；字段、位宽表达式及 JSON 示例以 [D3/D4 详细设计](D3_D4_DESIGN.md) 为准。规则状态区分 `observed`、`static_proven`、`observed_and_static_proven`、`unresolved` 和 `contradicted`。动态观察只证明该次输入走过此边；静态证明需包含路径条件和状态分发推导。证据不足的规则可以交接给下一轮采集，但不能进入自动修复。

## 阶段及交接内容

| 阶段 | 目的与处理 | 输入 | 输出与进入下一阶段的条件 |
| --- | --- | --- | --- |
| 0 分析基准 | 固定样本版本，导出函数范围、指令及静态 CFG | 二进制、目标函数 | `binary_manifest`、`instruction_table`、`static_cfg`；哈希与运行样本一致 |
| 1 粗粒度采集 | 对多组输入记录块执行顺序、调用与返回边界、结果 | 阶段 0 的目标地址与测试输入 | `raw_trace`；事件可按调用和线程准确排序 |
| 2 结构发现 | 对齐动态与静态块，提出分发器、状态位置和回跳区域候选并校验数据流 | 静态 CFG、指令、`raw_trace` | `structure_candidates`、`probe_plan`；每个候选附证据和反例 |
| 3 定点采集 | 按采集计划记录条件输入、状态读写、间接目标与实际后继 | `probe_plan`、测试输入 | `transition_observations`、静态切片引用；记录可逐次配对 |
| 4 转移推导 | 求条件、状态表达式及分发目标，核对观测并标记未解规则 | 静态切片、结构候选、转移观测 | `transition_rules`；拟修复规则须有明确条件和目标 |
| 5 修复规划 | 检查副作用、可用指令空间和分支编码，生成可撤销修改 | 已证明规则、原始指令 | `patch_plan`；每项包含旧/新指令、依据及撤销信息 |
| 6 实施验证 | 执行计划，比较修复前后的行为和 trace，失败时撤销 | `patch_plan`、原始样本、测试输入 | 修复结果、差分报告、仍未解决的规则 |

上表保留最初的阶段目标。当前 D6 首版完成二进制副本修改、静态 CFG 重建、撤销哈希试验，以及指定输入的返回值、退出码和标准错误对比；**尚未采集并比较修复前后的 trace，也没有在行为失败后自动撤销修复副本**。D5/D6 已在 demo 设备上验证，完整设计仍有待实现的部分，详见 [开发计划](ROADMAP.md)。

### 阶段 1 到阶段 2

现有 `../../demo/scripts/trace_lesson_score.js` 仅打印目标范围内的 Stalker 块起点、输入和返回值。它足以制作观察图，但过滤掉范围外事件，也没有保存块终点或调用/返回信息，因此日志里相邻的两个块未必是直接 CFG 边。正式采集格式需保留原始事件或足够重建调用边界的数据。现有 `../../demo/scripts/build_trace_graph.py` 已能根据七次运行生成观察图，并在提供结构锚点时折叠分发路径；它尚不自动发现这些锚点。

阶段 2 先用图特征提出候选，再由静态数据流核查：回边和多来源汇入、反复读取同一状态位置、比较或间接地址计算、其他块写入该状态位置。频率不能单独证明分发器身份；真实循环也可能反复执行。混合块按指令作用区分计算与路由，不能整块贴单一标签。

当前 D2 首版在 `DISCOVERY_STRATEGIES` 登记 `stack_comparison_chain_v1`，内部实现可选的原子证据规则。它以多来源汇入点为候选，要求多个前驱块写同一状态槽，并在可达分发区域读该槽或同块复制出的别名、执行比较分流；还要求 trace 中该候选重复出现。输出 `structure_candidates`、观察图和 `probe_plan`；后者目前只覆盖同一块内条件比较、条件选择和状态写入。所有候选保留 `hypothesis` 状态，不等同于已证明业务边。`--use-model` 保存独立只读提案，并可通过 `rule:<规则名>` 选择可选证据规则；核心规则不可由模型关闭，结构结果仍由规则引擎生成。

D3 的计划编译通过 `PROBE_PLANNERS` 登记采集策略；当前 `stack_slot_v1` 负责栈槽读写，后续寄存器状态和间接目标可加入新规划器。D4 通过 `INFERENCE_STRATEGIES` 选择相应推导函数；未知策略明确输出未解。计划中的 `unsupported` 是按来源块列出的明确失败事实，不能被 D4 解释为成功采集。D4 符号解释器中无法解释的条件节点会阻止静态证明；分发读取观测若与写入值矛盾，相关规则标为 `contradicted`。规则还保存静态指令、CFG、D2 结构与 D3 观测的输入哈希，阶段闸门据此检测过期结果。

### 阶段 2 到阶段 4

D3 与 D4 的联合数据契约、采集配对方法、表达式推导和验收条件见 [D3/D4 详细设计](D3_D4_DESIGN.md)。demo 首版及真实设备结果见 [验收记录](D3_D4_ACCEPTANCE.md)。

`probe_plan` 由候选结构和反向切片生成。固定回跳的样本从分发器所读状态反查写入，再追条件选择；`BR Xn` 从目标寄存器反查定义；调用返回值参与目标计算时追调用参数、返回寄存器及后续运算。策略无法解释切片时输出未解决项，可由大模型提出新策略，再由工具校验。

阶段 3 记录运行值，不声称覆盖未执行分支。阶段 4 以静态表达式求所有可行条件和目标，用阶段 3 的记录核对。例如 `0x17E0` 的 `TST/CSEL/STR` 可导出奇偶两种状态及目标；仅有两条运行记录不足以证明规则完整。阶段 4 是通用推导调度器加可扩展语义策略，不是对日志重新排版。

### 阶段 4 到阶段 6

阶段 5 只接受已证明且可安全绕过分发代码的转移。当前 `arm64_direct_edges_v1` 审计分发路径内的指令、栈状态别名和目标活跃输入，核对 ELF 旧字节后为入口、单后继和双后继生成 `patch_plan.json`。调用、间接跳转、未知内存影响或模板不符会留在未解项。计划不直接写文件；详情见 [D5/D6 设计](D5_D6_DESIGN.md)。

阶段 6 在副本上执行计划，核对每条新分支的解码目标，重建 CFG，验证撤销哈希，再按 runner 规范比较原件和副本的返回值、退出码及标准错误。修复指令表、CFG、逐输入结果和检查状态保存于 `verification_report.json`；有限输入通过不等于对所有输入的形式化等价证明。需要检查外部副作用时扩展 runner 和比较字段。设备验收见 [D5/D6 验收](D5_D6_ACCEPTANCE.md)。

## 模块边界

| 模块 | 职责 |
| --- | --- |
| `collect` | Frida 采集与原始事件存档 |
| `normalize` | 地址、指令和 Stalker 块边界对齐 |
| `discover` | 图特征、状态读写和分发器候选 |
| `probe` | 定点采集计划与结构化观测 |
| `infer` | 条件表达式、目标推导和证据校验 |
| `plan` | 修复安全检查与可撤销方案 |
| `verify` | 差分运行、trace 核对和失败反馈 |
| `strategies` | 分发器识别、跨块溯源、间接跳转与修复模板 |

大模型通过候选规则和诊断报告接入。它可以提议识别区域、采集点或新策略；输出必须符合阶段数据格式，并接受静态、动态及回归验证。大模型的判断本身不是证明状态。

## 大模型接入接口

模型是可选的**提案提供者**，不直接修改 trace、CFG 或二进制。D2 的 `ModelAdapter.propose(request) -> proposal` 提出结构候选；D4 的 `review-rules` 针对单条规则提出疑点和补采建议。另有 D2–D6 的 `--model-policy on_blocker`：仅在确定性阶段分类出可分析阻塞时保存只读诊断。提案可离线重放，不改写证明、补丁和验证状态。请求只传有限的图、指令及观测切片，不把整份原始日志放进上下文。

模型不属于固定必经阶段。已知模式无阻塞时 D0–D6 可全程不调用模型；未知结构、未解语义或难以解释的验证差异才适合按需请求提案。现有调用与未来触发规则的边界见 [模型介入设计核查](MODEL_INTERVENTION_DESIGN.md)。

请求与响应都使用带版本号的 JSON Schema。最小契约：

```json
{
  "request": {
    "schema_version": 1,
    "task": "structure_hypothesis",
    "binary_id": "<sha256>",
    "scope": {"function": "0x15fc"},
    "evidence_refs": ["graph:edge:0x18f8->0x1620", "insn:0x1620"],
    "facts": {"observed_backedge_count": 176}
  },
  "proposal": {
    "schema_version": 1,
    "kind": "dispatcher_candidate",
    "region": ["0x1620", "0x175c"],
    "state_location": "stack:sp+4:u32",
    "supporting_refs": ["graph:edge:0x18f8->0x1620", "insn:0x1620"],
    "checks_requested": ["find_state_writers", "check_region_side_effects"]
  }
}
```

模型提案先过 Schema、地址范围和引用存在性校验，再由图算法、数据流分析和动态记录核查。模型给出的“置信度”不作为通过条件；校验失败保存反例和原因，交给下一轮提案或标为 `unresolved`。每次调用保存模型适配器、模型标识、请求摘要、提案和验证结果；相同请求可用保存的提案重放回归测试。

当前实现 `replay` 和 `codex_exec`：前者读取固定提案，用于离线测试；后者调用本机 Codex CLI 的非交互模式，在只读工作区输出符合 Schema 的 JSON。`responses_api` 是后续运行时后端计划，尚未实现。默认配置在 [`config/default.toml`](../config/default.toml)：模型 `gpt-6-sol`，推理强度 `high`。`replay` 不发起模型调用。

`codex_exec` 的进程退出码、超时、拒绝、非 JSON 输出和 Schema 不匹配都作为明确错误处理。未来的 `responses_api` 需要独立配置 API 凭据；不假设当前 Codex 对话或桌面登录会自动变成 API 凭据。需要持久会话和流式工具交互时，可增加 Codex SDK 或 app-server 适配器。

`codex_exec` 的调用形态如下；实际命令由适配器以参数数组启动，提案 Schema 和提示词由工具生成。它启动一次独立的 Codex 任务，不继承当前聊天上下文。

```text
codex exec -C <analysis-workdir> -s read-only -m gpt-6-sol -c 'model_reasoning_effort="high"' --output-schema <proposal.schema.json> -o <proposal.json> -
```

官方接口依据：[Codex 非交互模式](https://learn.chatgpt.com/docs/non-interactive-mode)、[Codex SDK](https://learn.chatgpt.com/docs/codex-sdk)、[OpenAI 结构化输出](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses)。

IDA MCP 可作为可选的**只读证据适配器**：工具先用它或 IDAPython 导出目标函数的指令、块和引用，再压缩为上述模型请求。模型对 IDA MCP 的直接访问不作为流水线前提；这样每次分析仍可凭保存的证据重放。实际修复由阶段 5–6 的规划器与执行器负责，模型接口不包含 `patch` 或写入命令。

## 首个纵向里程碑

分阶段的开发任务与验收标准见 [开发计划](ROADMAP.md)。

1. 迁入并规范现有采集与建图原型，保留原始实验数据不变。
2. 自动提出 `lesson_score` 的状态位置、回跳块与分发区域候选，并输出可审阅证据。
3. 自动生成 `0x1760`、`0x17BC`、`0x17E0`、`0x188C` 的定点采集计划。
4. 采集条件值和状态值，推导该函数的完整条件转移表。
5. 输出修复计划，在 IDA 中验证 CFG 和多组输入行为。

每步完成后以其数据产物作为下一步输入；遇到未解规则时保留证据并进入策略迭代，不用猜测结果填补接口。

## 版本管理

本目录位于现有 `android-reverse` Git 仓库内。开发文档、工具源码、可重复的小型测试夹具纳入版本控制；设备日志、构建缓存和 IDA 数据库留在本机，按需单独管理。`reverce/` 中其他目录可能包含未跟踪文件，提交时只暂存 `deobfuscation-tool/`。仓库内 `tests/fixtures/lesson_score/` 提供独立运行的测试夹具。
