# D3 定点采集与 D4 转移推导设计

**状态：设计完成，尚未实现。** 两阶段共用一份带版本的数据契约：D3 保存每一次实际转移的观测事实，D4 在这些事实和静态指令上推导条件与目标。D3 不猜公式；D4 不把一次观察当作全输入证明。

## 1. 边界和交接

| 阶段 | 输入 | 核心工作 | 输出 | 不负责 |
| --- | --- | --- | --- | --- |
| D3 定点采集 | D0 指令/CFG、D1 原始 trace、D2 `structure_candidates`/`probe_plan`、本轮测试输入 | 编译探针计划；在**同一次调用**中记录条件输入、状态写入、跳转目标和块序列；逐次配对并规范化 | `probe_events.jsonl`（原始）、`transition_observations.json`（统一模板）、`capture_diagnostics.json` | 判断未执行分支的条件公式；宣布某条边可 patch |
| D4 转移推导 | D0 静态数据、D2 候选、D3 统一观测 | 按指令语义反向切片，求条件、状态表达式和分发映射；逐条核对观测与反例 | `transition_rules.json`、`unresolved_rules.json` | 写入二进制；证明绕过指令没有副作用（D5） |

交接规则：所有产物使用同一个 `binary_id`、函数范围和版本号。D3 新运行的探针与块事件必须共享 `run_id + thread_id + invocation_id`；**不能**把新探针值按“输入相同”拼接到旧 D1 trace。旧 trace 只用于选点和覆盖对比。若某次调用缺少块事件、探针事件或终止标记，D3 输出明确缺失原因，D4 不把它当作完整的已观察转移。

## 2. 统一的 D3 观测模板

一条 `transition_observation` 对应“某次调用中某个来源块的**一次出现**”，不是一个来源块的汇总。根对象沿用 D0 的 `schema_version`、`kind`、`binary_id`、`data` 包装。`data` 包含 `function`、`structure_id`、`plan_id`、`capture_ids`、`records`、`unpaired_events` 和 `diagnostics`。`structure_id` 是选定 D2 候选及其规则配置的哈希；`plan_id` 是包含该 `structure_id` 的规范化探针计划哈希。这样模型或规则改变候选、探针改变位置时，旧采集不会被误配到新计划。

每个 `record` 固定使用下表字段；适用性不同的字段填 `null` 并写明原因，不为间接跳转另造一套 JSON 格式。

| 字段 | 含义 |
| --- | --- |
| `id` | `run_id/thread_id/invocation_id/source_block/source_ordinal` 组成的稳定实例标识 |
| `origin` | 来源块、入口块、该块在本次调用中的出现序号、原始 block 事件引用 |
| `decision` | 条件指令地址；执行该指令**之前**读取的寄存器/内存输入、位宽及可选标志位；无条件转移则为 `null` |
| `transfer` | 带类型的事实：`state_write`、`direct_branch`、`indirect_branch`、`call_return_target` 或 `unknown`；包含写入/跳转指令、数据来源位置、执行时值与位宽 |
| `route` | `immediate_successor`、经过的分发块事件引用、`eventual_target`、目标所属模块与匹配状态；两种后继分别记录 |
| `quality` | 哪些采值、块序列、调用边界完整；是否丢事件、配对有歧义、命中未验证的混合块 |
| `evidence` | 原始探针行、D1 同轮块事件、D0 指令和 D2 候选的引用，不用推断覆盖原始值 |

所有机器值使用 `{ "width": 32, "hex": "0x00000002" }` 这类定宽位向量表示；有符号解释是**附加视图**，不改变原始比特。地址统一表示为 `{binary_id, module_offset}` 或明确的其他模块地址。寄存器名使用执行时实际宽度（`w8`/`x8`）；内存位置同时保留相对表达式和本次调用的实际地址，避免不同栈帧混淆。D3 内存位置规范为 `sp+0x4`、`sp+0x10` 等显式十六进制；计划编译器负责把 D2 当前的 `sp+4`、`sp+10` 形式转换过来，避免把后者误读成十进制偏移。

以下是**未来采集记录的格式示例，并非本次 D2 已有的真实探针数据**：

```json
{
  "id": "r1/9319/1/0x17e0/3",
  "origin": {"source_block": "0x17e0", "source_ordinal": 3, "block_event_ref": "trace:r1:9319:1:104"},
  "decision": {"site": "0x17f4", "phase": "before", "values": {"w8": {"width": 32, "hex": "0x00000002"}}},
  "transfer": {"kind": "state_write", "site": "0x17fc", "location": "sp+0x4",
               "value": {"width": 32, "hex": "0x81fc94e6"}},
  "route": {"immediate_successor": "0x18f8", "eventual_target": "0x1804",
            "target_status": "observed_candidate_boundary", "path_refs": ["trace:r1:9319:1:105"]},
  "quality": {"complete": true, "missing": [], "ambiguous": false},
  "evidence": ["probe:r1:9319:1:17", "probe:r1:9319:1:18", "insn:0x17f4", "insn:0x17fc"]
}
```

`eventual_target` 的赋值依赖 D2 的候选区域边界：沿**同一次调用**的块序列，从本次来源块出发，越过已标记的路由区域，取第一个执行入口。若路由跨区、候选区域混有业务指令、发生调用/异常或多个入口都可能配对，则值为 `null`、`target_status=unresolved`；绝不静默选择最近的地址。这里得到的是动态到达目标，不是已证明的静态后继关系。

### 类型扩展，而非按样本改模板

- `state_write`：记录写前的源寄存器值、写入位置与位宽；可选写后读回用于核验。固定状态、条件选择、编码状态都用此型，公式由 D4 求。
- `direct_branch`：记录分支指令、条件输入与实际目标；没有状态槽时仍适用。
- `indirect_branch`：在 `BR Xn` 前记录 `Xn` 和实际目标地址，保留目标寄存器的静态定义引用。
- `call_return_target`：分别记录调用点参数、返回点寄存器值和后续地址计算。调用副作用未知时标记未解，不把函数返回值硬说成常量。
- `unknown`：保存原始值与未支持原因，让新策略可重放处理，不丢弃样本。

## 3. D3 的执行流程

### 3.1 扩展并编译探针计划

D2 当前的 `probe_plan` 给出四处 `condition_at` 和 `state_write_at`，但 D3 不能只采这四处。它要从 `structure_candidates.state_writers` 与 D0 指令表自动补齐其余**八个无条件状态写入块**、入口的初始状态写入、分发入口对状态的读取；若存在间接转移，再补 `BR/BLR` 前的目标寄存器。探针计划成为独立版本化产物，包含 `site`、`phase=before/after`、需读取的寄存器或内存、所归属的来源块和预计开销。模型可建议新采点，但必须经指令范围、可读取性与证据引用校验。

首版 demo 的关键采值时刻：在 `CMP/TST` **之前**取条件输入；在 `STR [sp,#4]` **之前**取将要写入的源寄存器；若需要确认落盘值，则在写后另设读回点。仅记录 `CSEL` 结果不能解释其条件，仅记录 `CMP` 也不知道实际选择了哪个状态。

### 3.2 同轮采集和逐次配对

扩展现有 Frida/Stalker 采集器，在一个跟踪会话中同时保留 D1 的 block/call/ret 事件和选定指令的定点值。只在目标函数/地址集命中时采值；不对整个线程逐指令打印。每个来源块入口分配 `source_ordinal`，条件和写入探针附到同一实例。Frida 消息可能延后交付，**不能仅靠消息抵达主机的顺序配对**；使用调用 ID、来源序号、探针点和块事件锚点。重复命中、嵌套调用、线程切换或丢包都应有显式诊断。

当前 D1 把第一个参数和返回值按 `int32` 记录。D3 采值层先保留原始位宽，再由可配置函数签名给出有符号/无符号解释；未知签名不妨碍记录原始比特。若采集影响目标应用稳定性，可减少探针、限定一次调用或输入组，但必须保存所用配置与未覆盖范围。

### 3.3 归一化与阶段闸门

规范化器按实例输出统一模板，并核对：同一二进制、同一函数、探针地址在指令表中、一次来源出现至多一个完整条件/写入组、块序列属于同一调用、值的位宽合法。一个实例可以 `quality.complete=false`，但不得伪造缺失的状态或目标。D3 阶段校验要求产物格式与所有调用可追溯；**不要求所有分支都已覆盖**。缺失分支交给 D4 静态推导或下一轮 D3 输入设计。

## 4. D4 的执行流程

### 4.1 统一内部表达式

D4 从 D0 指令和 D3 观测构建带位宽的表达式 AST：常量、寄存器/内存读取、算术/位运算、比较、条件选择 `ite`、地址计算。主要输出 AST；可读的汇编式文本只是展示字段。所有计算遵守 ARM64 对应位宽的截断和有符号比较语义，例如 `W` 寄存器是 32 位，`LT/GT` 使用有符号条件，`TST` 更新标志。没有支持的指令或跨块定义时，切片停在 `unknown`，不能用某次运行的值冒充普遍常量。

首版策略覆盖 demo 的 `MOV/MOVK` 常量拼接、`LDR/STR` 栈槽、`CMP/TST/SUBS` 标志、`CSEL`、直接条件分支和比较链分发。策略接口统一为 `infer(source, static_slice, observations, structure) -> alternatives + unresolved`；后续的间接地址、调用返回、编码状态增加语义策略，不改 D3 模板。

### 4.2 从状态写入推到执行目标

对每个来源块：从状态写入或目标寄存器反向切片，求条件及每条路径的状态/地址表达式；再从 D2 分发区域的读取点追比较、别名与跳转，建立“状态值 → 执行入口”映射。需要检查别名写入确实传递同一位宽的状态，以及比较链的有符号/无符号关系。状态映射冲突、没有匹配 case、间接目标未解，均输出 `unresolved`。D3 的每条观测用来核对表达式求值与目标，**不**承担枚举所有条件的责任。

以 `0x17E0` 为例，静态切片应导出两条候选规则：`(value & 1)==0` 时写 `0x81FC94E6` 并经分发器到 `0x1804`；否则写 `0xE6E37D04` 并到 `0x182C`。D3 对某次 `value=2` 的记录只能验证前一条在该次调用成立；另一条的存在来自静态条件选择与分发表，而不是“没看到就不存在”。

### 4.3 规则产物与证明状态

`transition_rules.json` 的每条来源记录包含 `source_block`、`transfer_kind`、`alternatives`、`coverage`、`evidence`、`unresolved`。每个 alternative 使用固定字段 `guard_ast`、`state_ast`（不适用为 `null`）、`target_ast`/`target_block`、`observation_ids`、`instruction_refs`、`status`。状态沿用现有 `observed`、`static_proven`、`observed_and_static_proven`、`unresolved`，另有冲突记录 `contradicted`，后者绝不能进入 D5。

同样以 `0x17E0` 为例，未来的 D4 记录形状如下（地址和值来自静态样本，`observation_ids` 仅示意；**尚未运行 D4**）：

```json
{
  "source_block": "0x17e0",
  "transfer_kind": "state_write",
  "alternatives": [
    {"guard_ast": {"op": "eq", "width": 1,
                    "args": [{"op": "and", "width": 32,
                              "args": [{"op": "load", "width": 32, "location": "sp+0x10"},
                                       {"op": "const", "width": 32, "hex": "0x00000001"}]},
                             {"op": "const", "width": 32, "hex": "0x00000000"}]},
     "state_ast": {"op": "const", "width": 32, "hex": "0x81fc94e6"},
     "target_ast": null, "target_block": "0x1804",
     "observation_ids": ["r1/9319/1/0x17e0/3"],
     "instruction_refs": ["insn:0x17f4", "insn:0x17f8", "insn:0x17fc"],
     "status": "observed_and_static_proven"},
    {"guard_ast": {"op": "ne", "width": 1,
                    "args": [{"op": "and", "width": 32,
                              "args": [{"op": "load", "width": 32, "location": "sp+0x10"},
                                       {"op": "const", "width": 32, "hex": "0x00000001"}]},
                             {"op": "const", "width": 32, "hex": "0x00000000"}]},
     "state_ast": {"op": "const", "width": 32, "hex": "0xe6e37d04"},
     "target_ast": null, "target_block": "0x182c",
     "observation_ids": [], "instruction_refs": ["insn:0x17f4", "insn:0x17f8", "insn:0x17fc"],
     "status": "static_proven"}
  ],
  "coverage": {"normal_exits_static": 2, "alternatives_observed": 1,
               "guards_disjoint": true, "guards_exhaustive": true},
  "evidence": ["insn:0x17f4", "insn:0x17f8", "insn:0x17fc"],
  "unresolved": []
}
```

`static_proven` 至少要求：条件路径在支持的指令语义内可推导、候选分发区域中的状态传递可闭合、目标唯一、替代分支的条件互斥且覆盖来源块所有正常出口。`observed` 只说明某次调用走过该目标；即使重复千次也不能升级为静态证明。`observed_and_static_proven` 还要求所有相关 D3 观测与公式一致。副作用是否可以安全绕过仍交给 D5，不能由此状态自动推出。

`unresolved_rules.json` 保存失败位置、未支持指令/调用、冲突观测、缺失探针和建议补采点。模型仅可基于这些缩小的切片建议采集点或新策略；新策略经固定夹具回归后才能用于推断。

## 5. D3+D4 联合开发顺序与验收

两阶段**共同定稿模板、一起实现纵向样本**，不先写一个随意的 D3 JSON 再让 D4 适配。建议按以下顺序开发：

1. 固定上述 JSON Schema、值/地址/证据规范和一个手工构造的记录夹具；先让 D4 读取该夹具，验证模板能表达条件、状态、立即回跳和最终目标。
2. 实现 D3 探针计划编译与同轮采集，先采 `lesson_score` 的四个条件写入点及其块序列，再补八个无条件写入点和初始状态。
3. 实现规范化器与故障夹具：少一个条件事件、写入值不匹配、同一来源重复、模块地址碰撞、调用跨线，都必须保留明确诊断。
4. 实现 D4 的 ARM64 最小语义和比较链映射；每增加一种指令语义，直接用 D3 规范记录做端到端回归。
5. 用 demo 的七组输入重新采集，生成 `transition_observations` 和 `transition_rules`；保存原始证据、未解项及覆盖报告。在线模型建议保存在独立提案文件，不成为测试真值。

demo 的联合验收：四个条件状态块各有两种分支观测且能逐次配对；八个单状态写入块、入口初始化和返回端得到相应记录；D4 给出四处双后继及八处单后继的静态规则，并能与七组输入核对。故意删除一条探针记录、篡改一个状态值或引入未知指令时，不得输出伪确定规则。D3 的采集开销与丢事件数要记录，但不以有限输入的 8/8 已观察出口代替静态完整性证明。

## 6. 首版能力边界

首版只承诺 demo 所需的共享回跳、栈状态槽、同块 `CMP/TST → CSEL → STR` 和比较链。方案中的 `indirect_branch`、`call_return_target` 类型先保证能存放原始事实；对应静态推导可保持 `unresolved`，在增强阶段加入专用策略。多局部分发、跨块状态更新与混合块不能为了得到简洁 CFG 被强行折叠。D5 只接收有明确条件与目标、且后续通过副作用审计的规则。
