# dsh-arch · 架构插件（终端执行架构）

把「跑一个任务」固定成四层架构，每一层的动作都落在系统终端里：

```
规划层  plan       把任务拆成有序步骤（标题 / cwd / 期望）
   ↓
执行层  exec       每个步骤 = 一条系统终端命令（powershell / cmd / bash），真起子进程
   ↓
校验层  verify     退出码 / 输出正则（expect），失败即判红；allowFail 降级为警告
   ↓
回执层  receipt    回执落盘 + 每步完整终端日志，可复查、可重放
```

- 不经过模型：`arch_run` 一旦受理，后续流程全部由插件自己的终端执行器推进。
- 不依赖任何第三方包：纯 Node ESM，零外部依赖。
- 终端输出直接写日志文件（见「边界与实测坑」），回执与日志都在磁盘上。

## 工具

| 工具 | 作用 |
| --- | --- |
| `arch_run` | 提交一个任务计划并在系统终端里执行；`background: true` 立即返回 id |
| `arch_flow` | 多角色 + 终端执行的固定阵型（拆分→路径→对抗性复核（只读·红队·极具攻击性）→规划→隔离→修改→工作→多方验证）；默认 `sessionPolicy: "spawn"`：角色子会话由插件现创建（子对话强隔离），强约束全部写死在插件底层；对抗性复核久议不决时可向下分发自己的子智能体（同样强隔离/只读/必交回执） |
| `arch_status` | 查一次运行的回执（省略 id 时列出最近运行） |
| `arch_log` | 读某步骤的终端日志尾部（运行中可读已写部分） |
| `arch_stop` | 叫停正在跑的任务（必须给 id，或 `all: true` 才全停） |

### arch_run

```jsonc
{
  "title": "构建并自检",
  "cwd": "C:\\work\\proj",          // 可选，缺省用工作区/配置
  "stopOnFail": true,               // 可选，失败后是否跳过剩余步骤（默认 true）
  "background": false,              // 可选，true 则后台跑、立即返回 id
  "console": true,                  // v0.5.1 可选，true 则每步开一个可见 Windows Terminal 窗口（默认 false=隐藏）
  "keepOpenMs": 4000,               // v0.5.1 可选，console 模式下窗口跑完保留多久（毫秒，默认 4000）
  "terminal": "auto",               // v0.6.0 可选，终端执行路线：auto（默认，有 ctx.terminals 就走 PTY 会话）/ "pty" / "process"
  "plan": {                          // 也可直接把 plan 字段平铺到参数里
    "steps": [
      { "name": "编译", "cmd": "npm run build" },
      { "name": "测试", "cmd": "npm test",
        "timeoutMs": 180000,
        "expect": { "exitCode": 0, "match": "passed", "notMatch": "FAIL" } },
      { "name": "可选检查", "cmd": "npm run lint", "allowFail": true }
    ]
  }
}
```

单步字段：

| 字段 | 说明 |
| --- | --- |
| `name` | 步骤名（进回执与日志文件名） |
| `cmd` | **必填**，整条终端命令（不拆分参数，直接交给 shell） |
| `cwd` | 该步工作目录，缺省用运行级 cwd |
| `timeoutMs` | 该步超时（毫秒），超时立即终止；`0` 表示不限 |
| `expect` | 判定条件：`exitCode`（数字）、`match`（输出正则）、`notMatch`（输出排除正则） |
| `allowFail` | `true` 时该步失败只记 `warn`，不中断后续 |

运行状态：`done` / `warn`（有 allowFail 失败）/ `failed` / `stopped`；单步另可 `skipped`。

### arch_flow（阵型：多角色 + 终端执行）

固定阵型（**顺序写死，不可重排**）：

```
拆分 → 路径 → 对抗性复核（只读、先议路径）→ 规划 → 隔离 → 修改 → 工作 → 验证方（多方，≥2）
```

**硬约束全部在插件代码里 fail-closed，不靠 prompt**：

| 硬约束 | 判据（代码） | 违反后果 |
| --- | --- | --- |
| 阵型固定 | 六个工作角色各一次、顺序严格；`adversarial` 必填；`verifiers.length >= 2` | 直接拒绝，一条终端命令都不跑 |
| **子对话强隔离** | 默认 `sessionPolicy: "spawn"`：每个角色由插件用 `subagents.startActivation` **现创建真实子会话**（独立上下文、非 fork），调用方不得传 `session`/`receipt`；子会话 id 必须非空、不等于主会话/调用方会话、彼此不重复；跑完全部 `drainChildren` 退班 | 伪冒/撞车即 FAIL；宿主无 `subagents.startActivation` 时 fail-closed（拒绝用声明 id 冒充） |
| 主会话不参与工作 | spawn 口径下角色会话全由插件创建，主会话天然不在其中；调用方会话 id 必须等于 `mainSession` | 拒绝执行 |
| 主对话 ≠ 对抗性复核 | 对抗性复核是独立子会话，与其余角色子会话两两不同 | 拒绝执行 |
| 对抗性复核只读 | 子会话执行前后对 `watch` 目录树做快照比对（新增/删除/改动）；`.dsh-arch-receipts` 等回执目录跳过 | 有写入即 FAIL，并点名写入文件 |
| 依据文档不得一致 | 每份依据按 sha256 判同一份（路径不同、内容相同也算）；对抗性复核与任何其他人的依据不得撞车（阵营内部＝对抗日与它派出的下级共用依据时不算撞车） | 撞车即 FAIL（与拆分/路径撞车会在「规划」之前就停） |
| 对抗性复核极具攻击性 | 回执必须带 `attacks[]`（每条：`target` + `failure_mode`），条数 ≥ `adversarial.minAttacks`（默认 2）；「没发现问题/整体可行/建议补测试」这类背书不计入 | 攻击点不足即 FAIL（`攻击面不足`），gate 记 `attacks` 与 `minAttacks` |
| 久议不决可向下分发 | 对抗性复核在回执里写 `dispatch:[{focus,citations?}]`（或 `undecided:true` + `unresolved[]`）⇒ 插件用 `startActivation` **以对抗日为 parent** 现创建下级子会话（`role=adversarial-sub`），逐条串行点卯/退班；下级沿用同等约束：独立会话、只读（快照覆盖到全部下级结束）、必交非空回执、依据不得与非对抗阵营撞车；随后用 `sendMessage` 唤醒对抗日写终审回执（role 仍是 adversarial、仍带 attacks），最终判定取「终审 + 下级最差」 | 下级空耗/只读违规/依据撞车 ⇒ FAIL；终审没写成 ⇒ 记警告并按「父复核 + 下级」最差收口；`subagents:false` 或 declared 口径 ⇒ 不分发（declared 只记警告） |
| 不许空耗 | 每个角色必须交回执（json：`role`/`verdict`/`findings`；验证方另有 `evidence`），文件缺失、过短、非 JSON、findings 为空；spawn 口径下 `roleTimeoutMs` 内没交合法回执也判空耗 | 该角色判空耗、interrupt 子会话，整条阵型 FAIL |
| 多方验证降权 | 同一份文档被 k 个验证方引用 ⇒ 每个引用者在该文档上只得 1/k 权重；加权得分 = Σ(w·verdict)/Σw；要求存在 k=1 的独立证据 | 无独立证据或加权分 < `passThreshold` ⇒ FAIL |
| **角色各有独立系统终端**（v0.5.0） | 默认 `terminal: "plugin"`：每个角色的任务由插件在它自己的系统终端里跑（一次角色＝一次独立终端进程，独立 PID 与日志），逐角色写进 `gate.terminals`（runId/shell/pid/每步 exit/日志路径）；子会话只拿这份终端真实输出做判定，不许自己编执行结果（防幻觉） | 该角色终端执行失败 ⇒ 整条阵型 FAIL，且**不创建子会话**（不接受回执冒充完成）；`terminal: "session"` 为旧口径（命令交给子会话自己的终端工具执行） |
| **按预演关键词下发技能**（v0.5.0） | 与 DSH 活体 `skills` 服务实时同步（`ctx.get("skills").list({cwd})`，被禁用的 `modelInvocable:false` 不下发；服务不可用才回退扫 `~/.agents/skills` 与 `~/.dsh/skills`）；按「任务标题 + 角色职责 + 该角色终端命令」做关键词检索，每个角色最多 `skills.max` 条（默认 4）；**省 token 类技能默认常驻**（`tokenSavers:true`，最多 2 条）；brief 里只给名字 + 一句话摘要，全文由子会话用 `skill` 工具按需加载；每角色命中写进 `gate.skills.perRole` | `skills.enabled:false` 可关；技能服务读不到只记 `catalog.source=dsh-skills-error`，不影响阵型 |
| **防幻觉 · 防对话污染 · 防越权**（v0.5.0） | ① brief 自包含：每个角色只拿本角色的输入与终端输出，不共享其他角色上下文、不许猜别人结论；② 子会话写入审计：`startActivation` 前后对监视树做快照比对，除它自己的回执外任何写入都判越权；③ brief 明禁再派生子智能体/转交任务；④ 回执 `evidence` 必须是真实存在的文件；⑤ 唯一事实来源＝终端日志与真实文件，不许编造。gate 里 `guards` 逐条记账 | 越权写入/evidence 不存在 ⇒ 该角色与整条阵型 FAIL（`越权写入` / `防编造证据`）；再派生与转交任务属 brief 硬约束、违反即判失败 |
| **可见终端窗口**（v0.5.1，默认关） | `console:true`：每个角色那一次终端运行改在**可见的 Windows Terminal 窗口**里跑（一步一窗），标题形如 `dsh-arch · <title> · <角色> · <步骤名>`；窗口内用辅助脚本跑命令，把真实 pid 与退出码写进 `.code.json` 标记回传；窗口保留 `keepOpenMs`（默认 4000）供人查看后自动关闭；判据仍是 exit 码/expect/日志，与隐藏模式完全一致 | 本机检出不到 `wt.exe` ⇒ 该步 FAIL（`无法启动终端窗口`），**不静默退回隐藏模式**（否则会以为在看窗口实际没跑） |
| **走宿主终端服务**（v0.6.0，默认） | 每个任务/每个角色在宿主 `ctx.terminals`（dsh-terminal-bash 持久终端）的**独立会话**里跑：独立会话 ID/PID/日志，输出回读落日志、结束标记回传退出码，跑完 kill 会话；`terminal: "auto"`（默认）/"pty"/"process" 可切 | 宿主无 `terminals` 服务或缺 owner ⇒ 记 `terminalMode:"process"` + `terminalFallback` 原因后回退原生子进程（不静默、回执可查） |
| 全量回执 | 每次阵型落 `<home>/flows/<flowId>/gate.json`（含 `isolation` 子会话台账、`terminals` 独立终端台账、`skills` 技能下发台账、`guards` 守卫声明、每角色 run/回执/子会话、对抗性复核只读结论、引用文档权重表、失败原因） | 工具只回裁决；主会话只核验 |

```jsonc
{
  "title": "把 XX 任务按阵型跑完",
  "mainSession": "session-<主会话 id>",   // 只核验；子会话全由插件创建，天然与它不同
  "cwd": "C:\\work\\proj",
  "watch": ["."],                          // 对抗性复核只读监视根 / 子会话写入审计根
  "passThreshold": 0.6,
  "roleTimeoutMs": 120000,                 // 每个角色子会话交回执的时限（默认取 timeoutMs）
  "terminal": "plugin",                    // v0.5.0：每个角色的任务在它自己的系统终端里跑（默认）；"session"=旧口径
  "console": true,                         // v0.5.1：true ⇒ 角色终端开成可见 Windows Terminal 窗口（默认 false）
  "keepOpenMs": 4000,                      // v0.5.1：console 模式下窗口保留多久（默认 4000）
  "terminalMode": "auto",                  // v0.6.0：角色任务的终端路线 auto/pty/process
  "skills": {                              // v0.5.0：与 DSH 活体技能库同步后按预演关键词下发
    "enabled": true,                       // 关掉传 false
    "tokenSavers": true,                   // 省 token 类技能默认常驻（默认 true）
    "max": 4                               // 每个角色最多几条（1–8）
  },
  "stages": [                              // 必须严格按此顺序：拆分/路径/规划/隔离/修改/工作
    { "role": "split", "citations": ["docs/task.md"],
      "steps": ["node gen-receipt.mjs split"] }   // terminal=plugin（默认）：插件在该角色自己的终端里跑这些命令，子会话只读输出做判定
    // … path / plan / isolate / modify / work 同形；不回执 session/receipt（由插件创建/生成）
  ],
  "adversarial": {                         // 固定角色，独立子会话，只读·红队
    "citations": ["docs/adv-evidence.md"],
    "steps": ["node review-path.mjs"],      // 审查命令必须只读
    "minAttacks": 2,                        // 攻击点下限（默认 2，不足即 FAIL）
    "subagents": { "maxChildren": 3, "adjudicate": true }
    // subagents:false 关掉向下分发；maxChildren 默认 3、硬上限 6；adjudicate:false 不唤醒终审
  },
  "verifiers": [                           // ≥2；引用同一份文档会被降权
    { "name": "验证方1", "citations": ["docs/report-a.md"], "steps": ["node verify.mjs v1"] },
    { "name": "验证方2", "citations": ["docs/report-b.md"], "steps": ["node verify.mjs v2"] }
  ]
}
```

每个角色子会话收到的 brief 里写死了：独立会话（禁与主会话/其他角色共享）、职责、工作目录、
本角色唯一的输入（v0.5.0 起：`terminal=plugin` 时是**插件已在它自己的系统终端跑完的输出**——
每步命令、exit 码、pid、耗时、绝对日志路径与末尾输出摘录；命令不许重复执行，只允许再跑只读命令补证）、
要逐条执行的终端命令（`terminal=session` 旧口径）、**唯一允许写入的回执路径**（`<home>/flows/<flowId>/.dsh-arch-receipts/...`，
相对路径按 `cwd` 解析）、回执 JSON 契约与 `role` 字段值、按预演关键词检索出的 DSH 技能摘要
（`## DSH 技能` 段，只给名字+一句话，全文用 `skill` 工具按需加载）；v0.5.0 另加
【隔离与越权边界】段（只拿本角色输入、禁再派生子智能体/转交任务、除回执外禁止写入、不许编造）；
对抗性复核另加【只读硬约束】+
【攻击性硬要求】两段（背书不算 attack、必须给具体失效方式），spawn 口径下再加
【久议不决可向下分发】段（dispatch 格式与上限、终审回执路径、逐条处置下级结论）；
下级子会话的 brief 只交办一个查点，同样写死只读与回执契约。

**v0.5.0 三项硬保证（代码强制，不靠 prompt 自觉）**：
① **各在各的终端**：一次角色＝一次 `engine.start` 终端运行（独立进程/PID/日志），子会话的判定只能引用这份
真实输出（终端没跑成就不创建子会话）；`gate.terminals` 逐角色留 runId / shell / pid / 每步 exit / 日志路径。
② **技能与 DSH 同步**：`ctx.get("skills")` 活体目录（禁用过的技能不下发）+ 关键词检索 + token 类默认常驻，
每角色命中写进 `gate.skills.perRole`；技能服务读不到才回退扫目录，并在 `catalog.source` 如实标来源。
③ **防幻觉/防污染/防越权**：brief 自包含、子会话写入快照审计（除自己回执外一律判越权）、
禁止再派生/转交、`evidence` 必须真实存在；`gate.guards` 逐条记账。

**v0.6.0 终端执行路线（默认走宿主终端服务）**：不再自己管进程，而是把每个任务丢进宿主
`ctx.terminals`（`@deepseek-ai/dsh-terminal` + `dsh-terminal-bash` 持久终端后端）里的**独立会话**：

- 每步 / 每个角色 = 一次 `terminals.spawn(owner, {type:'shell', name, cwd})` ⇒ 独立会话 ID、独立 PID、
  独立日志；会话跑完即 `terminals.kill`，不残留。
- **方言无关**：会话里的 shell 可能是 bash 方言也可能是 pwsh 方言，而 `st.cmd` 是给 `run.shell` 的——
  所以会话里只发一句 `node "pty-NN.mjs" "pty-NN.cfg.json"`，由这个 node 启动器 spawn `run.shell + st.cmd`
  并把 stdio 继承给终端；起止标记由 node 自己打印，退出码原样带回（不靠 shell 变量、不靠引号拼接）。
- 输出从会话滚动区 `terminals.read()` 读回、去掉起止标记后落 `NN-<slug>.log`，判定仍是
  exit 码 / `expect.match` / `expect.notMatch` / 超时，与隐藏模式逐项等价；超时判 `timedOut` 并 kill 会话。
- **回退如实记账**：宿主没提供 `terminals` 服务、或工具层拿不到调用方 Agent（owner）时，该运行记
  `terminalMode:"process"` + `terminalFallback:"<原因>"` 走原生子进程，并写进回执与 `arch_status`
  输出（不静默）；`terminal:"process"` 可强制老行为，`terminal:"pty"` 可强制走会话。
- `arch_flow` 同样按角色开会话：`gate.terminals[*]` 里每个角色带 `terminalMode`（pty/process）、
  `runId`、逐步骤 `pid` 与日志路径——这就是「每个角色的任务各在自己的系统终端里跑」的硬证据。
- 判据（`pty-smoke` 实测）：有力 terminals 服务时 `receipt.terminalMode==='pty'`、多步各自 pid、
  退出码经标记回传、`expect.match` 生效、超时 kill 会话、无服务时回退并写明原因。

**v0.6.2 终端路线可点名（`terminalMode` 接通）**：v0.6.0 的文档里就写了 `"terminalMode": "auto"`，但
`validateFlowPlan` 的 plan 里没有这个字段、`runRoleTerminal` 传的是 `undefined` ⇒ 只能吃引擎配置默认值，
调用方点名 pty/process 无效。现补：`arch_flow` 参数 `terminalMode: auto|pty|process`（默认 auto），
`gate.terminalMode` 记点名值、`terminals[].terminalMode` 记每个角色实际落定的路线；非法值在开跑前拒绝
（GATE FAIL，不创建任何子会话）。同轮修 `pty-smoke` 夹具：它原来用**管道 stdio** 读 helper 输出，而本机
DSH 沙箱禁命名管道（`spawn(..., {stdio: 默认})` 同步抛 `spawn EPERM`）⇒ 拿不到结束标记、5 项假失败；
改成与插件 `process` 分支同一手法（fd 重定向写文件，`read()` 再读文件），现 18/18 全绿。
`FLOW_VERSION` 同步对齐到插件版本（gate.json 的 `version`）。

**v0.5.1 可见终端窗口（`console:true`）**：默认仍是隐藏模式（输出直接写日志，无窗口、最省事）。
传 `console:true` 时，`arch_run` 的每一步、`arch_flow` 的每个角色那一次终端运行都改成
**开一个可见的 Windows Terminal 窗口**（`wt.exe -w new`，一步一窗，标题带角色名与步骤名，窗口关闭即算结束）：

- 命令不是直接 `spawn`，而是由自动落盘的 `console-run.mjs` 辅助脚本在窗口内执行：它把
  `{ pid, exitCode, startedAt, endedAt }` 写进 `<log>.code.json` 标记，插件轮询该标记取回
  **真实 pid 与退出码**——判定仍是退出码 / `expect` / 日志，与隐藏模式逐项等价。
- 窗口跑完保留 `keepOpenMs`（默认 4000ms，可按次覆盖）后自动关闭；超时会先落 `timedOut` 再关窗，
  判 `failed` 或 `warn`（`allowFail`）的规则不变。
- **不回退**：本机检出不到 `wt.exe` 时该步直接 FAIL（`无法启动终端窗口`），不静默退回隐藏模式；
  用户在等窗口、实际没跑是最坏的假象。
- 判据（`console-smoke` 实测）：窗口标题真出现、标记里的 pid 是真进程 pid、多步各自独立日志、
  超时窗口仍按超时判。

**与 dsh-court 组合**：默认 spawn 口径下插件自己创建角色子会话，不再需要外部把 court 的
部/司会话 id 填进来；若要让 court 的某个部/司直接当角色（旧口径），显式传
`sessionPolicy: "declared"` + `allowDeclaredSessions: true`，并在 `stages[*].session` /
`verifiers[*].session` 填真实会话 id——gate 会标 `isolation=declared` 供审计（这是降级口径，
会绕过「子对话强隔离」）。主会话（Lead/皇帝会话）只填 `mainSession`，不进入任何角色会话。

## 配置

`cordis.patch.yml` 里可给插件传 config（全部可选）：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | `false` 时 `arch_run` 只回开关提示，不执行 |
| `home` | `$DSH_ARCH_HOME` 或 `~/.dsh/arch` | 回执根目录 |
| `shell` | `auto` | `auto` / `powershell` / `pwsh` / `cmd` / `bash` / `sh`，或 `{exe,args,kind}` |
| `cwd` | DSH 进程 cwd | 运行级默认工作目录。**注意**：本机实测进程 cwd 是 `~/.dsh/profiles/desktop`，不是会话工作区 ⇒ 建议每次 `arch_run` 显式传 `cwd`，或在这里固定一个常用目录 |
| `timeoutMs` | `120000` | 每步默认超时 |
| `maxOutputBytes` | `262144` | 单步日志回执里保留的输出字节上限（日志文件本身不截断） |
| `keepRuns` | `50` | 内存里保留的最近运行数（回执文件不清理） |

## 落盘结构

```
<home>/dsh-arch-apply.log       # 装载留痕：每次 apply 一行（版本/pid/home/shell/工具名）
<home>/runs/<runId>/
├─ receipt.json          # 完整回执：状态、每步 cmd/退出码/耗时/日志路径/输出摘录
└─ 00-<slug>.log         # 第 1 步的终端日志（头部有 run/step/cmd/cwd/shell/时间）
<home>/flows/<flowId>/gate.json            # 阵型裁决：isolation 子会话台账 + terminals 独立终端台账
                                        #   + skills 技能下发台账 + guards 守卫声明 + 每角色 run/回执
                                        #   + 对抗性复核 attacks/dispatch/终审 + 权重表 + warnings + 失败原因
<home>/flows/<flowId>/.dsh-arch-receipts/ # spawn 口径下由插件创建的子会话回执（唯一允许写入位置）
```

`runId` 形如 `arch-mf3k2h9c-a1b2`。`arch_log` 只回尾部（默认 80 行、最多 256KB），
大日志不会一次灌进上下文。`dsh-arch-apply.log` 是装机验收判据：它存在且带工具名，
说明插件真被装载过（热重载失败时插件只在日志里留一句、工具却不见）。

## 安装

本机（desktop profile，由桌面应用独占管理，不能 `dsh plugin add`，且本机 pnpm 不可用）：

```powershell
# 需在 danger-full-access 下跑（要写会话工作区之外的 profile）
node scripts\install-desktop.mjs            # 安装
node scripts\install-desktop.mjs --uninstall # 卸载
node scripts\install-desktop.mjs --dry       # 只看计划
```

脚本做三件事并逐步回读校验：profile `package.json` 里 `dependencies["dsh-arch"] =
link:<本插件目录>`、`dsh.profile.bundles` 追加 `dsh-arch`、`node_modules\dsh-arch`
建 junction。写前自动备份 `package.json.bak-dsh-arch-<时间>`。

DSH 配置热加载会自动建 loader entry：**实测装完当轮工具即出现在会话里，无需重启**
（本机 2026-10-26 验证：arch_run/arch_flow/arch_status/arch_log/arch_stop 直接可用）。
web profile 可直接 `dsh plugin --profile web add <dir>`。

卸载：`--uninstall` 即可，回执目录独立保留。

### 装宿主终端子系统（v0.6.1，默认终端路线要用）

`arch_run`/`arch_flow` 默认走 `ctx.terminals`（每个任务/每个角色一个宿主终端会话）。该服务**不是**桌面应用
默认装载的，需在 profile 的用户层补两行（`~/.dsh/profiles/desktop/cordis.patch.yml` 末尾追加；本机 2026-10-27
实测**热加载即生效、无需重启**，`arch_run` 回执随即显示 `终端路线：PTY 会话（shell）`）：

```yaml
- insert:
    - id: terminal
      name: '@deepseek-ai/dsh-terminal'
    - id: terminal-bash
      name: '@deepseek-ai/dsh-terminal-bash'
      config:
        shellDialect: pwsh        # bash 后端就写 bash
```

依赖 `@deepseek-ai/dsh-subprocess-local`、`dsh-sandbox-policy`、`dsh-session-projection` 三个服务
（base bundle 已带）。没装这两行时插件**不会静默**：回执与 `arch_status` 里记
`- 终端路线：原生子进程（回退：宿主未提供 terminals 服务（dsh-terminal-bash 未装载））`。

## 测试

```powershell
node tests\host-smoke.mjs    # 45 项：arch_run/status/log/stop 全链路 + 沙箱行为
node tests\flow-smoke.mjs    # 87 项：arch_flow 全部硬闸（阵型/子对话强隔离/只读/依据撞车/空耗/降权/攻击性/向下分发/独立终端/技能下发/越权/终端路线点名）
node tests\console-smoke.mjs # 21 项：v0.5.1 可见终端窗口（窗口真出现 + 退出码/日志/超时与隐藏模式等价）
node tests\pty-smoke.mjs      # 18 项：v0.6.0 宿主终端会话路线（每步独立会话/退出码回传/超时 kill/回退记账）
```

`flow-smoke` 覆盖：缺角色与乱序拒绝、declared 未显式允许拒绝、spawn 下伪传 session 拒绝、
子会话 id 重复（隔离破坏）拒绝、宿主缺子会话原语 fail-closed 且零阶段、子会话超时未交回执判空耗并
interrupt、对抗性复核子会话写入监视区判违反只读、主会话当角色拒绝、对抗性复核=主对话拒绝、
只读违规、依据文档「路径不同内容相同」判同一份、回执缺失/findings 空判空耗、验证方 <2 拒绝、
引用同文档降权 1/k、无独立证据 FAIL、阶段终端失败即停、`gate.json` 落盘、GATE PASS 全绿；
v0.4.0 另覆盖：攻击点 0 条判 `攻击面不足`、攻击点充足入账、分发 happy path（下级 parent=对抗日、
2 个下级各自成会话、sendMessage 终审 done、11 个子会话全部退班、下级 findings 并入）、
超 `maxChildren` 截断并记警告、下级不交回执判空耗、下级依据与非对抗阵营撞车判同一份、
宿主无 `sendMessage` 只警告不失败、`subagents:false` 不分发；
v0.5.0 另覆盖：9 个角色各有独立终端（runId 两两不同、PID 非空、日志真实存在、终端信息落进阶段）、
技能库与活体服务同步（禁用技能不下发、token 类常驻、标题关键词命中 pcb-verify 进每角色 brief）、
子会话越权写入判 FAIL 并记账、角色终端失败判 FAIL 且不为它创建子会话。

`flow-smoke` 的 spawn 用例用假 `subagents` 模拟真实子会话（插件只认「回执文件出现」这个磁盘事实），
因此不需要 DSH 运行时也能验证隔离台账、退班、超时与 interrupt 行为。假 subagents 按宿主新原语
（`list`/`startActivation`/`drainChildren`）实现，并断言插件传出的 `provider`、`delivery:'caller'`、
`cwd`、自建 `AbortSignal` 都正确。`latestGate()` 按「跑前/跑后 flows 目录差集」定位本次 gate
（不按 mtime 取最新：相邻两次落盘只差几毫秒，本机曾因此偶发一次假失败 51/1）。

**现场验收（2026-10-26，活体插件，declared 口径）**：v0.2.0 代用 9 个角色回执跑通 `arch_flow`
（flow `flow-mvpbnna8-smdn`），裁决 `GATE PASS`；两个验证方共同引用 `evidence-a.md` ⇒ 每引用权重各 0.5，
验证方 2 另引独有证据 `evidence-b.md` ⇒ 权重 1.5，加权得分 1.0（阈值 0.6），独立证据=有。裁决落
`~/.dsh/arch/flows/flow-mvpbnna8-smdn/gate.json`。

**现场验收（2026-10-26，v0.3.1，活体 spawn 口径 · 9 个真实子会话）**：`arch_flow` 在活 DSH 上跑通
`flow-mvpcyrd4-74z8`，裁决 **`GATE PASS`**：`isolation.mode=spawn / createdByPlugin=true / provider=spawn /
delivery=caller / children=9 / drained=9`，9 个子会话 id 全为主机现创建、与主会话及调用方会话零交集；
六个工作段 + 对抗性复核 + 两个验证方的回执全部落在 `cwd\.dsh-arch-receipts\<flowId>\receipt-NN-<role>.json`。
对抗性复核会话独立、执行前后监视树零差异（只读通过），判 `warn`（findings 2 条）；两个验证方各引 2 份文档、
共同引用的 `docs/a.md` 每引用权重 0.5 ⇒ 加权得分 1.0（阈值 0.6），独立证据=有。各角色耗时 8.8s–131.1s
（总约 6 分钟，逐个子会话 200ms 轮询回执）。裁决落 `~/.dsh/arch/flows/flow-mvpcyrd4-74z8/gate.json`。
反例同样在活体验证：spawn 下给角色伪传 `session` ⇒ 立即拒绝且零子会话
（`flow-mvpd72pp-18au`，报「不得指定 session … 由插件用 subagents.startActivation 现创建」）。

**热重载口径（实测）**：编辑 `lib/*.js` 不会自动热重载到已注册的工具实例；本次用
`plugin_manager set_plugin include:dsh-arch enabled=false → enabled=true` 重装载，`~/.dsh/arch/dsh-arch-apply.log`
随即新增一行 `v0.3.1 pid=…`，工具当轮即为新代（也可重启 DSH）。判「活体跑的是哪一代」看该日志末行，或看
新 flow 的 `gate.json` 的 `version` 字段。

**v0.3.1 修复（2026-10-26，活体首跑抓到的真原因）**：本机 DSH 的 `subagents` 服务早就不叫
`startContinuable`/`drainContinuableChildren`，现行原语是 `startActivation`/`drainChildren`
（`startContinuable` 已不存在 ⇒ v0.3.0 在活体上必 fail-closed）。v0.3.1 改成：
`startActivation({ provider:'spawn', label, request:{cwd, prompt, parent}, signal, delivery:'caller' })`
→ 取 `{ childId, messageId }`；退班 `drainChildren(parentAgent,[childId])`；超时仍
`interrupt(childId,{kind:'ancestor',agent:parentAgent})`。三个要点：① `provider` 取宿主注册名
（默认 `spawn`，`subService.list()` 里没有就用清单首项）；② **子会话信号必须插件自建
`new AbortController().signal`**——`exec.signal` 会在工具调用返回时被 abort，接它会把还在跑的子会话
一起杀掉（dsh-court 踩过的坑）；③ `delivery:'caller'` 让完成通知不注入主线（主线只核验），结果由插件
自己收（没人 await `result` 时要 `.catch()` 兜住，避免 unhandled rejection）。

## 边界与实测坑

- **沙箱里不能用管道读子进程**：DSH 受限沙箱禁止命名管道，`spawn(..., {stdio:'pipe'})`
  会 `EPERM`。所以终端输出由子进程直接写日志文件（`stdio:['ignore', fd, fd]`），
  跑完再读文件。代价：没有实时流式回显，`arch_log` 是唯一实时通道。
- **沙箱里 `taskkill /T /F` 被拒**（`ERROR: Access denied`）：叫停/超时是
  「先 taskkill 试收子孙进程，250ms 内未退出就 `child.kill()` 兜底」。这意味着
  被命令自己拉起的后台子孙进程可能残留；需要严格清理时，把步骤写成
  「前台命令 + 自身信号处理」，或不要在步骤里常驻后台进程。
- **顺序执行**：步骤严格串行（架构本身是流水线，不做并行）。
- **回执只保留输出摘录**：完整输出在日志文件里；`maxOutputBytes` 只限制回执内嵌多少。
- **子对话强隔离的落地方式**：spawn 口径下插件调 `subagents.startActivation` 现创建子会话
  （独立上下文、非 fork），brief 里写死回执路径与只读要求，跑完 `drainChildren` 退班；
  判「办完」的唯一事实是**回执文件出现**（不是会话文字），因此子会话必须把回执写到指定路径。
  9 个角色逐个点卯/退班，避免撞 DSH 子 agent 活性上限（8）。
  降级口径 `declared` 需显式 `allowDeclaredSessions: true`，gate 标 `isolation=declared` 供审计。
- **只读监视范围 = `watch` 目录树**：跳过 `.git`、`node_modules`、`runs`、`flows`、
  `.dsh-arch-receipts`（子会话回执目录必须跳过，否则回执本身会被判成违规写入）；默认上限
  2000 个文件、≤1MB 的文件用 sha256、更大的用 size+mtime 判改动。
- **`cmd.exe` 引号坑**：插件把整条命令当参数交给 `cmd /d /s /c`，命令内部的双引号会被
  Node 反斜杠转义而解析失败（实测报 `'\"C:\Program Files\...\"' is not recognized`）。
  用 `cmd` 壳时命令里不要写双引号；复杂命令写进 `.cmd`/`.ps1` 脚本再调用；
  `powershell` 壳建议用单引号。（`arch_flow` 测试套件因此用无引号路径 + `node` 命令。）
- **为什么可见窗口走 Windows Terminal 而不是 `cmd /c start`（实测结论，别再回头试）**：Node 在 Windows 上
  `spawn`（detached 与否、`windowsHide:false`）都**不会**给子进程新建可见控制台；`cmd /c start "<标题>" /wait`
  能弹出窗口、标题也对，但 `start` 真实拉起的子进程树**看不到**（`CIM Win32_Process` 里没有父链），
  窗口里的退出码拿不回来，且 `/wait` 在部分情形下直接挂住 ⇒ 不可用于「要 exitCode/pid 又要窗口」的场合。
  `wt.exe -w new`（Windows Terminal）能开真窗口、窗口内进程可被辅助脚本拿到 pid 与退出码，
  再用标记文件回传，才同时保住「看得见」和「判得准」。
- **`wt.exe` 是 App Execution Alias（重解析点）**：`fs.existsSync`/`statSync` 对它返回 `false`/`EACCES`，
  必须用 `readdirSync(%LOCALAPPDATA%\Microsoft\WindowsApps)` 看目录项，或 `spawnSync('where.exe',['wt'])`
  的 `status===0` 判存在（插件两种都用了）。同理别用 `Test-Path` 的结果去解释 Node 侧行为。

- **v0.6.1：可见窗口里报「系统找不到指定的路径」＝launcher 编码坑**。`console-NN.cmd` 是 UTF-8 写的，
  而 cmd 默认按 OEM 代码页（简中本机 936/GBK）解析 ⇒ 中文标题乱码，且里面 `cd /d "<含中文的路径>"` 那行被读成
  不存在的路径，窗口一开就报错（退出码却仍是 0，极易误判「跑通了」）。修法两条同时做：launcher 首行
  `chcp 65001 >nul`（之后的行按 UTF-8 解析）、**launcher 里不写 `cd`**——工作目录交给 node 启动器
  `spawn(cfg.exe, …, {cwd: cfg.cwd})` 指定，路径不再经 cmd 解析，带空格/中文都安全；node 用
  `process.execPath` 绝对路径，不依赖窗口 PATH。活体验证：中文+空格目录
  `.dsh-arch-路径测试 空格` 里 `Write-Output 'PATH_OK 中文输出'` ⇒ 完成、exit=0。
- **验证权重只看「引用哪份文档」**：降权判据是被引文档的 sha256 分组，不评内容质量；
  同一文档内部前后矛盾、或引用一份没人看过的文档，本插件不判定——那属于审查者的事。
- **不是多智能体对话编排器**：`arch_run` 的执行层是系统终端子进程；`arch_flow` 每个角色的任务
  也由插件在**它自己的系统终端**里跑（v0.5.0 默认 `terminal=plugin`，独立 PID/日志），角色子会话只做
  「读终端输出 → 写回执」的判定，不共享上下文。要更复杂的角色对话编排用 dsh-court，二者组合方式见上文
  `arch_flow` 节。
