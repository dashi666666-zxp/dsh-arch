/**
 * dsh-arch flow-smoke：验证 arch_flow 的「强约束写在底层」——不启动 DSH，用 mock ctx 调 apply()，
 * 真跑系统终端命令（Windows 用 cmd 壳，POSIX 用 sh）。
 *
 * 覆盖（全部 fail-closed）：
 *   · 阵型顺序（缺角色 / 乱序拒绝）、角色各一次
 *   · 主会话隔离（主会话当角色 / 对抗性复核 = 主对话 / 角色会话重复 → 拒绝）
 *   · 调用方会话 ≠ mainSession → 拒绝
 *   · 对抗性复核只读（执行期间监视树被写 → 失败）
 *   · 对抗性复核依据文档与他人同内容（路径不同、sha256 相同也算）→ 失败
 *   · 每角色必须交回执（缺失 / findings 为空 / 非 JSON）→ 空耗失败
 *   · 验证方 ≥2、引用同一文档降权 1/k、无独立证据 → 失败
 *   · 阶段终端失败即停 + gate.json 落盘 + GATE PASS 全绿
 *
 * 跑法：node tests/flow-smoke.mjs
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const TMP = join(HERE, '.tmp-flow-smoke')
const HOME = join(TMP, 'home')
const WORK = join(TMP, 'work')
const DOCS = join(WORK, 'docs')
const RECEIPTS = join(TMP, 'receipts')
const isWin = process.platform === 'win32'
const SHELL = isWin ? 'cmd' : 'sh'
const PKG = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
/* 说明：cmd.exe 被 Node 以「整条命令当参数」方式拉起时，命令里出现双引号会被反斜杠转义而解析失败；
   测试路径均无空格，所以这里一律不加引号（推荐调用方把带引号的复杂命令写进 .ps1/.cmd 脚本再调用）。 */
const NODE = 'node'
const q = (p) => p

let pass = 0
let fail = 0
function check(name, cond, extra) {
  if (cond) {
    pass++
    console.log(`  ✓ ${name}`)
  } else {
    fail++
    console.log(`  ✗ ${name}${extra ? ` — ${extra}` : ''}`)
  }
}
function section(t) {
  console.log(`\n== ${t} ==`)
}

/* ── 回执助手：被各角色终端命令调用，写出一份合法 receipt json ──
 * v0.9.0：role=verify 时自动给出一份 docs/ 下每个文件的行级逐字摘录（内容级证据校验用）；
 * attacksArg='bad-quote' 故意给一条对不上的摘录；attacksArg='weak' 给一条缺 failure_mode 的攻击。 */
const HELPER = join(TMP, 'write-receipt.mjs')
const HELPER_SRC = `
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
const [file, role, verdict, evidenceCsv, attacksArg, ...findings] = process.argv.slice(2)
const evidence = evidenceCsv && evidenceCsv !== '-' ? evidenceCsv.split(',') : []
const badQuote = attacksArg === 'bad-quote'
const weak = attacksArg === 'weak'
const n = attacksArg === '-' || badQuote || weak ? (role === 'adversarial' ? 2 : 0) : Number(attacksArg)
const attacks = weak
  ? [{ target: 'weak-target-only' }]
  : Array.from({ length: Number.isFinite(n) && n > 0 ? n : 0 }, (_, i) => ({
      target: 'target-' + (i + 1),
      failure_mode: 'failure-mode-' + (i + 1),
    }))
const body = { role, verdict, findings, evidence, attacks }
if (role === 'verify') {
  if (badQuote) {
    body.quotes = [{ doc: '', quote: 'DEFINITELY-NOT-IN-ANY-DOC-0123456789-abcdef' }]
  } else {
    try {
      const dir = join(process.cwd(), 'docs')
      const quotes = []
      for (const name of readdirSync(dir).sort()) {
        if (!name.endsWith('.md')) continue
        const p = join(dir, name)
        const line = readFileSync(p, 'utf8')
          .split(/\\r?\\n/)
          .map((x) => x.trim())
          .find((x) => x && !x.startsWith('#') && x.length >= 12)
        if (line) quotes.push({ doc: p, quote: line })
      }
      if (quotes.length) body.quotes = quotes
    } catch {
      /* 没有 docs 目录就不给摘录（由 requireEvidenceQuote=false 的用例覆盖） */
    }
  }
}
writeFileSync(file, JSON.stringify(body, null, 2))
`
/** 生成一条「写回执行」终端命令（attacksArg：'2' 指定攻击点条数；'-' 走默认：对抗性复核 2 条、其它角色 0 条） */
function receiptCmd(receiptFile, role, verdict = 'pass', evidenceCsv = '-', findings = ['ok'], attacksArg = '-') {
  const args = [
    q(NODE),
    q(HELPER),
    q(receiptFile),
    role,
    verdict,
    evidenceCsv,
    attacksArg,
    ...findings.map((f) => (q(f) === f && /\s/.test(f) ? `"${f}"` : q(f))),
  ]
  return args.join(' ')
}
const R = (name) => join(RECEIPTS, `${name}.json`)
const doc = (name) => join(DOCS, name)

/* v0.9.0：mock 子会话给验证方回执补「逐字摘录」——从 brief 里解析依据文档，取文件中一行 ≥12 字符正文。 */
function quoteForFile(p) {
  try {
    const line = readFileSync(p, 'utf8')
      .split(/\r?\n/)
      .map((x) => x.trim())
      .find((x) => x && !x.startsWith('#') && x.length >= 12)
    return line ? { doc: p, quote: line } : null
  } catch {
    return null
  }
}

function stage(role, session, docName, receiptName, findings = ['ok']) {
  return {
    role,
    name: role,
    session,
    receipt: R(receiptName),
    citations: [doc(docName)],
    steps: [receiptCmd(R(receiptName), role, 'pass', '-', findings)],
  }
}

function basePlan(over = {}) {
  return {
    title: 'flow-smoke',
    mainSession: 's-main',
    /* 这些用例跑 declared（调用方声明会话）口径：默认 spawn 是强隔离口径，declared 必须显式允许。 */
    sessionPolicy: 'declared',
    allowDeclaredSessions: true,
    cwd: WORK,
    shell: SHELL,
    timeoutMs: 60000,
    watch: ['.'],
    passThreshold: 0.6,
    stages: [
      stage('split', 's-split', 'a.md', 'split'),
      stage('path', 's-path', 'b.md', 'path'),
      stage('plan', 's-plan', 'c.md', 'plan'),
      stage('isolate', 's-isolate', 'd.md', 'isolate'),
      stage('modify', 's-modify', 'e.md', 'modify'),
      stage('work', 's-work', 'f.md', 'work'),
    ],
    adversarial: {
      session: 's-adv',
      receipt: R('adv'),
      citations: [doc('adv.md')],
      steps: [receiptCmd(R('adv'), 'adversarial')],
    },
    verifiers: [
      {
        name: '验证方1',
        session: 's-v1',
        receipt: R('v1'),
        citations: [doc('a.md'), doc('b.md')],
        steps: [receiptCmd(R('v1'), 'verify')],
      },
      {
        name: '验证方2',
        session: 's-v2',
        receipt: R('v2'),
        citations: [doc('a.md'), doc('c.md')],
        steps: [receiptCmd(R('v2'), 'verify')],
      },
    ],
    ...over,
  }
}

/* ── mock ctx（同 host-smoke 口径） ── */
function makeCtx() {
  const tools = new Map()
  const services = new Map()
  const ctx = {
    tools: {
      register(tool) {
        if (tools.has(tool.name)) throw new Error(`tool "${tool.name}" is already registered`)
        tools.set(tool.name, tool)
        return () => tools.delete(tool.name)
      },
    },
    provide(n, v) {
      services.set(n, v)
      return () => services.delete(n)
    },
    effect(fn) {
      const d = fn()
      return typeof d === 'function' ? d : () => {}
    },
    get(k) {
      return k === 'tools' ? ctx.tools : services.get(k)
    },
    logger: { info() {}, warn() {}, error() {}, log() {} },
  }
  return { ctx, tools, services }
}

/* ── spawn 强隔离口径的假 subagents：模拟「真实子会话」把回执写到插件指定的路径 ── */
function makeSubagents(opts = {}) {
  const calls = { started: [], drained: [], interrupted: [], sent: [], active: 0, maxActive: 0 }
  /* v0.8.0：续跑测试要跨「两个 mock 实例」保持 childId 不撞车（真实宿主不会复用已退班的 id）。 */
  let n = Number(opts.startIdx) || 0
  /* v0.7.0：并发观测用——可给不同 role/序号配不同回执延迟，用来制造「完成顺序 ≠ 声明顺序」 */
  const delayOf = (role, idx) => (typeof opts.delayMs === 'function' ? Number(opts.delayMs(role, idx)) || 30 : Number(opts.delayMs) || 30)
  const writeReceipt = (receipt, role, idx, briefText = '') => {
    const advN = Number(opts.advAttacks ?? (role === 'adversarial' ? 2 : 0))
    const attacks = Array.from({ length: Number.isFinite(advN) && advN > 0 ? advN : 0 }, (_, i) => ({
      target: `${role}-target-${i + 1}`,
      failure_mode: `${role}-failure-${i + 1}`,
    }))
    const findings = role === 'adversarial-sub' ? [`sub-ok-${idx}`] : ['spawned-ok']
    const body = { role, verdict: opts.verdict || 'pass', findings, evidence: [], attacks }
    if (role === 'verify') {
      const cited = (String(briefText).match(/依据文档（只读参考）：(.+)/) || [])[1] || ''
      const quotes = cited
        .split('；')
        .map((s) => s.trim())
        .filter(Boolean)
        .map(quoteForFile)
        .filter(Boolean)
      if (quotes.length) body.quotes = quotes
    }
    if (role === 'adversarial' && opts.dispatchOnAdversarial) {
      body.dispatch = opts.dispatchOnAdversarial.map((d) => (typeof d === 'string' ? { focus: d } : { ...d }))
    }
    if (role === 'adversarial' && opts.undecided) {
      body.undecided = true
      body.unresolved = opts.undecided
    }
    writeFileSync(receipt, JSON.stringify(body, null, 2))
  }
  const sub = {
    list() {
      return opts.providers || ['spawn', 'fork']
    },
    async startActivation(spec) {
      const { label, request, provider, delivery, signal } = spec
      const text = String(request?.prompt?.[0]?.text || '')
      const role = (text.match(/回执 role 字段必须为：(\S+)/) || [])[1] || ''
      const receipt = (text.match(/回执路径：(.+)/) || [])[1] || ''
      const idx = ++n
      const childId = opts.duplicateId ? 'child-dup' : `child-${idx}`
      calls.started.push({ label, role, receipt, childId, parentId: request?.parent?.id || '', provider, delivery, cwd: request?.cwd, hasSignal: Boolean(signal && typeof signal.aborted === 'boolean'), hasParent: Boolean(request?.parent) })
      const skip = (opts.skipRoles || []).includes(role)
      /* v0.7.0：并发观测——active/maxActive 按「已点卯、尚未交回执」计（等于同时在跑的子会话数） */
      calls.active += 1
      if (calls.active > calls.maxActive) calls.maxActive = calls.active
      if (skip || !receipt) {
        calls.active -= 1
      } else {
        setTimeout(() => {
          try {
            writeReceipt(receipt, role, idx, text)
            /* v0.5.0 越权用例：子会话除了自己的回执，还偷偷写监视区 → 插件快照审计必须抓到。 */
            if (opts.overreach && role === 'split') writeFileSync(join(WORK, 'spawn-evil.txt'), 'x')
          } catch {
            /* 写不进去就等同空耗 */
          } finally {
            calls.active -= 1
          }
        }, delayOf(role, idx))
      }
      if (opts.leakOnReadOnly && role === 'adversarial') {
        setTimeout(() => {
          try {
            writeFileSync(join(WORK, 'spawn-leak.txt'), 'x')
          } catch {
            /* 忽略 */
          }
        }, 80)
      }
      return { childId, messageId: `msg-${n}`, result: Promise.resolve({ output: [], stopReason: 'completed' }), dispose: async () => {} }
    },
    async sendMessage(sender, targetId, content, options) {
      const text = String(content?.[0]?.text || '')
      calls.sent.push({ senderId: sender?.id || '', targetId, text, hasSignal: Boolean(options?.signal) })
      const fin = (text.match(/终审回执路径：(.+)/) || [])[1]
      if (fin && !opts.skipAdjudication) {
        setTimeout(() => {
          try {
            writeFileSync(
              fin,
              JSON.stringify(
                {
                  role: 'adversarial',
                  verdict: opts.finalVerdict || 'pass',
                  findings: ['final-ok'],
                  evidence: [],
                  attacks: [
                    { target: 'final-target-1', failure_mode: 'final-failure-1' },
                    { target: 'final-target-2', failure_mode: 'final-failure-2' },
                  ],
                },
                null,
                2,
              ),
            )
          } catch {
            /* 忽略 */
          }
        }, 30)
      }
      return `msg-sent-${calls.sent.length}`
    },
    interrupt(childId) {
      calls.interrupted.push(childId)
    },
    async drainChildren(parent, ids) {
      calls.drained.push(...ids)
      return ids.length
    },
  }
  if (opts.noSendMessage) delete sub.sendMessage
  return { sub, calls }
}

/** spawn 口径的阵型入参：不给 session/receipt（由插件创建子会话并生成回执路径）。 */
function spawnPlan(over = {}) {
  const actor = (role, docName) => ({ role, name: role, citations: [doc(docName)], steps: [`echo spawn-${role}`] })
  return {
    title: 'spawn-smoke',
    mainSession: 's-main',
    cwd: WORK,
    shell: SHELL,
    timeoutMs: 60000,
    roleTimeoutMs: 8000,
    watch: ['.'],
    passThreshold: 0.6,
    stages: [actor('split', 'a.md'), actor('path', 'b.md'), actor('plan', 'c.md'), actor('isolate', 'd.md'), actor('modify', 'e.md'), actor('work', 'f.md')],
    adversarial: { name: '对抗性复核', citations: [doc('adv.md')], steps: ['echo spawn-adv'] },
    verifiers: [
      { name: '验证方1', citations: [doc('a.md'), doc('b.md')], steps: ['echo spawn-v1'] },
      { name: '验证方2', citations: [doc('a.md'), doc('c.md')], steps: ['echo spawn-v2'] },
    ],
    ...over,
  }
}

/* 最近一次 run() 自己写出的 gate：按「跑前/跑后的 flows 目录差集」定位。
   不能只按 gate.json 的 mtime 取最新——相邻两次 flow 的落盘可只差几毫秒，
   在本机文件系统上会取到上一次的 gate（实测过一次 51/1 假失败）。 */
let lastGateFile = null

function flowDirs() {
  const dir = join(HOME, 'flows')
  return existsSync(dir) ? new Set(readdirSync(dir)) : new Set()
}

function latestGate() {
  if (lastGateFile && existsSync(lastGateFile)) return JSON.parse(readFileSync(lastGateFile, 'utf8'))
  const dir = join(HOME, 'flows')
  if (!existsSync(dir)) return null
  const subs = readdirSync(dir)
    .map((n) => join(dir, n, 'gate.json'))
    .filter((p) => existsSync(p))
  if (!subs.length) return null
  subs.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)
  return JSON.parse(readFileSync(subs[0], 'utf8'))
}

async function main() {
  const KEEP = process.env.FLOW_SMOKE_KEEP === '1'
  rmSync(TMP, { recursive: true, force: true })
  mkdirSync(DOCS, { recursive: true })
  mkdirSync(RECEIPTS, { recursive: true })
  writeFileSync(HELPER, HELPER_SRC, 'utf8')
  /* 依据文档：a..f + adv 各自不同内容；clone.md 与 a.md 内容完全相同（用于「同内容＝同一份」判据）。
     v0.9.0：正文加一行 ≥12 字符的 VERBATIM-QUOTE-*，供验证方回执的逐字摘录（内容级证据）命中。 */
  for (const n of ['a', 'b', 'c', 'd', 'e', 'f', 'adv'])
    writeFileSync(doc(`${n}.md`), `# doc ${n}\nVERBATIM-QUOTE-${n}: alpha beta gamma delta epsilon zeta eta.\ncontent-${n}\n`, 'utf8')
  writeFileSync(doc('clone.md'), readFileSync(doc('a.md')))

  section('模块形态与注册')
  const mod = await import(pathToFileURL(join(ROOT, 'lib', 'index.js')).href)
  check('导出版本与 package.json 一致', mod.VERSION === PKG.version, `${mod.VERSION} vs ${PKG.version}`)
  const { ctx, tools } = makeCtx()
  mod.apply(ctx, { home: HOME, shell: SHELL, timeoutMs: 60000 })
  const flow = tools.get('arch_flow')
  check('注册工具 arch_flow', !!flow)
  const out = flow && flow.output
  check(
    'arch_flow output 渲染契约',
    !!out && !!out.schema && typeof out.render === 'function' && out.render(null, 'x')[0].type === 'text',
  )
  const run = async (args, exec) => {
    const before = flowDirs()
    const text = await flow.execute(args, exec || {})
    const added = [...flowDirs()].filter((n) => !before.has(n))
    lastGateFile = added.length ? join(HOME, 'flows', added.sort().at(-1), 'gate.json') : null
    return text
  }

  section('阵型顺序 / 角色完整性（拒绝，且一条命令都不跑）')
  let t = await run(basePlan({ stages: basePlan().stages.slice(0, 5) }))
  let g = latestGate()
  check('缺角色 → GATE FAIL', /GATE FAIL/.test(t) && g && g.status === 'rejected', t.slice(0, 120))
  check('缺角色不动工（无阶段运行）', !g || !g.stages || g.stages.length === 0)

  const swapped = basePlan().stages
  ;[swapped[0], swapped[1]] = [swapped[1], swapped[0]]
  t = await run(basePlan({ stages: swapped }))
  check('乱序 → 拒绝（顺序写死）', /GATE FAIL/.test(t) && /顺序错误/.test(t), t.slice(0, 200))

  t = await run(basePlan({ adversarial: undefined }))
  check('缺固定对抗性复核 → 拒绝', /GATE FAIL/.test(t) && /对抗性复核/.test(t), t.slice(0, 200))

  t = await run(basePlan({ verifiers: [basePlan().verifiers[0]] }))
  check('验证方 < 2 → 拒绝（多方验证）', /GATE FAIL/.test(t) && /至少 2 个/.test(t), t.slice(0, 200))

  section('主会话 / 对话隔离（强约束）')
  t = await run(basePlan({ mainSession: 's-adv' }))
  check('对抗性复核 = 主对话 → 拒绝', /主会话|同一对话/.test(t) && /GATE FAIL/.test(t), t.slice(0, 200))

  const mainAsStage = basePlan()
  mainAsStage.stages[2].session = 's-main'
  t = await run(mainAsStage)
  check('主会话当角色（主会话参与工作）→ 拒绝', /主会话不得参与工作/.test(t), t.slice(0, 200))

  const dupSession = basePlan()
  dupSession.stages[3].session = 's-split'
  t = await run(dupSession)
  check('角色会话重复 → 拒绝（每个角色独立对话）', /会话冲突/.test(t), t.slice(0, 200))

  t = await run(basePlan(), { sessionId: 'session-other' })
  check('调用方会话 ≠ mainSession → 拒绝', /主会话不匹配/.test(t), t.slice(0, 200))

  section('GATE PASS 全链路（含引用同文档降权）')
  const okText = await run(basePlan())
  g = latestGate()
  check('GATE PASS', /GATE PASS/.test(okText) && g && g.status === 'done', okText.slice(0, 120))
  check('gate.json 落盘', !!g && typeof g.gateFile === 'string' && existsSync(g.gateFile))
  check('9 个阶段运行（6 角色 + 对抗性复核 + 2 验证方）', g && g.stages.length === 9, g ? `got ${g.stages.length}` : 'no gate')
  check(
    '对抗性复核只读通过',
    g && g.adversarial && g.adversarial.readOnly === true && g.adversarial.changes.length === 0,
    g ? JSON.stringify(g.adversarial && g.adversarial.changes) : '',
  )
  const rows = g ? g.verify.rows : []
  check('验证权重封顶：原始 1.5 被压到 1（每方 ≤1）', rows.length === 2 && rows.every((r) => r.weight === 1 && r.weightRaw === 1.5), JSON.stringify(rows))
  const aHash = g ? g.verify.docs.find((d) => d.citedBy.length === 2) : null
  check('同一文档被 2 方引用 → 每引用权重 1/2', !!aHash && aHash.weightEach === 0.5, JSON.stringify(aHash))
  check('加权得分 = 1（阈值 0.6）', g && g.verify.score === 1 && g.verify.independentEvidence === true, g ? String(g.verify.score) : '')
  check('独立证据口径：2 份独引文档（b/c）才算独立', g && g.verify.independentDocs === 2 && g.verify.weightCap === 1, g ? JSON.stringify({ n: g.verify.independentDocs, cap: g.verify.weightCap }) : '')
  check('gate 记录了各角色 run 与回执', g && g.stages.every((s) => s.runId && s.actorReceipt))

  section('对抗性复核：只读违规')
  const advWrite = basePlan()
  advWrite.adversarial = {
    ...advWrite.adversarial,
    steps: [isWin ? `type nul > ${q(join(WORK, 'leak.txt'))}` : `touch ${join(WORK, 'leak.txt')}`, receiptCmd(R('adv'), 'adversarial')],
  }
  t = await run(advWrite)
  g = latestGate()
  check('执行期间有写入 → GATE FAIL', /GATE FAIL/.test(t) && g && g.status === 'failed', t.slice(0, 160))
  check('只读违规被点名', g && g.adversarial && g.adversarial.readOnly === false && /违反只读/.test(t), g ? JSON.stringify(g.adversarial.changes) : '')

  section('对抗性复核：依据文档不得与他人一致（内容级）')
  const advClone = basePlan()
  advClone.adversarial = { ...advClone.adversarial, citations: [doc('clone.md')] }
  t = await run(advClone)
  g = latestGate()
  check('路径不同但内容相同 → 判同一份', /GATE FAIL/.test(t) && /同一份/.test(t), t.slice(0, 200))
  check('撞车发生在 plan 之前（拆分/路径/对抗性复核已跑，规划未跑）', g && g.stages.length === 3, g ? `got ${g.stages.length}` : 'no gate')

  section('对抗性复核：极具攻击性（只背书不算复核）')
  const softAdv = basePlan()
  softAdv.adversarial = { ...softAdv.adversarial, steps: [receiptCmd(R('adv'), 'adversarial', 'pass', '-', ['ok'], 0)] }
  t = await run(softAdv)
  g = latestGate()
  check('攻击点 0 条 → FAIL（攻击面不足）', /GATE FAIL/.test(t) && /攻击面不足/.test(t), t.slice(0, 260))
  check('gate 记下 attacks 条数', g && g.adversarial && Array.isArray(g.adversarial.attacks) && g.adversarial.attacks.length === 0, g ? JSON.stringify(g.adversarial.attacks) : 'no gate')

  const sharpAdv = basePlan()
  sharpAdv.adversarial = { ...sharpAdv.adversarial, steps: [receiptCmd(R('adv'), 'adversarial', 'pass', '-', ['ok'], 3)] }
  t = await run(sharpAdv)
  g = latestGate()
  check('攻击点充足（3 条）→ GATE PASS 并逐条入账', /GATE PASS/.test(t) && g && g.adversarial.attacks.length === 3 && /攻击点/.test(t), t.slice(0, 200))

  section('空耗判定：回执缺失 / findings 为空')
  const missReceipt = basePlan()
  missReceipt.stages = missReceipt.stages.map((s) => (s.role === 'work' ? { ...s, receipt: join(RECEIPTS, 'missing.json') } : s))
  t = await run(missReceipt)
  g = latestGate()
  check('回执缺失 → 空耗 FAIL', /GATE FAIL/.test(t) && /回执不存在/.test(t), t.slice(0, 200))
  check('失败发生在「工作」阶段（不进入验证方）', g && g.stages.length === 7, g ? `got ${g.stages.length}` : 'no gate')

  const emptyFindings = basePlan()
  emptyFindings.stages[0].steps = [receiptCmd(R('split'), 'split', 'pass', '-', [])]
  t = await run(emptyFindings)
  check('findings 为空 → 空耗 FAIL', /GATE FAIL/.test(t) && /findings 为空/.test(t), t.slice(0, 200))

  section('多方验证：全部引用同一文档（无独立证据）')
  const sameDocs = basePlan()
  sameDocs.verifiers = [
    { name: '验证方1', session: 's-v1', receipt: R('v1'), citations: [doc('a.md')], steps: [receiptCmd(R('v1'), 'verify')] },
    { name: '验证方2', session: 's-v2', receipt: R('v2'), citations: [doc('a.md')], steps: [receiptCmd(R('v2'), 'verify')] },
  ]
  t = await run(sameDocs)
  g = latestGate()
  check('全部撞车 → 无独立证据 FAIL', /GATE FAIL/.test(t) && /无独立证据/.test(t), t.slice(0, 200))
  check('撞车时权重被降到 0.5', g && g.verify && g.verify.rows.every((r) => r.weight === 0.5), g ? JSON.stringify(g.verify.rows) : '')

  section('阶段终端失败即停')
  const stageFail = basePlan()
  stageFail.stages[1].steps = [isWin ? 'exit 1' : 'false']
  t = await run(stageFail)
  g = latestGate()
  check('终端失败 → 立即 FAIL', /GATE FAIL/.test(t) && g && g.status === 'failed', t.slice(0, 160))
  check('失败后不再跑后续角色', g && g.stages.length === 2, g ? `got ${g.stages.length}` : 'no gate')

  section('回执相对路径（按 cwd 解析，回归）')
  const rel = basePlan({ watch: ['docs'] })
  const relReceipt = (name) => `${name}-receipt.json`
  rel.stages = rel.stages.map((s) => ({ ...s, receipt: relReceipt(s.role), steps: [receiptCmd(relReceipt(s.role), s.role)] }))
  rel.adversarial = { ...rel.adversarial, receipt: relReceipt('adv'), steps: [receiptCmd(relReceipt('adv'), 'adversarial')] }
  rel.verifiers = rel.verifiers.map((v, i) => ({
    ...v,
    receipt: relReceipt(`v${i + 1}`),
    steps: [receiptCmd(relReceipt(`v${i + 1}`), 'verify')],
  }))
  t = await run(rel)
  g = latestGate()
  check(
    '相对回执路径 → 按 cwd 解析且 GATE PASS',
    /GATE PASS/.test(t) && g && g.status === 'done',
    `${t.slice(0, 100)} ｜ failures=${g ? g.failures.join(' / ') : 'no gate'}`,
  )
  check(
    'gate 记录的回执为绝对路径且存在',
    g && g.stages.every((s) => isAbsolute(s.actorReceipt) && existsSync(s.actorReceipt)),
    g ? g.stages.map((s) => s.actorReceipt).join(' | ') : '',
  )

  section('子对话强隔离（spawn 默认：插件现创建真实子会话，调用方不给 session）')
  const mkOk = makeSubagents()
  ctx.provide('subagents', mkOk.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check('spawn：GATE PASS', /GATE PASS/.test(t) && g && g.status === 'done', `${t.slice(0, 120)} ｜ failures=${g ? g.failures.join(' / ') : 'no gate'}`)
  check('gate 标 isolation=spawn 且 createdByPlugin', g && g.isolation && g.isolation.mode === 'spawn' && g.isolation.createdByPlugin === true, g ? JSON.stringify(g.isolation) : 'no gate')
  check('插件真实创建 9 个子会话、跑完全部退班', mkOk.calls.started.length === 9 && g.isolation.children.length === 9 && g.isolation.drained.length === 9, g ? `children=${g.isolation.children.length} drained=${g.isolation.drained.length}` : '')
  check(
    '各阶段 session 全部来自插件创建且不与主会话撞车',
    g && g.stages.every((s) => s.spawned === true && /^child-/.test(s.session) && s.session !== 's-main' && s.session !== 's-main'),
    g ? g.stages.map((s) => s.session).join(' ') : '',
  )
  check('brief 里带绝对回执路径与角色契约', mkOk.calls.started.every((c) => c.role && c.receipt && isAbsolute(c.receipt)), JSON.stringify(mkOk.calls.started[0]))
  check(
    '用宿主新原语 startActivation：provider=spawn、delivery=caller、cwd/brief 齐',
    mkOk.calls.started.every((c) => c.provider === 'spawn' && c.delivery === 'caller' && c.cwd === WORK && c.hasParent),
    JSON.stringify(mkOk.calls.started[0]),
  )
  check(
    '子会话信号是插件自建 AbortSignal（不接工具 exec.signal，工具返回后不会杀掉子会话）',
    mkOk.calls.started.every((c) => c.hasSignal),
    JSON.stringify(mkOk.calls.started[0]),
  )

  const withSession = spawnPlan()
  withSession.stages = withSession.stages.map((s, i) => (i === 0 ? { ...s, session: 's-forged' } : s))
  t = await run(withSession, { sessionId: 's-main', agent: { fake: true } })
  check('spawn 下仍传 session（伪冒子对话）→ 拒绝', /不得指定 session/.test(t), t.slice(0, 200))

  t = await run(basePlan({ allowDeclaredSessions: false }))
  check('declared 未显式允许 → 拒绝（防绕过强隔离）', /声明式会话/.test(t), t.slice(0, 200))

  const mkMiss = makeSubagents({ skipRoles: ['work'] })
  ctx.provide('subagents', mkMiss.sub)
  t = await run(spawnPlan({ roleTimeoutMs: 3000 }), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check('子会话超时未交回执 → 空耗 FAIL', /GATE FAIL/.test(t) && /空耗/.test(t), t.slice(0, 200))
  check('超时后 interrupt 该子会话', mkMiss.calls.interrupted.length >= 1, JSON.stringify(mkMiss.calls.interrupted))
  check('超时阶段状态 failed 且不进入验证方', g && g.stages.length === 7 && g.stages[6].status === 'failed', g ? `stages=${g.stages.length}` : 'no gate')

  const mkLeak = makeSubagents({ leakOnReadOnly: true })
  ctx.provide('subagents', mkLeak.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  check('对抗性复核子会话写入监视区 → 违反只读 FAIL', /GATE FAIL/.test(t) && /违反只读/.test(t), t.slice(0, 240))

  const mkDup = makeSubagents({ duplicateId: true })
  ctx.provide('subagents', mkDup.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  check('两个角色拿到同一子会话 id → 隔离破坏 FAIL', /子会话隔离破坏/.test(t), t.slice(0, 200))

  section('v0.5.0：角色各有独立系统终端 + 按预演关键词下发技能 + 防越权')
  const mkV5 = makeSubagents()
  ctx.provide('subagents', mkV5.sub)
  const fakeSkills = [
    { name: 'token-saver', description: '省 token 的读写纪律', invocation: { modelInvocable: true, userInvocable: true } },
    { name: 'pcb-verify', description: 'PCB 校验与几何核对', invocation: { modelInvocable: true } },
    { name: 'hidden-note', description: '被禁用，不该下发', invocation: { modelInvocable: false } },
  ]
  ctx.provide('skills', {
    async list() {
      return fakeSkills
    },
  })
  t = await run(spawnPlan({ title: 'pcb 校验任务' }), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check(
    'v0.5.0：GATE PASS 且 terminal=plugin',
    /GATE PASS/.test(t) && g && g.status === 'done' && g.terminal === 'plugin',
    `${t.slice(0, 140)} ｜ ${g ? g.failures.join(' / ') : 'no gate'}`,
  )
  check(
    '每个角色各一个独立终端（runId 两两不同、有真实 PID）',
    g && g.terminals && g.terminals.length === 9 && new Set(g.terminals.map((x) => x.runId)).size === 9 && g.terminals.every((x) => x.pids.length >= 1),
    g ? `terminals=${g.terminals && g.terminals.length}` : 'no gate',
  )
  check(
    '终端记录带独立日志路径且日志真实存在',
    g && g.terminals.every((x) => x.logs.length >= 1 && x.logs.every((p) => existsSync(p))),
    g ? JSON.stringify(g.terminals && g.terminals[0] && g.terminals[0].logs) : '',
  )
  check(
    'brief 的终端信息落到阶段（子会话拿终端输出做判定）',
    g && g.stages.filter((s) => s.spawned).every((s) => s.terminal && s.terminal.runId && s.terminal.pids.length >= 1),
    g ? JSON.stringify(g.stages.map((s) => (s.terminal ? s.terminal.runId : null))) : '',
  )
  check(
    '技能库与 DSH 活体服务同步（禁用过的不可见）',
    g && g.skills && g.skills.catalog.source === 'dsh-skills' && g.skills.catalog.visible === 2 && g.skills.catalog.total === 3,
    g ? JSON.stringify(g.skills && g.skills.catalog) : '',
  )
  const roleSkillNames = g ? Object.values(g.skills.perRole).map((v) => v.map((x) => x.name)) : []
  check('token 节省类技能默认常驻（每个角色都下发）', roleSkillNames.length > 0 && roleSkillNames.every((ns) => ns.includes('token-saver')), JSON.stringify(roleSkillNames))
  check('按关键词命中下发（标题含 pcb → 每个角色都拿到 pcb-verify）', roleSkillNames.length > 0 && roleSkillNames.every((ns) => ns.includes('pcb-verify')), JSON.stringify(roleSkillNames))
  check('被禁用技能（modelInvocable=false）不下发', roleSkillNames.every((ns) => !ns.includes('hidden-note')), JSON.stringify(roleSkillNames))
  check(
    '阶段记录下发的技能名',
    g && g.stages.filter((s) => s.spawned).every((s) => Array.isArray(s.skills) && s.skills.length > 0),
    g ? JSON.stringify(g.stages.map((s) => s.skills)) : '',
  )
  check(
    'gate 记下时限配置（roleTimeoutMs 事后可审计）',
    g && g.timeouts && g.timeouts.roleMs === 8000 && g.timeouts.stepMs === 60000,
    g ? JSON.stringify(g.timeouts) : '',
  )
  check(
    'guards 由实测推导（干净场次：只写回执 / 无预置回执 / 读活体技能库）',
    g &&
      g.guards &&
      g.guards.childWriteScope === 'receipt-only' &&
      g.guards.receiptsClean === true &&
      g.guards.evidenceMustExist === true &&
      g.guards.adversarialReadOnly === true &&
      g.guards.skillSource === 'dsh-skills',
    g ? JSON.stringify(g.guards) : '',
  )

  section('v0.6.2：终端执行路线可点名（此前 plan.terminalMode 恒 undefined）')
  const mkV6 = makeSubagents()
  ctx.provide('subagents', mkV6.sub)
  t = await run(spawnPlan({ title: '终端路线点名', terminalMode: 'process' }), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check(
    'terminalMode=process：GATE PASS 且 gate 记下点名路线',
    /GATE PASS/.test(t) && g && g.status === 'done' && g.terminalMode === 'process',
    `${t.slice(0, 140)} ｜ ${g ? JSON.stringify({ terminalMode: g.terminalMode, failures: g.failures }) : 'no gate'}`,
  )
  check(
    '点名路线落到每个角色的终端回执（process 强制原生子进程）',
    g && g.terminals && g.terminals.length === 9 && g.terminals.every((x) => x.terminalMode === 'process'),
    g ? JSON.stringify(g.terminals && g.terminals.map((x) => x.terminalMode)) : '',
  )
  const startedBefore = mkV6.calls.started.length
  t = await run(spawnPlan({ terminalMode: 'bogus' }), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check(
    'terminalMode 非法 → 开跑前拒绝（GATE FAIL，不创建子会话）',
    /GATE FAIL/.test(t) && /terminalMode 非法/.test(t) && g && g.status === 'rejected' && mkV6.calls.started.length === startedBefore,
    `${t.slice(0, 160)} ｜ started ${startedBefore}→${mkV6.calls.started.length}`,
  )

  /* 防越权：子会话除了写自己的回执，任何写入都判越权 FAIL */
  const mkOver = makeSubagents({ overreach: true })
  ctx.provide('subagents', mkOver.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check('子会话越权写入 → GATE FAIL', /GATE FAIL/.test(t) && /越权写入/.test(t), t.slice(0, 240))
  check(
    '越权写入被记账（gate 阶段里能看到变更）',
    g && g.stages.some((s) => Array.isArray(s.writeViolations) && s.writeViolations.length > 0),
    g ? JSON.stringify(g.stages.map((s) => s.writeViolations || null)) : '',
  )
  check(
    '越权写入反映到 guards.childWriteScope（不写死 receipt-only）',
    g && g.guards && g.guards.childWriteScope === 'violated',
    g ? JSON.stringify(g.guards) : '',
  )

  /* 终端失败：不许创建子会话冒充完成 */
  const mkTerm = makeSubagents()
  ctx.provide('subagents', mkTerm.sub)
  const termFailPlan = spawnPlan()
  termFailPlan.stages[1].steps = [isWin ? 'exit 3' : 'false']
  t = await run(termFailPlan, { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check('角色终端失败 → GATE FAIL（不接受回执冒充完成）', /GATE FAIL/.test(t) && /独立系统终端执行失败/.test(t), t.slice(0, 240))
  check('终端失败的角色不创建子会话', mkTerm.calls.started.every((c) => c.role !== 'path'), `started=${mkTerm.calls.started.map((c) => c.role).join(',')}`)

  section('久议不决：对抗性复核向下分发自己的子智能体（沿用同等约束）')
  const mkFan = makeSubagents({ dispatchOnAdversarial: ['核对路径中未声明的假设', '核对只读边界是否可绕过'] })
  ctx.provide('subagents', mkFan.sub)
  ctx.provide('agents', { get: (id) => (typeof id === 'string' && id.startsWith('child-') ? { id } : undefined) })
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  const fan = g ? g.adversarial.dispatch : null
  check('分发：GATE PASS', /GATE PASS/.test(t) && g && g.status === 'done', `${t.slice(0, 140)} ｜ failures=${g ? g.failures.join(' / ') : 'no gate'}`)
  check(
    '分发被识别并记触发方式/条数',
    !!fan && fan.enabled === true && fan.mode === 'spawn' && fan.trigger === 'dispatch' && fan.children.length === 2 && fan.status === 'done',
    JSON.stringify(fan && { trigger: fan.trigger, children: fan.children.length, status: fan.status }),
  )
  const subStarted = mkFan.calls.started.filter((c) => c.role === 'adversarial-sub')
  check(
    '下级作为「对抗日自己的子会话」创建（parent=对抗日）',
    subStarted.length === 2 && subStarted.every((c) => c.parentId === g.adversarial.session),
    JSON.stringify(subStarted.map((c) => ({ role: c.role, parentId: c.parentId, session: c.childId }))),
  )
  check(
    '下级沿用同等约束：spawn / 独立会话 / 只读 / 交回执',
    subStarted.every((c) => c.provider === 'spawn' && c.delivery === 'caller' && c.hasParent && c.hasSignal) &&
      new Set([g.adversarial.session, ...fan.children.map((c) => c.session)]).size === 3 &&
      g.adversarial.readOnly === true,
    JSON.stringify(subStarted[0]),
  )
  check(
    '终审：sendMessage 唤醒对抗日写终审回执',
    mkFan.calls.sent.length === 1 && mkFan.calls.sent[0].targetId === g.adversarial.session && fan.adjudication.status === 'done' && g.adversarial.finalVerdict === 'pass',
    JSON.stringify(fan && fan.adjudication),
  )
  check(
    '下级 findings 并入对抗日（去重合并）',
    g.adversarial.findings.some((f) => /^sub-ok-/.test(f)) && g.adversarial.findings.includes('spawned-ok') && new Set(g.adversarial.findings).size === g.adversarial.findings.length,
    JSON.stringify(g.adversarial.findings),
  )
  check(
    '11 个子会话（9 角色 + 2 下级）全部退班',
    mkFan.calls.started.length === 11 && g.isolation.children.length === 11 && g.isolation.drained.length === 11,
    `started=${mkFan.calls.started.length} children=${g.isolation.children.length} drained=${g.isolation.drained.length}`,
  )
  check('渲染战况：红队 / 攻击点 / 向下分发', /红队/.test(t) && /攻击点/.test(t) && /向下分发/.test(t))

  const mkTrunc = makeSubagents({ dispatchOnAdversarial: ['查点1', '查点2', '查点3'] })
  ctx.provide('subagents', mkTrunc.sub)
  t = await run(
    spawnPlan({ adversarial: { ...spawnPlan().adversarial, subagents: { maxChildren: 2, adjudicate: false } } }),
    { sessionId: 's-main', agent: { fake: true } },
  )
  g = latestGate()
  check(
    '超过 maxChildren → 按上限派 + 记账警告（终审可关）',
    g && g.status === 'done' && g.adversarial.dispatch.children.length === 2 && g.adversarial.dispatch.truncated === 1 && g.warnings.length >= 1 && /截断/.test(t),
    g ? `children=${g.adversarial.dispatch.children.length} warnings=${JSON.stringify(g.warnings)}` : 'no gate',
  )

  const mkSubMiss = makeSubagents({ dispatchOnAdversarial: ['查点X'], skipRoles: ['adversarial-sub'] })
  ctx.provide('subagents', mkSubMiss.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  check('下级不交回执 → 空耗 FAIL（与非对抗日同判据）', /GATE FAIL/.test(t) && /空耗/.test(t), t.slice(0, 240))

  const mkSubClone = makeSubagents({ dispatchOnAdversarial: [{ focus: '核对拆分结论', citations: [doc('a.md')] }] })
  ctx.provide('subagents', mkSubClone.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  check('下级依据文档与非对抗阵营同内容 → 判同一份 FAIL', /GATE FAIL/.test(t) && /同一份/.test(t), t.slice(0, 240))

  const mkNoSend = makeSubagents({ dispatchOnAdversarial: ['查点Y'], noSendMessage: true })
  ctx.provide('subagents', mkNoSend.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check(
    '宿主无 sendMessage → 终审记为 unavailable 并警告（不误判失败）',
    g && g.status === 'done' && g.adversarial.dispatch.adjudication.status === 'unavailable' && g.warnings.some((w) => /终审/.test(w)),
    g ? `status=${g.status} warnings=${JSON.stringify(g.warnings)}` : 'no gate',
  )

  const mkOff = makeSubagents({ dispatchOnAdversarial: ['查点1', '查点2'] })
  ctx.provide('subagents', mkOff.sub)
  t = await run(spawnPlan({ adversarial: { ...spawnPlan().adversarial, subagents: false } }), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check(
    'subagents:false → 一人复核、不分发（mode=off）',
    g && g.status === 'done' && mkOff.calls.started.length === 9 && !g.adversarial.dispatch && g.adversarialFanout.mode === 'off',
    g ? `started=${mkOff.calls.started.length} mode=${g.adversarialFanout && g.adversarialFanout.mode}` : 'no gate',
  )

  ctx.provide('subagents', undefined)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  g = latestGate()
  check('宿主缺子会话原语 → fail-closed（拒绝用声明 id 冒充）', /GATE FAIL/.test(t) && /未提供子会话原语/.test(t), t.slice(0, 200))
  check('缺原语时一条命令都不跑', g && g.stages.length === 0, g ? `stages=${g.stages.length}` : 'no gate')

  const mkNoDrain = makeSubagents()
  delete mkNoDrain.sub.drainChildren
  ctx.provide('subagents', mkNoDrain.sub)
  t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
  check('缺 drainChildren（无法退班）→ fail-closed', /GATE FAIL/.test(t) && /未提供 drainChildren/.test(t), t.slice(0, 200))

  ctx.provide('subagents', mkOk.sub)
  t = await run(basePlan())
  g = latestGate()
  check('declared 降级口径在 gate 标 isolation=declared', g && g.isolation && g.isolation.mode === 'declared', g ? JSON.stringify(g.isolation) : 'no gate')

  /* ── v0.7.0 并行：验证方之间 / 对抗性复核下级之间按 maxParallel 有界并发 ── */
  section('v0.7.0 并行（验证方 / 下级的有界并发）')
  {
    /* 默认 maxParallel=3：两个验证方回执故意写慢，应当同时在跑 */
    const mkPar = makeSubagents({ delayMs: (role) => (role === 'verify' ? 160 : 20) })
    ctx.provide('subagents', mkPar.sub)
    t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
    g = latestGate()
    check('默认并行生效：两个验证方同时在跑', mkPar.calls.maxActive >= 2, `maxActive=${mkPar.calls.maxActive}`)
    check(
      'gate.parallel 记账（上限 / 两处实际并发数 / 串行阶段清单）',
      g && g.parallel && g.parallel.maxParallel === 3 && g.parallel.verifiers === 2 && g.parallel.adversarialChildren === 0 && g.parallel.serialized.length === 7,
      g ? JSON.stringify(g.parallel) : 'no gate',
    )

    /* maxParallel=1 → 退回旧口径：任何时刻最多 1 个子会话 */
    const mkSer = makeSubagents({ delayMs: 25 })
    ctx.provide('subagents', mkSer.sub)
    t = await run(spawnPlan({ maxParallel: 1 }), { sessionId: 's-main', agent: { fake: true } })
    g = latestGate()
    check('maxParallel=1 → 逐个跑（maxActive 恒为 1）', mkSer.calls.maxActive === 1, `maxActive=${mkSer.calls.maxActive}`)
    check('maxParallel=1 仍 9 个阶段全跑完', g && g.status === 'done' && g.stages.length === 9, g ? `status=${g.status} stages=${g.stages.length}` : 'no gate')

    /* 完成顺序反转（验证方 1 慢、验证方 2 快）时，gate.stages 仍按创建顺序 */
    const mkOrd = makeSubagents({ delayMs: (role, idx) => (role === 'verify' && idx === 8 ? 220 : 20) })
    ctx.provide('subagents', mkOrd.sub)
    t = await run(spawnPlan(), { sessionId: 's-main', agent: { fake: true } })
    g = latestGate()
    const order = g ? g.stages.map((s) => (s.role === 'verify' ? s.label : s.role)) : []
    check(
      '验证方晚完成也不改变 gate.stages 顺序（按 seq 定序）',
      g && order.join(',') === 'split,path,adversarial,plan,isolate,modify,work,验证方 1,验证方 2',
      order.join(','),
    )
    check(
      '并发后加权分/独立性判定与串行一致',
      g && g.verify && g.verify.score === 1 && g.verify.independentEvidence === true,
      g && g.verify ? JSON.stringify({ score: g.verify.score, independent: g.verify.independentEvidence }) : 'no gate',
    )

    /* 对抗性复核的下级之间也并发（3 个下级同时跑） */
    const mkChild = makeSubagents({ dispatchOnAdversarial: ['查点1', '查点2', '查点3'], delayMs: (role) => (role === 'adversarial-sub' ? 180 : 20) })
    ctx.provide('subagents', mkChild.sub)
    t = await run(
      spawnPlan({ adversarial: { ...spawnPlan().adversarial, subagents: { maxChildren: 3, adjudicate: false } } }),
      { sessionId: 's-main', agent: { fake: true } },
    )
    g = latestGate()
    check('对抗性复核下级 3 路并发', mkChild.calls.maxActive >= 3, `maxActive=${mkChild.calls.maxActive}`)
    check('gate.parallel 记下级实际并发数', g && g.parallel && g.parallel.adversarialChildren === 3, g ? JSON.stringify(g.parallel) : 'no gate')

    /* 非法值开跑前拒绝（不进终端、不建子会话） */
    t = await run(spawnPlan({ maxParallel: 9 }), { sessionId: 's-main', agent: { fake: true } })
    check('maxParallel 越界（9）→ 开跑前拒绝', /GATE FAIL/.test(t) && /maxParallel 非法/.test(t), t.slice(0, 200))
    t = await run(spawnPlan({ maxParallel: 0 }), { sessionId: 's-main', agent: { fake: true } })
    check('maxParallel=0 → 开跑前拒绝', /GATE FAIL/.test(t) && /maxParallel 非法/.test(t), t.slice(0, 200))
  }

  /* ── v0.8.0：断点续跑 + 监视快照上限可配（截断必须记账）+ 独立证据 ≥2 份独引 ── */
  section('v0.8.0 断点续跑 / 快照上限 / 独立证据收紧')
  {
    /* ① 快照截断：单元级（docs 下 8 份文档 > 上限 3） */
    const flowMod = await import(pathToFileURL(join(ROOT, 'lib', 'flow.js')).href)
    const { snapshotTree } = flowMod.__flowInternals
    const snapTrunc = snapshotTree(DOCS, { maxFiles: 3 })
    check('快照上限：超过 maxFiles 即截断且 truncated=true', snapTrunc.size === 3 && snapTrunc.truncated === true, `size=${snapTrunc.size} truncated=${snapTrunc.truncated}`)
    const snapFull = snapshotTree(DOCS, { maxFiles: 100 })
    check(
      '快照上限：未超过时不标截断（maxFiles 记账）',
      snapFull.size >= 8 && snapFull.truncated === false && snapFull.maxFiles === 100,
      `size=${snapFull.size} truncated=${snapFull.truncated}`,
    )

    /* ② 非法 snapshotMaxFiles → 开跑前拒绝 */
    t = await run(basePlan({ snapshotMaxFiles: 0 }))
    check('snapshotMaxFiles=0 → 开跑前拒绝', /GATE FAIL/.test(t) && /snapshotMaxFiles 非法/.test(t), t.slice(0, 200))
    t = await run(basePlan({ snapshotMaxFiles: 20001 }))
    check('snapshotMaxFiles 超硬上限 → 拒绝', /GATE FAIL/.test(t) && /snapshotMaxFiles 非法/.test(t), t.slice(0, 200))

    /* ③ 真跑：watch docs（8 文件）+ 上限 3 → gate 记 snapshot.truncated + 一条不阻断的 warning */
    t = await run(basePlan({ watch: ['docs'], snapshotMaxFiles: 3 }))
    g = latestGate()
    check(
      '快照截断记账：gate.snapshot + 一条不阻断的 warning',
      g &&
        g.status === 'done' &&
        g.snapshot &&
        g.snapshot.maxFiles === 3 &&
        g.snapshot.truncated.length === 1 &&
        g.warnings.some((w) => /监视快照达到上限/.test(w)),
      g ? JSON.stringify({ snapshot: g.snapshot, warnings: g.warnings }) : 'no gate',
    )

    /* ④ 独立证据收紧：只有 1 份独引文档（c.md）→ 旧口径会 PASS，新口径必须 FAIL */
    const oneUnique = basePlan({
      verifiers: [
        { name: '验证方1', session: 's-v1', receipt: R('v1'), citations: [doc('a.md'), doc('b.md')], steps: [receiptCmd(R('v1'), 'verify')] },
        {
          name: '验证方2',
          session: 's-v2',
          receipt: R('v2'),
          citations: [doc('a.md'), doc('b.md'), doc('c.md')],
          steps: [receiptCmd(R('v2'), 'verify')],
        },
      ],
    })
    t = await run(oneUnique)
    g = latestGate()
    check(
      '独引文档仅 1 份 → 判无独立证据 FAIL（一份凑数独引不再过）',
      /GATE FAIL/.test(t) && /无独立证据/.test(t) && g && g.verify && g.verify.independentDocs === 1,
      g && g.verify ? JSON.stringify({ n: g.verify.independentDocs, failures: g.failures }) : 'no gate',
    )

    /* ⑤ 断点续跑：先让 work 缺回执（spawn 口径），再用健康 mock 续跑同一条流 */
    const mkFailWork = makeSubagents({ skipRoles: ['work'] })
    ctx.provide('subagents', mkFailWork.sub)
    t = await run(spawnPlan({ roleTimeoutMs: 1200 }), { sessionId: 's-main', agent: { fake: true } })
    g = latestGate()
    const failedFlowId = g && g.flowId
    check(
      '续跑前置：work 缺回执 → FAIL 且留下 state.json',
      /GATE FAIL/.test(t) && g && g.status === 'failed' && existsSync(g.stateFile),
      g ? `status=${g.status} state=${g.stateFile}` : 'no gate',
    )

    const mkResume = makeSubagents({ startIdx: 50 })
    ctx.provide('subagents', mkResume.sub)
    t = await run({ resumeFlowId: failedFlowId, mainSession: 's-main' }, { sessionId: 's-main', agent: { fake: true } })
    g = latestGate()
    const rerunRoles = mkResume.calls.started.map((c) => c.role).sort().join(',')
    check(
      '续跑 → GATE PASS（沿用原 flowId）',
      /GATE PASS/.test(t) && g && g.status === 'done' && g.flowId === failedFlowId,
      `${t.slice(0, 140)} ｜ ${g ? g.failures.join(' / ') : 'no gate'}`,
    )
    check(
      '续跑只补没办完的：work + 两验证方（已完成阶段不重跑）',
      rerunRoles === 'verify,verify,work' && !mkResume.calls.started.some((c) => ['split', 'path', 'plan', 'isolate', 'modify'].includes(c.role)),
      rerunRoles,
    )
    check(
      'gate.resume 记账（第几次进入 / 上一轮已完成阶段 / state.json）',
      g &&
        g.resume &&
        g.resume.resumed === true &&
        g.resume.attempts === 1 &&
        g.resume.fromPhases.includes('adversarial') &&
        !g.resume.fromPhases.includes('work') &&
        g.resume.stateFile === g.stateFile,
      g ? JSON.stringify(g.resume) : 'no gate',
    )
    check(
      '旧失败阶段记录标 superseded（证据保留、不与新记录混淆）',
      g &&
        g.stages.some((s) => s.role === 'work' && s.superseded === true) &&
        g.stages.filter((s) => s.role === 'work' && s.status === 'done').length === 1,
      g ? JSON.stringify(g.stages.filter((s) => s.role === 'work').map((s) => ({ status: s.status, superseded: !!s.superseded }))) : '',
    )
    check('续跑后已完成阶段沿用（split 仍只有一条记录）', g && g.stages.filter((s) => s.role === 'split').length === 1, g ? `split=${g.stages.filter((s) => s.role === 'split').length}` : '')

    /* ⑥ 续跑护栏：不存在 / mainSession 不符 / 已 GATE PASS */
    t = await run({ resumeFlowId: 'flow-does-not-exist', mainSession: 's-main' })
    check('续跑不存在的断点 → 拒绝', /GATE FAIL/.test(t) && /找不到可续跑的断点/.test(t), t.slice(0, 200))
    t = await run({ resumeFlowId: failedFlowId, mainSession: 's-other' })
    check('续跑 mainSession 与断点不符 → 拒绝', /GATE FAIL/.test(t) && /mainSession 不匹配/.test(t), t.slice(0, 200))
    t = await run({ resumeFlowId: failedFlowId, mainSession: 's-main' }, { sessionId: 's-main', agent: { fake: true } })
    check('已 GATE PASS 的流再续跑 → 拒绝（无需续跑）', /GATE FAIL/.test(t) && /无需续跑/.test(t), t.slice(0, 200))
  }

  /* ── v0.9.0：大文件采样哈希 / 内容级证据 / 只读违规还原 / attacks 结构 ── */
  section('v0.9.0 大文件哈希 / 内容级证据 / 只读还原 / attacks 结构')
  {
    const flowMod = await import(pathToFileURL(join(ROOT, 'lib', 'flow.js')).href)
    const { snapshotTree, diffSnapshot } = flowMod.__flowInternals

    /* ① 大文件不再 hash:null：超过 hashMaxBytes 用首尾采样哈希 */
    const bigFile = join(WORK, 'big.bin')
    writeFileSync(bigFile, Buffer.alloc(700 * 1024, 7))
    const stBig = snapshotTree(WORK, { maxFiles: 2000, hashMaxBytes: 512 * 1024 })
    const fpBig = stBig.get('big.bin')
    check(
      '大文件进快照：超 hash 上限用采样哈希（不再 hash:null）',
      fpBig && fpBig.hashKind === 'sample' && typeof fpBig.hash === 'string' && fpBig.hash.length === 64,
      fpBig ? `kind=${fpBig.hashKind} hash=${String(fpBig.hash).slice(0, 12)}` : 'no entry',
    )
    const stFull = snapshotTree(WORK, { maxFiles: 2000, hashMaxBytes: 4 * 1024 * 1024 })
    const fpFull = stFull.get('big.bin')
    check('未超上限仍用整文件哈希（hashKind=full）', fpFull && fpFull.hashKind === 'full', fpFull ? String(fpFull.hashKind) : 'no entry')

    /* ② 采样哈希的盲区由 mtime 兜住：只改中间段（首尾不变）也要判「改动」 */
    const beforeBig = snapshotTree(WORK, { maxFiles: 2000, hashMaxBytes: 512 * 1024 })
    const buf = Buffer.alloc(700 * 1024, 7)
    buf.write('MIDDLE-CHANGED', 300 * 1024)
    writeFileSync(bigFile, buf)
    const later = new Date(Date.now() + 5000)
    utimesSync(bigFile, later, later)
    const afterBig = snapshotTree(WORK, { maxFiles: 2000, hashMaxBytes: 512 * 1024 })
    check(
      '采样哈希 + mtime：中间段被改也能报「改动」',
      diffSnapshot(beforeBig, afterBig).some((x) => x.includes('big.bin')),
      JSON.stringify(diffSnapshot(beforeBig, afterBig)),
    )

    /* ③ 非法 snapshotHashMaxBytes → 开跑前拒绝 */
    t = await run(basePlan({ snapshotHashMaxBytes: 1024 }))
    check('snapshotHashMaxBytes 低于下限 → 拒绝', /GATE FAIL/.test(t) && /snapshotHashMaxBytes 非法/.test(t), t.slice(0, 160))
    t = await run(basePlan({ snapshotHashMaxBytes: 70 * 1024 * 1024 }))
    check('snapshotHashMaxBytes 超硬上限 → 拒绝', /GATE FAIL/.test(t) && /snapshotHashMaxBytes 非法/.test(t), t.slice(0, 160))

    /* ④ 内容级证据：验证方 2 的摘录对不上 → FAIL */
    const badQuotePlan = basePlan({
      verifiers: [
        { name: '验证方1', session: 's-v1', receipt: R('v1'), citations: [doc('a.md'), doc('b.md')], steps: [receiptCmd(R('v1'), 'verify')] },
        {
          name: '验证方2',
          session: 's-v2',
          receipt: R('v2'),
          citations: [doc('a.md'), doc('c.md')],
          steps: [receiptCmd(R('v2'), 'verify', 'pass', '-', ['ok'], 'bad-quote')],
        },
      ],
    })
    t = await run(badQuotePlan)
    g = latestGate()
    check(
      '内容级证据：摘录对不上 → GATE FAIL',
      /GATE FAIL/.test(t) && /内容级证据不合格/.test(t) && g && g.evidenceQuotes && g.evidenceQuotes.violations === 1,
      g ? JSON.stringify(g.evidenceQuotes) : 'no gate',
    )

    /* ⑤ 内容级证据可关：requireEvidenceQuote=false 时无摘录仍 PASS */
    t = await run({ ...badQuotePlan, requireEvidenceQuote: false })
    g = latestGate()
    check(
      'requireEvidenceQuote=false → 无摘录仍 GATE PASS（gate 记账 required=false）',
      /GATE PASS/.test(t) && g && g.status === 'done' && g.evidenceQuotes && g.evidenceQuotes.required === false,
      g ? JSON.stringify({ status: g.status, q: g.evidenceQuotes }) : 'no gate',
    )

    /* ⑥ attacks 结构：只写 target、缺 failure_mode → 形状不合格 */
    const weakPlan = basePlan()
    weakPlan.adversarial = { ...weakPlan.adversarial, steps: [receiptCmd(R('adv'), 'adversarial', 'pass', '-', ['ok'], 'weak')] }
    t = await run(weakPlan)
    check('attacks 缺 failure_mode → 判攻击面不合格', /GATE FAIL/.test(t) && /攻击面不合格/.test(t), t.slice(0, 240))

    /* ⑦ 只读违规自动还原：对抗性复核改监视区已有文件 → 跑完内容回滚到监视前 */
    const origA = readFileSync(doc('a.md'), 'utf8')
    const mkRestore = makeSubagents({})
    const restorePlan = spawnPlan({
      adversarial: {
        ...spawnPlan().adversarial,
        steps: [isWin ? 'echo hacked> docs\\a.md' : 'echo hacked > docs/a.md'],
      },
    })
    ctx.provide('subagents', mkRestore.sub)
    t = await run(restorePlan, { sessionId: 's-main', agent: { fake: true } })
    g = latestGate()
    check(
      '只读违规自动还原：被改文件回写原内容（gate.adversarial.restore 记账）',
      /GATE FAIL/.test(t) &&
        g &&
        g.adversarial &&
        g.adversarial.readOnly === false &&
        g.adversarial.restore &&
        g.adversarial.restore.restored.length >= 1 &&
        readFileSync(doc('a.md'), 'utf8') === origA &&
        g.warnings.some((w) => /已按监视前快照还原/.test(w)),
      g ? JSON.stringify({ readOnly: g.adversarial && g.adversarial.readOnly, restore: g.adversarial && g.adversarial.restore }) : 'no gate',
    )
  }

  section('清理')
  check('临时目录已就绪（无残留 helper 冲突）', existsSync(HELPER))
  if (KEEP) console.log(`  (FLOW_SMOKE_KEEP=1，保留 ${TMP} 供排查)`)
  else rmSync(TMP, { recursive: true, force: true })

  console.log(`\nARCH_FLOW_SMOKE ${fail === 0 ? 'PASS' : 'FAIL'} | pass=${pass} fail=${fail}`)
  if (fail) process.exitCode = 1
}

main().catch((e) => {
  console.error(e)
  process.exitCode = 1
})
