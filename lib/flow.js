/**
 * dsh-arch · 阵型流水线（arch_flow）
 *
 * 把「多角色 + 终端执行」落成一条固定阵型（顺序写死，不接受调用方重排）：
 *
 *   拆分 → 路径 → 对抗性复核（只读、先议路径）→ 规划 → 隔离 → 修改 → 工作 → 验证方（多方）
 *
 * 底层强约束（全部在代码里 fail-closed，不靠 prompt）：
 *   1. 顺序与角色固定：少一个角色、改一次顺序都直接拒绝执行。
 *   2. 主会话不参与工作：mainSession 必须与所有角色会话互不相同（含对抗性复核）。
 *   3. 对抗性复核固定存在：独立会话、只读（执行前后对监视树做快照比对，有任何写入即判失败）。
 *   4. 对抗性复核的依据文档不能与任何其他人的依据文档同内容（按 sha256 判，路径不同但内容相同也算一致）。
 *   5. 不许空耗：每个角色必须交出 receipt(json) 且含非空 findings/evidence，否则该角色无效、整条阵型失败。
 *   6. 多方验证：验证方至少 2 个；按「引用同一份文档」降权——同一文档被 k 个验证方引用，每个引用者在该文档上只拿 1/k 权重。
 *   7. 对抗性复核必须极具攻击性：回执必须带 attacks[]（≥ minAttacks 条具体攻击点，每条写 target + failure_mode）；
 *      「没发现问题 / 建议补充测试 / 整体可行」这类背书不算攻击，攻击面不足直接 FAIL。
 *   8. 久议不决可向下分发（v0.4.0）：对抗性复核在自己的回执里写 dispatch[]（或 undecided:true + unresolved[]），
 *      插件为每条现创建一个「下级复核」子会话（parent=对抗日、独立会话、只读、同样必须交非空回执），
 *      下级沿用与其他角色子会话相同的约束；跑完由插件用 sendMessage 唤醒对抗日写终审回执；
 *      只读快照从对抗开始一直覆盖到终审结束，下级会话同样逐个退班。
 *   9. 全部判定写进 gate.json 落盘；工具只回执与裁决，主会话只核验。
 *   10. 子对话强隔离（v0.3.0 起，v0.3.1 换宿主新原语）：角色会话不是调用方给的字符串 id，而是插件用
 *      `subagents.startActivation` 现创建的真实子会话——独立上下文、非 fork、会话两两不同、
 *      主会话不在其中；每个角色子会话跑完即退班（释放名额）。缺子会话原语一律 fail-closed。
 *      旧口径（调用方声明会话）保留为 declared，必须显式 allowDeclaredSessions:true，
 *      gate 会标 isolation=declared（降级可审计）。
 *
 * v0.5.0 加固（架构层，仍然 fail-closed）：
 *   11. 角色各有独立系统终端：spawn 口径下每个角色的任务由插件在**它自己的系统终端**里跑
 *      （一次角色 = 一次独立终端进程 + 独立 PID + 独立日志），终端记录与 PID 写进 gate；
 *      终端跑失败的角色不允许用回执冒充完成。子会话拿到的只有「终端真实输出摘要 + 日志路径」。
 *   12. 按预演关键词下发 skills：技能来源是 DSH 活体 skills 服务（与已装技能实时同步，服务不可用才回退扫目录），
 *      关键词 = 任务标题 + 角色职责 + 该角色终端命令；命中技能随角色 brief 下发（不塞全文，只给名字+一句话）；
 *      节省 token 类 skills 默认常驻（skills.tokenSavers=false 才关）。技能索引与每角色命中写进 gate。
 *   13. 防幻觉 / 防对话污染 / 防越权：brief 每条都是自包含的（只给本角色输入，不给其他角色会话内容）；
 *      唯一事实来源是终端日志——回执 evidence 必须真实存在、findings 不得为空；
 *      子会话写入审计（执行前后对监视树快照比对）：除回执外任何写入即判「越权」并整条阵型 FAIL；
 *      brief 明禁再派生子智能体/转交任务。
 */

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, relative, resolve } from 'node:path'

/* ───────── 常量 ───────── */

export const FLOW_VERSION = '0.6.2'

/** 对抗性复核派发的「下级复核」：role 与 label 前缀（gate / 回执 / 呈现都按它识别「对抗阵营」）。 */
export const ADV_SUB_ROLE = 'adversarial-sub'
const ADV_CAMP_LABEL = '对抗性复核'
const ADV_SUB_LABEL_PREFIX = '对抗性复核·下级'
/** 对抗性复核向下分发的硬上限（子 agent 活性上限 8，整条阵型已用 9 个名额，故必须串行点卯/退班）。 */
const DEFAULT_MAX_ADV_SUBAGENTS = 3
const HARD_MAX_ADV_SUBAGENTS = 6
/* v0.5.0：对抗性复核是全场最重的角色（要读代码、构造攻击点），120s 默认时限实测会被截断。
   给它一个不低于 7 分钟的下限，且永远不低于调用方给的 roleTimeoutMs。 */
const DEFAULT_ADV_TIMEOUT_MS = 420000
/** 攻击面下限：至少两条具体攻击点，否则「极具攻击性」无从谈起。 */
const DEFAULT_MIN_ATTACKS = 2
const MAX_DISPATCH_FOCUS = 400

/** v0.5.0：按预演关键词下发 skills 的口径。 */
const DEFAULT_SKILL_MAX = 4
const HARD_SKILL_MAX = 8
const MAX_SKILL_BRIEF_CHARS = 120
const MAX_SKILL_QUERY_CHARS = 4000
/** 「节省 token 类」技能（默认常驻下发）：名字命中即算，不做模糊匹配。 */
const TOKEN_SAVER_SKILLS = [
  'token-saver',
  'headroom',
  'caveman',
  'caveman-compress',
  'caveman-review',
  'caveman-commit',
  'dcp-config',
  'dsh-dcp-config',
]
const DEFAULT_SKILL_ROOTS = [join(homedir(), '.agents', 'skills'), join(homedir(), '.dsh', 'skills')]

/** v0.5.0：角色任务由谁在终端里跑。plugin=插件在角色自己的系统终端里跑（默认，可核验）；session=旧口径（子会话自己跑）。 */
const TERMINAL_MODES = ['plugin', 'session']
/* v0.6.2：终端执行路线。此前 plan 里没有 terminalMode，runRoleTerminal 传的是 undefined ⇒
   arch_flow 只能吃引擎 cfg 默认（auto），调用方无法点名 pty/process。auto 与 pty 同义
   （都有宿主终端服务时走会话，不可用则如实记 fallback 回退原生子进程），process 强制原生子进程。 */
const TERMINAL_ROUTES = ['auto', 'pty', 'process']

/** 工作前段 → 对抗性复核 → 工作段。roles 必须严格按 STAGES 顺序出现，各一次。 */
export const STAGES = ['split', 'path', 'plan', 'isolate', 'modify', 'work']
export const STAGE_CN = {
  split: '拆分',
  path: '路径',
  adversarial: '对抗性复核',
  plan: '规划',
  isolate: '隔离',
  modify: '修改',
  work: '工作',
  verify: '验证方',
  [ADV_SUB_ROLE]: '对抗性复核·下级',
}
/** 对抗性复核的位置：split、path 之后，plan 之前。 */
export const ADVERSARIAL_AFTER = 'path'

const VERDICT_VALUE = { pass: 1, warn: 0.5, fail: 0 }
const MAX_SNAPSHOT_FILES = 2000
const MAX_HASH_BYTES = 1024 * 1024
const SKIP_DIRS = new Set(['.git', 'node_modules', '.tmp-arch-smoke', '.tmp-flow-smoke', 'runs', 'flows', '.dsh-arch-receipts'])

/* ───────── 小工具 ───────── */

function textOut() {
  return {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: String(value ?? '') }],
  }
}

function newFlowId() {
  return `flow-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
}

function sha256File(file) {
  try {
    const buf = readFileSync(file)
    return createHash('sha256').update(buf).digest('hex')
  } catch {
    return null
  }
}

function shortHash(h) {
  return String(h || '').slice(0, 12)
}

function fmtMs(ms) {
  if (ms == null || !Number.isFinite(Number(ms))) return '-'
  const n = Number(ms)
  return n < 1000 ? `${n}ms` : `${(n / 1000).toFixed(1)}s`
}

function resolvePath(p, base) {
  if (!p) return ''
  const raw = String(p).replace(/^~(?=$|[\\/])/, process.env.USERPROFILE || process.env.HOME || '')
  return resolve(base || process.cwd(), raw)
}

function walkFiles(root, out, depth = 0) {
  if (out.length >= MAX_SNAPSHOT_FILES || depth > 12) return out
  let entries = []
  try {
    entries = readdirSync(root, { withFileTypes: true })
  } catch {
    return out
  }
  for (const ent of entries) {
    if (out.length >= MAX_SNAPSHOT_FILES) break
    if (SKIP_DIRS.has(ent.name)) continue
    const full = join(root, ent.name)
    let st = null
    try {
      st = statSync(full)
    } catch {
      continue
    }
    if (st.isDirectory()) {
      walkFiles(full, out, depth + 1)
    } else if (st.isFile()) {
      const fp = { path: full, size: st.size, mtimeMs: st.mtimeMs, hash: null }
      if (st.size <= MAX_HASH_BYTES) fp.hash = sha256File(full)
      out.push(fp)
    }
  }
  return out
}

/** 对监视根做内容快照（小文件用 sha256，大文件用 size+mtime）。 */
function snapshotTree(root) {
  const map = new Map()
  const files = walkFiles(root, [])
  for (const f of files) map.set(relative(root, f.path), f)
  return map
}

/** 比对两份快照，返回「新增 / 删除 / 改动」的文件相对路径。 */
function diffSnapshot(before, after) {
  const changes = []
  for (const [rel, a] of after) {
    const b = before.get(rel)
    if (!b) changes.push(`新增 ${rel}`)
    else if (a.size !== b.size || a.hash !== b.hash || (a.hash == null && a.mtimeMs !== b.mtimeMs)) changes.push(`改动 ${rel}`)
  }
  for (const rel of before.keys()) {
    if (!after.has(rel)) changes.push(`删除 ${rel}`)
  }
  return changes
}

/** 从工具 exec 上下文尽力取调用方会话 id（不同 DSH 版本字段不一样）。 */
function callerSessionFromExec(exec) {
  const tries = [
    () => exec?.sessionId,
    () => exec?.session?.id,
    () => exec?.agent?.sessionId,
    () => exec?.agent?.id,
    () => exec?.agent?.session?.id,
  ]
  for (const t of tries) {
    try {
      const v = t()
      if (typeof v === 'string' && v.trim()) return v.trim()
    } catch {
      /* 继续 */
    }
  }
  return ''
}

/* ───────── 子对话强隔离（v0.3.0 起，v0.3.1 换宿主新原语） ───────── */

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

/** 取宿主服务（ctx.get 优先；与 index.js 的 svc 同口径）。 */
function svc(ctx, key) {
  try {
    if (ctx && typeof ctx.get === 'function') {
      const s = ctx.get(key)
      if (s) return s
    }
  } catch {
    /* 未挂该服务 */
  }
  try {
    return ctx ? ctx[key] : undefined
  } catch {
    return undefined
  }
}

function slugPart(s) {
  return (
    String(s || 'x')
      .toLowerCase()
      .replace(/[^0-9a-z\u4e00-\u9fa5]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 24) || 'x'
  )
}

/** 回执里的 role 字段：验证方统一写 verify（与 gate 的 verify 口径一致）。 */
function receiptRoleOf(role) {
  return role
}

/** 是否属于「对抗阵营」（对抗性复核本体 + 它派发的下级）：阵营内部共用依据文档不算撞车。 */
function inAdvCamp(owner) {
  const s = String(owner || '')
  return s === ADV_CAMP_LABEL || s.startsWith(ADV_SUB_LABEL_PREFIX)
}

function worstVerdict(a, b) {
  const av = VERDICT_VALUE[a] ?? VERDICT_VALUE.fail
  const bv = VERDICT_VALUE[b] ?? VERDICT_VALUE.fail
  return av <= bv ? a : b
}

function dedupeStrings(list) {
  const out = []
  const seen = new Set()
  for (const x of list || []) {
    const s = String(x ?? '').trim()
    if (!s || seen.has(s)) continue
    seen.add(s)
    out.push(s)
  }
  return out
}

/* ───────── v0.5.0：按预演关键词下发 skills（与 DSH 活体技能库同步） ───────── */

/** 极简 frontmatter 解析（只取 name/description/disable-model-invocation；不引依赖）。 */
function parseSkillFrontmatter(text) {
  const out = {}
  const m = String(text || '').match(/^---\r?\n([\s\S]*?)\r?\n---/)
  if (!m) return out
  for (const line of m[1].split(/\r?\n/)) {
    const hit = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
    if (!hit) continue
    out[hit[1]] = hit[2].replace(/^['"]|['"]$/g, '').trim()
  }
  return out
}

/** 技能摘要归一（只留关键词检索要用的字段；调用策略按 invocation.modelInvocable 过滤）。 */
function normSkillEntry(x) {
  if (!x || typeof x !== 'object') return null
  const name = String(x.name || '').trim()
  if (!name) return null
  const invocation = x.invocation && typeof x.invocation === 'object' ? x.invocation : {}
  return {
    name,
    description: String(x.description || '').trim(),
    whenToUse: String(x.whenToUse || '').trim(),
    source: String(x.source || ''),
    modelInvocable: invocation.modelInvocable !== false,
  }
}

/** 回退路径：活体服务不可用时直接扫技能目录（默认 ~/.agents/skills 与 ~/.dsh/skills）。 */
function scanSkillRoots(roots) {
  const out = []
  for (const root of roots || []) {
    let names = []
    try {
      names = readdirSync(root)
    } catch {
      continue
    }
    for (const n of names) {
      const f = join(root, n, 'SKILL.md')
      if (!existsSync(f)) continue
      let text = ''
      try {
        text = readFileSync(f, 'utf8')
      } catch {
        continue
      }
      const fm = parseSkillFrontmatter(text)
      out.push({
        name: fm.name || n,
        description: fm.description || '',
        whenToUse: '',
        source: root,
        modelInvocable: fm['disable-model-invocation'] !== 'true',
      })
    }
  }
  return out
}

/** 把 hooks/config 里的技能根归一成绝对路径数组。 */
function skillRootsOf(cfg, hooks) {
  const raw = []
  const push = (v) => {
    if (!v) return
    if (Array.isArray(v)) for (const x of v) push(x)
    else raw.push(String(v).trim())
  }
  push(cfg && cfg.roots)
  if (!raw.length) push(hooks && hooks.skillRoots)
  const roots = raw.filter(Boolean).map((r) => resolvePath(r))
  return roots.length ? roots : DEFAULT_SKILL_ROOTS
}

/**
 * 技能目录：**优先读 DSH 活体 skills 服务**（与已装/已禁用技能实时同步；禁用过的 modelInvocable=false 不下发），
 * 服务不可用才回退扫目录。返回值同时给 gate 记账（source/total/visible）。
 */
async function readSkillCatalog(hooks, cfg) {
  const meta = { source: 'none', detail: '未取到技能库', complete: true, total: 0, visible: 0, roots: [] }
  const entries = []
  let skillsSvc = null
  try {
    skillsSvc = hooks && hooks.ctx ? svc(hooks.ctx, 'skills') : null
  } catch {
    skillsSvc = null
  }
  if (skillsSvc && typeof skillsSvc.list === 'function') {
    try {
      const list = await skillsSvc.list({ cwd: cfg.cwd || undefined })
      for (const x of Array.isArray(list) ? list : []) {
        const e = normSkillEntry(x)
        if (e) entries.push(e)
      }
      meta.source = 'dsh-skills'
      meta.detail = 'DSH 活体技能服务'
    } catch (e) {
      meta.source = 'dsh-skills-error'
      meta.detail = `DSH 活体技能服务读取失败：${e?.message ?? e}`
    }
  }
  if (!entries.length) {
    const roots = skillRootsOf(cfg, hooks)
    meta.roots = roots
    const scanned = scanSkillRoots(roots)
    if (scanned.length) {
      entries.push(...scanned)
      meta.source = meta.source === 'dsh-skills-error' ? 'dir-scan-after-error' : 'dir-scan'
      meta.detail = `${meta.detail}｜回退扫目录 ${roots.join('、')}`
    } else if (meta.source === 'none') {
      meta.source = 'none'
      meta.detail = '技能库为空（活体服务不可用，目录里也没有技能）'
    }
  }
  const visible = entries.filter((e) => e.modelInvocable !== false)
  meta.total = entries.length
  meta.visible = visible.length
  return { meta, entries: visible }
}

/** 中文按 2-gram、英文按词切（关键词检索够用，不引分词库）。 */
function tokenize(text) {
  const s = String(text || '').toLowerCase()
  const out = new Set()
  if (!s.trim()) return out
  for (const m of s.matchAll(/[a-z0-9][a-z0-9_.+-]{1,}/g)) out.add(m[0])
  for (const m of s.matchAll(/[\u4e00-\u9fff]{2,}/g)) {
    const run = m[0]
    for (let i = 0; i + 2 <= run.length; i++) out.add(run.slice(i, i + 2))
  }
  return out
}

function isTokenSaverSkill(name) {
  const n = String(name || '').toLowerCase()
  return TOKEN_SAVER_SKILLS.some((t) => n.includes(t))
}

/**
 * 按预演关键词给某个角色挑技能：节省 token 类默认常驻（最多 2 条），其余按关键词命中分排序。
 * 排序口径：技能名命中 +3/词，description/whenToUse 命中 +1/词；同分按名字稳定排序。
 */
function pickRoleSkills(queryText, catalog, cfg) {
  const picked = []
  const seen = new Set()
  const max = Math.max(1, Math.min(HARD_SKILL_MAX, Number(cfg.max) || DEFAULT_SKILL_MAX))
  const push = (e, reason, score) => {
    if (!e || seen.has(e.name) || picked.length >= max) return
    seen.add(e.name)
    picked.push({
      name: e.name,
      description: String(e.description || e.whenToUse || '').trim().slice(0, MAX_SKILL_BRIEF_CHARS),
      reason,
      score,
    })
  }
  if (cfg.tokenSavers !== false) {
    for (const e of catalog.entries) {
      if (!isTokenSaverSkill(e.name)) continue
      push(e, '节省 token（默认常驻）', 0)
      if (picked.filter((p) => p.reason.startsWith('节省 token')).length >= 2) break
    }
  }
  const tokens = tokenize(String(queryText || '').slice(0, MAX_SKILL_QUERY_CHARS))
  if (tokens.size) {
    const scored = []
    for (const e of catalog.entries) {
      if (seen.has(e.name)) continue
      const nameTokens = tokenize(String(e.name).replace(/[-_]+/g, ' '))
      const textTokens = tokenize(`${e.description} ${e.whenToUse}`)
      let score = 0
      for (const t of tokens) {
        if (nameTokens.has(t)) score += 3
        else if (textTokens.has(t)) score += 1
      }
      if (score > 0) scored.push({ e, score })
    }
    scored.sort((a, b) => b.score - a.score || String(a.e.name).localeCompare(String(b.e.name)))
    for (const s of scored) push(s.e, `关键词命中 ${s.score} 分`, s.score)
  }
  return picked
}

/** 角色 brief 里的技能段（只给名字+一句话，不塞全文——全文由子会话用 skill 工具按需加载）。 */
function skillBriefLines(picked, meta) {
  const L = []
  L.push('## DSH 技能（按预演关键词从活体技能库检索后下发）')
  L.push(`技能库：${meta.detail || meta.source}（共 ${meta.total} 条，可下发 ${meta.visible} 条）`)
  if (!picked.length) {
    L.push('本角色没有命中技能：需要时可用 skill 工具按名加载，但不要凭记忆编造技能内容。')
    return L
  }
  for (const s of picked) L.push(`- ${s.name}：${s.description || '(无描述)'}${s.reason ? `（${s.reason}）` : ''}`)
  L.push('用法：需要细节时用 skill 工具按名加载全文（渐进式披露）；技能内容只从技能库读，不许编造。')
  return L
}

/** 计划里的 skills 配置：默认开启、节省 token 类常驻、每角色最多 4 条。 */
function normSkillsConfig(raw) {
  const o = raw && typeof raw === 'object' ? raw : {}
  const max = Number.isFinite(Number(o.max)) ? Math.max(1, Math.min(HARD_SKILL_MAX, Math.floor(Number(o.max)))) : DEFAULT_SKILL_MAX
  return {
    enabled: o.enabled !== false,
    tokenSavers: o.tokenSavers !== false,
    max,
    roots: Array.isArray(o.roots) ? o.roots.map(String) : [],
  }
}


/** 从回执里取攻击点（attacks[]）：支持 {target,failure_mode} 对象与纯字符串，缺字段补占位。 */
function normAttacks(rc) {
  const data = rc && rc.data ? rc.data : null
  const raw = data && Array.isArray(data.attacks) ? data.attacks : []
  const out = []
  for (const a of raw) {
    if (a && typeof a === 'object') {
      const target = String(a.target ?? a.at ?? a.attack ?? '').trim()
      const mode = String(a.failure_mode ?? a.failureMode ?? a.fail_mode ?? a.mode ?? '').trim()
      if (target || mode) out.push({ target: target || '(未写 target)', failure_mode: mode || '(未写 failure_mode)' })
    } else if (typeof a === 'string' && a.trim()) {
      out.push({ target: a.trim().slice(0, 120), failure_mode: '(未写 failure_mode)' })
    }
  }
  return out
}

/** 攻击面不足 = FAIL（「极具攻击性」是硬要求，不是建议）。 */
function attackShortfall(attacks, min) {
  const need = Math.max(0, Math.floor(Number(min) || 0))
  if (!need || attacks.length >= need) return ''
  return `对抗性复核攻击面不足：attacks 至少 ${need} 条具体攻击点（当前 ${attacks.length} 条）——对抗性复核必须极具攻击性，只背书不算复核`
}

/** 角色职责一句话（写进子会话 brief；判定不靠它，靠回执/快照/哈希）。 */
const ROLE_DUTY = {
  split: '把任务拆成可执行的子任务清单，并给出验收口径',
  path: '给出实现路径（步骤、依赖、风险、回滚）',
  plan: '按已议定的路径出详细执行计划（顺序、产物、检查点、验收）',
  isolate: '确认隔离边界（工作目录、改动范围、不许触碰的文件/目录）',
  modify: '按计划修改文件（改动最小、可回滚）',
  work: '在工作目录执行终端命令完成实现与自查',
  adversarial: '对抗性复核（红队）：只读、极具攻击性——假设方案一定是错的，主动构造反例/边界/并发/顺序/回滚失败场景，至少给 2 条具体攻击点；判不了就向下分发，不要背书',
  [ADV_SUB_ROLE]: '对抗性复核·下级：只查父复核交办的那一个查点，只读；给结论与依据，否证父复核假设要直接写出来',
  verify: '验证方：按验收口径核验产出，给 verdict 与证据文档。gate.json 由插件在阵型末尾统一写盘，你核验时它通常还没生成——不要以「gate 未生成」「某项只有调用方可证」为降级理由，只判你自己能取证的实际产物与行为',
}

/** 角色命令里的 {{receipt}} 占位符 → 插件为该角色生成的绝对回执路径。 */
function renderBriefCmd(cmd, receiptPath) {
  return String(cmd).replace(/\{\{\s*receipt\s*\}\}/g, receiptPath)
}

/**
 * 角色子会话 brief：自包含（不继承主线上下文），写明终端命令与回执契约。
 * 子会话唯一允许写入的位置是插件指定的回执路径。
 */
function buildRoleBrief(plan, actor, role, label, receiptPath, base, opts = {}) {
  const L = []
  L.push(`你是「${label}」角色子会话（独立会话 · 强隔离）。`)
  L.push('你与主会话、其他角色会话互不共享上下文；主会话只核验、不参与工作。')
  L.push(`任务：${plan.title}`)
  L.push(`工作目录：${base}`)
  L.push(`本角色职责：${ROLE_DUTY[role] || role}`)
  L.push('')
  L.push('【隔离与越权边界（硬约束，插件审计）】')
  L.push('- 你只拿到本角色的输入；主会话/其他角色会话的上下文不在你这里，也不许猜测它们的内容（防对话污染）。')
  L.push('- 禁止创建子智能体、禁止把任务转交其他会话（越权）。')
  L.push('- 除回执文件外禁止创建/修改/删除任何文件；插件会在你执行前后对监视树做快照比对，发现其他写入立即判越权、整条阵型失败。')
  L.push('- 唯一事实来源是插件给出的终端日志与真实文件；不许编造命令输出、文件内容、行号或测试结果（防幻觉）。')
  L.push('')
  const term = opts.terminal || null
  if (term) {
    L.push('## 独立系统终端（插件已在你的专属终端执行，这就是你的输入）')
    L.push(
      `- 终端：${term.shell || 'system'}｜run ${term.runId}｜${(term.steps || []).length} 步｜状态 ${term.status}｜pid ${(term.pids || []).join('/') || '-'}`,
    )
    for (let i = 0; i < (term.steps || []).length; i++) {
      const st = term.steps[i]
      const cmd = String(st.cmd ?? actor.steps[i]?.cmd ?? '').slice(0, 220)
      L.push(`  ${i + 1}. ${cmd}`)
      L.push(`     → exit=${st.exitCode ?? '-'}｜pid=${st.pid ?? '-'}｜${fmtMs(st.ms ?? 0)}｜日志：${st.logPath || '-'}`)
      const tail = String(st.tail || '').trim()
      if (tail) {
        const lines = tail.split(/\r?\n/).slice(-6).join(' / ').slice(0, 400)
        L.push(`     输出摘录：${lines}`)
      }
    }
    L.push('- 上面命令已由插件执行完，不要重复执行；你的任务是读真实输出、给本角色判定与回执。')
    L.push('- 允许你自己再跑只读命令补充取证；任何写入都会被快照审计判越权。')
  } else {
    L.push('必须用系统终端工具逐条执行以下命令（按顺序，不要改写命令）：')
    for (let i = 0; i < actor.steps.length; i++) L.push(`  ${i + 1}. ${renderBriefCmd(actor.steps[i].cmd, receiptPath)}`)
  }
  L.push('')
  if (Array.isArray(opts.skills) && opts.skillMeta) {
    L.push(...skillBriefLines(opts.skills, opts.skillMeta))
    L.push('')
  }
  L.push('完成后必须把回执 JSON 写到（绝对路径，这是你唯一允许写入的位置）：')
  L.push(`  回执路径：${receiptPath}`)
  L.push(`  回执 role 字段必须为：${receiptRoleOf(role)}`)
  L.push('回执格式：{"role":"<上面的 role>","verdict":"pass|warn|fail","findings":["至少一条非空 finding"],"evidence":["<真实存在的证据文件绝对路径>"]}')
  L.push('要求：findings 至少 1 条非空；evidence 里的文件必须真实存在；不许空回执（空回执＝没干活，整条阵型判失败）。')
  L.push('')
  if (role === 'adversarial') {
    const minAttacks = Math.max(1, Math.floor(Number(opts.minAttacks) || DEFAULT_MIN_ATTACKS))
    L.push('【攻击性硬要求】你是红队，不是背书人：目标是击穿这份路径/计划，不是确认它可行。')
    L.push(
      `- 回执必须带 attacks 数组，至少 ${minAttacks} 条：{"attacks":[{"target":"<被攻击对象：文件/命令/假设/时序/边界>","failure_mode":"<具体怎么失效：输入/边界/并发/顺序/回滚/数据丢失>"}]}`,
    )
    L.push('- 「没发现问题」「整体可行」「建议补充测试」「可以再完善」都不算 attack；必须给出具体、可判定或可复现的失效方式。')
    L.push('- 只有每条 attack 都写明「为何不足以阻断」并附验证依据，才允许 verdict=pass；否则给 warn/fail。')
    L.push('【只读硬约束】你是对抗性复核：除上面的回执文件外，禁止创建/修改/删除任何文件；只许读取与执行只读命令。')
    L.push('插件会在你执行前后对监视树做快照比对：发现任何其他写入，立即判你违规、整条阵型失败。')
    if (opts.fanout) {
      L.push('')
      L.push('【久议不决可向下分发】若某处你判不了（缺证据、需多路取证、两条线索互相矛盾），不要猜、也不要一个人硬扛：')
      L.push('- 在本回执里写 dispatch 数组，插件会为每条现创建一个「下级复核」子会话（独立会话·强隔离·只读），它们与你受同样的约束。')
      L.push(`- dispatch 条目格式：{"focus":"<一句可执行的具体查点>","citations":["<只读依据文档绝对路径>"]}；最多 ${Math.max(1, Math.floor(Number(opts.maxChildren) || DEFAULT_MAX_ADV_SUBAGENTS))} 条。`)
      L.push('- 等价写法：undecided:true + unresolved:["<查点>", ...]。')
      L.push('- 不需要分发就不写 dispatch（照常给 verdict，不会因此扣分）。')
      L.push(`- 若触发分发，插件随后会用 sendMessage 把下级回执摘要发给你；你必须再写一份终审回执（role 仍是 adversarial，同样带 attacks）：${opts.finalReceiptPath || '(未分配)'}`)
      L.push('- 终审里由你裁决：逐条处置下级结论（采纳/驳回＋理由），最终 verdict 以终审为准。')
    }
    L.push('')
  }
  L.push(`依据文档（只读参考）：${(actor.citations || []).join('；')}`)
  L.push('完成后只回一行：DONE')
  return L.join('\n')
}

/**
 * 下级复核子会话 brief：父复核「久议不决」时交办的单个查点。
 * 约束与其他角色子会话一致：独立会话、只读、必须交回执（findings 非空、evidence 真实存在）。
 */
function buildSubBrief(plan, parentLabel, item, label, receiptPath, base) {
  const L = []
  L.push(`你是「${label}」角色子会话（独立会话 · 强隔离）——父复核「${parentLabel}」久议不决，把下面这一查点交给你。`)
  L.push('你与主会话、父复核、其他角色会话互不共享上下文；主会话只核验、不参与工作。')
  L.push('禁止创建子智能体、禁止转交任务；除回执外禁止写入任何文件（插件快照审计）。')
  L.push(`任务：${plan.title}`)
  L.push(`工作目录：${base}`)
  L.push(`本角色职责：${ROLE_DUTY[ADV_SUB_ROLE]}`)
  L.push(`父复核交办的查点：${item.focus}`)
  L.push('')
  L.push('用只读手段自己核实这个查点（读文件、跑只读命令）；不要接受父复核的结论。')
  L.push('执行完后，必须把回执 JSON 写到（绝对路径，这是你唯一允许写入的位置）：')
  L.push(`  回执路径：${receiptPath}`)
  L.push(`  回执 role 字段必须为：${receiptRoleOf(ADV_SUB_ROLE)}`)
  L.push(
    '回执格式：{"role":"adversarial-sub","verdict":"pass|warn|fail","findings":["至少一条非空 finding：这个查点的结论与依据"],"evidence":["<真实存在的证据文件绝对路径>"]}',
  )
  L.push('要求：findings 至少 1 条非空；若结论否证了父复核的假设，直接写出来；不许空回执（空回执＝没干活，整条阵型判失败）。')
  L.push('')
  L.push('【只读硬约束】除上面的回执文件外，禁止创建/修改/删除任何文件；只许读取与执行只读命令。')
  L.push('插件会在你执行前后对监视树做快照比对：发现任何其他写入，立即判你违规、整条阵型失败。')
  L.push('')
  const cites = Array.isArray(item.citations) ? item.citations : []
  L.push(`依据文档（只读参考）：${cites.join('；') || '(未指定，按查点自行取证)'}`)
  L.push('完成后只回一行：DONE')
  return L.join('\n')
}

/* ───────── 入参规整 ───────── */

function normSteps(steps, label) {
  if (!Array.isArray(steps) || !steps.length) {
    return { error: `${label} 缺少终端命令（steps 必须是非空数组）` }
  }
  const out = []
  for (let i = 0; i < steps.length; i++) {
    const raw = steps[i]
    const o = typeof raw === 'string' ? { cmd: raw } : raw ?? {}
    if (typeof o.cmd !== 'string' || !o.cmd.trim()) {
      return { error: `${label} 第 ${i + 1} 条命令为空` }
    }
    out.push({
      name: String(o.name || `步骤 ${i + 1}`).trim() || `步骤 ${i + 1}`,
      cmd: o.cmd,
      cwd: o.cwd || null,
      timeoutMs: o.timeoutMs,
      expect: o.expect,
      allowFail: o.allowFail === true,
    })
  }
  return { steps: out }
}

function normCitationList(list, label) {
  if (!Array.isArray(list) || !list.length) {
    return { error: `${label} 缺少 citations（依据文档路径数组，必须非空）` }
  }
  const out = []
  for (const raw of list) {
    if (typeof raw !== 'string' || !raw.trim()) return { error: `${label} 的 citations 含空路径` }
    out.push(raw.trim())
  }
  return { citations: out }
}

/**
 * 对抗性复核的「久议不决 ⇒ 向下分发」配置（v0.4.0）。
 * spawn 口径默认开启（maxChildren 默认 3、硬上限 6）；declared 口径没有子会话原语，只能记警告。
 */
function normAdversarialFanout(raw, spawn) {
  const o = raw && typeof raw === 'object' ? raw : {}
  const clamp = (v, def, lo, hi) => {
    const n = Math.floor(Number(v))
    if (!Number.isFinite(n)) return def
    return Math.max(lo, Math.min(hi, n))
  }
  const minAttacks = clamp(o.minAttacks ?? DEFAULT_MIN_ATTACKS, DEFAULT_MIN_ATTACKS, 1, 9)
  let enabled = spawn
  let maxChildren = DEFAULT_MAX_ADV_SUBAGENTS
  let adjudicate = true
  const sub = o.subagents
  if (sub === false) {
    enabled = false
  } else if (sub && typeof sub === 'object') {
    if (sub.enabled === false) enabled = false
    maxChildren = clamp(sub.maxChildren ?? DEFAULT_MAX_ADV_SUBAGENTS, DEFAULT_MAX_ADV_SUBAGENTS, 1, HARD_MAX_ADV_SUBAGENTS)
    if (sub.adjudicate === false) adjudicate = false
  }
  const mode = !spawn ? 'declared-skipped' : enabled ? 'spawn' : 'off'
  if (!spawn) enabled = false
  return { minAttacks, fanout: { enabled: enabled === true, mode, maxChildren, adjudicate } }
}

/**
 * 从对抗性复核首轮回执里读「久议不决」的分发请求：
 *   dispatch:[{focus, citations?}]，或 undecided:true + unresolved:[string]。
 * 超出 maxChildren 的部分截断并记账；条目非法只记 rejected，不阻断。
 */
function parseAdversarialDispatch(data, actor, cfg) {
  const out = { trigger: 'none', items: [], truncated: 0, rejected: [] }
  if (!data || typeof data !== 'object') return out
  const raw = []
  if (Array.isArray(data.dispatch)) {
    for (const d of data.dispatch) {
      if (d && typeof d === 'object' && String(d.focus ?? d.item ?? d.query ?? '').trim()) raw.push(d)
      else if (typeof d === 'string' && d.trim()) raw.push({ focus: d })
      else out.rejected.push('dispatch 条目缺少 focus')
    }
    if (raw.length) out.trigger = 'dispatch'
  }
  if (!raw.length && data.undecided === true) {
    const list = Array.isArray(data.unresolved) ? data.unresolved : []
    for (const u of list) if (String(u ?? '').trim()) raw.push({ focus: u })
    if (raw.length) out.trigger = 'undecided'
  }
  if (!raw.length) return out
  for (const d of raw) {
    const focus = String(d.focus ?? d.item ?? d.query).trim().slice(0, MAX_DISPATCH_FOCUS)
    let citations = []
    if (Array.isArray(d.citations) && d.citations.length) {
      const norm = normCitationList(d.citations, `${ADV_SUB_LABEL_PREFIX} 的依据文档`)
      if (norm.error) {
        out.rejected.push(norm.error)
        continue
      }
      citations = norm.citations
    }
    /* 没给依据就沿用父复核的依据（同阵营共用不算撞车）。 */
    out.items.push({ focus, citations: citations.length ? citations : (actor.citations || []).slice(0, 2) })
  }
  if (out.items.length > cfg.maxChildren) {
    out.truncated = out.items.length - cfg.maxChildren
    out.items = out.items.slice(0, cfg.maxChildren)
  }
  return out
}

function normActor(o, label, opts = {}) {
  if (!o || typeof o !== 'object') return { error: `缺少 ${label}` }
  const spawn = opts.spawn === true
  const session = String(o.session || '').trim()
  if (spawn) {
    /* 强隔离口径：会话由插件现创建，调用方不许指定会话 id，也不许指定回执路径。 */
    if (session) {
      return { error: `${label} 不得指定 session：子对话强隔离模式（默认）下子会话由插件用 subagents.startActivation 现创建，不是调用方声明的字符串 id` }
    }
    if (o.receipt) return { error: `${label} 不得指定 receipt：回执路径由插件在子会话目录生成` }
  } else if (!session) {
    return { error: `${label} 缺少 session（declared 口径必须给真实会话 id；默认强隔离口径请不要传 session）` }
  }
  const st = normSteps(o.steps, label)
  if (st.error) return { error: st.error }
  const receipt = String(o.receipt || '').trim()
  if (!spawn && !receipt) return { error: `${label} 缺少 receipt（该角色必须交出回执 json 文件路径，不许空耗）` }
  const ct = normCitationList(o.citations, label)
  if (ct.error) return { error: ct.error }
  return {
    actor: {
      session,
      name: String(o.name || label).trim() || label,
      steps: st.steps,
      receipt,
      citations: ct.citations,
    },
  }
}

/**
 * 阵型校验：顺序、角色、会话隔离、回执要求。返回 { plan } 或 { error }。
 * 顺序是第一道闸——这里不通，一条终端命令都不会跑。
 */
export function validateFlowPlan(args = {}) {
  const mainSession = String(args.mainSession || '').trim()
  if (!mainSession) return { error: '缺少 mainSession：必须显式给出主会话 id（主会话只核验，不参与工作）' }

  /* 会话策略：默认 spawn＝插件现创建子会话（强隔离）；declared 仅作显式降级口径。 */
  const policy = String(args.sessionPolicy || 'spawn').toLowerCase()
  if (policy !== 'spawn' && policy !== 'declared') return { error: `sessionPolicy 非法：${args.sessionPolicy}（只允许 spawn / declared）` }
  if (policy === 'declared' && args.allowDeclaredSessions !== true) {
    return {
      error:
        '声明式会话（declared）会绕过「子对话强隔离」：默认必须由插件创建真实子会话。确需旧口径请显式传 allowDeclaredSessions:true（gate 会标 isolation=declared 供审计）。',
    }
  }
  const spawn = policy === 'spawn'

  if (!Array.isArray(args.stages)) return { error: '缺少 stages（角色数组）' }

  const byRole = new Map()
  for (let i = 0; i < args.stages.length; i++) {
    const s = args.stages[i] ?? {}
    const role = String(s.role || '').trim()
    if (!STAGES.includes(role)) return { error: `stages[${i}] 的角色非法：${role || '(空)'}；只允许 ${STAGES.join(' / ')}` }
    if (byRole.has(role)) return { error: `角色 ${STAGE_CN[role]} 重复出现；每个角色只能有一个` }
    const actor = normActor(s, `角色「${STAGE_CN[role]}」`, { spawn })
    if (actor.error) return { error: actor.error }
    byRole.set(role, { role, ...actor.actor })
  }
  const missing = STAGES.filter((r) => !byRole.has(r))
  if (missing.length) {
    return { error: `阵型缺角色：${missing.map((r) => STAGE_CN[r]).join('、')}（顺序必须为 ${STAGES.map((r) => STAGE_CN[r]).join(' → ')}）` }
  }
  const got = args.stages.map((s) => String(s?.role || '').trim())
  const want = STAGES
  if (got.length !== want.length || got.some((r, i) => r !== want[i])) {
    return { error: `角色顺序错误：收到 ${got.map((r) => STAGE_CN[r] || r).join(' → ')}；必须为 ${want.map((r) => STAGE_CN[r]).join(' → ')}` }
  }

  const adv = normActor(args.adversarial, '对抗性复核', { spawn })
  if (adv.error) return { error: adv.error }
  const fan = normAdversarialFanout(args.adversarial, spawn)

  if (!Array.isArray(args.verifiers) || args.verifiers.length < 2) {
    return { error: '验证方不足：verifiers 至少 2 个（多方验证）' }
  }
  const verifiers = []
  for (let i = 0; i < args.verifiers.length; i++) {
    const v = normActor(args.verifiers[i], `验证方 ${i + 1}`, { spawn })
    if (v.error) return { error: v.error }
    verifiers.push({ role: 'verify', ...v.actor })
  }

  /* ── 硬约束：主会话与所有角色必须是不同对话（对抗性复核尤其不能与主对话同一） ──
     spawn 口径：会话全由插件创建，调用方一个会话 id 都进不来（更硬的隔离）；
     declared 口径：退回对账，逐个核会话 id。 */
  const actors = [...STAGES.map((r) => byRole.get(r)), adv.actor, ...verifiers]
  if (!spawn) {
    const seen = new Map()
    for (const a of actors) {
      const prev = seen.get(a.session)
      if (prev) return { error: `会话冲突：「${prev}」与「${a.name}」用了同一个会话 id（${a.session}）；每个角色必须是独立对话` }
      seen.set(a.session, a.name)
    }
    if (seen.has(mainSession)) {
      const who = seen.get(mainSession)
      return { error: `主会话不得参与工作：角色「${who}」使用了主会话 id（${mainSession}）` }
    }
    if (adv.actor.session === mainSession) return { error: '主对话与对抗性复核不能为同一对话' }
  }

  /* v0.5.0：角色任务在谁的终端里跑（默认插件在角色自己的系统终端里跑，可核验），以及 skills 下发配置。 */
  const terminalRaw = args.terminal == null ? 'plugin' : String(args.terminal).trim().toLowerCase()
  if (!TERMINAL_MODES.includes(terminalRaw)) {
    return { error: `terminal 非法：${args.terminal}；只允许 ${TERMINAL_MODES.join(' / ')}（默认 plugin＝插件在每个角色自己的系统终端执行其任务）` }
  }
  const skillsCfg = normSkillsConfig(args.skills)

  /* v0.6.2：角色任务的终端执行路线可由调用方点名（此前 plan 里没有这个字段 ⇒ 恒吃引擎默认）。 */
  const terminalModeRaw = args.terminalMode == null ? '' : String(args.terminalMode).trim().toLowerCase()
  if (terminalModeRaw && !TERMINAL_ROUTES.includes(terminalModeRaw)) {
    return { error: `terminalMode 非法：${args.terminalMode}；只允许 ${TERMINAL_ROUTES.join(' / ')}（默认 auto＝优先宿主终端会话，不可用则如实记 fallback 回退原生子进程）` }
  }

  const watch = Array.isArray(args.watch) && args.watch.length ? args.watch.map(String) : ['.']
  return {
    plan: {
      title: String(args.title || '').trim() || '未命名阵型任务',
      mainSession,
      cwd: String(args.cwd || '').trim(),
      shell: args.shell || null,
      timeoutMs: args.timeoutMs,
      sessionPolicy: policy,
      /** spawn 口径下的终端归属：plugin=插件跑（默认）；session=子会话自己跑（旧口径）。 */
      terminal: spawn ? terminalRaw : 'session',
      /* v0.6.2：终端执行路线（auto/pty/process）；缺省 null＝交给引擎按 cfg.terminalMode 决定。 */
      terminalMode: terminalModeRaw || null,
      /* v0.5.1：console=true ⇒ 每个角色在自己的可见系统终端窗口里跑（窗口只负责看得见，判定走 exitCode/expect）。 */
      console: args.console === true,
      keepOpenMs: Number.isFinite(Number(args.keepOpenMs)) ? Math.max(0, Number(args.keepOpenMs)) : 1500,
      skills: skillsCfg,
      roleTimeoutMs: Math.max(5000, Math.floor(Number(args.roleTimeoutMs) || Number(args.timeoutMs) || 120000)),
      threshold: Number.isFinite(Number(args.passThreshold)) ? Number(args.passThreshold) : 0.6,
      stages: STAGES.map((r) => byRole.get(r)),
      adversarial: adv.actor,
      adversarialFanout: fan.fanout,
      minAttacks: fan.minAttacks,
      verifiers,
      watch,
    },
  }
}

/* ───────── 回执校验 ───────── */

/** 读取并校验某个角色的 receipt json：必须存在、非空、角色匹配、verdict 合法、findings 非空。 */
export function readActorReceipt(file, role, label) {
  const p = String(file || '').trim()
  if (!p) return { error: `${label} 未给 receipt 路径` }
  if (!existsSync(p)) return { error: `${label} 的回执不存在：${p}（空耗判定：没交回执＝没干活）` }
  let size = 0
  try {
    size = statSync(p).size
  } catch {
    /* 忽略 */
  }
  if (size < 16) return { error: `${label} 的回执过短（${size} 字节），判为空耗：${p}` }
  let data
  try {
    data = JSON.parse(readFileSync(p, 'utf8'))
  } catch (e) {
    return { error: `${label} 的回执不是合法 JSON（${e?.message ?? e}）：${p}` }
  }
  if (data.role && data.role !== role) {
    return { error: `${label} 的回执 role=${data.role} 与阵型角色 ${role} 不符：${p}` }
  }
  const verdict = String(data.verdict || '').toLowerCase()
  if (!(verdict in VERDICT_VALUE)) {
    return { error: `${label} 的回执缺少合法 verdict（pass/warn/fail）：${p}` }
  }
  const findings = Array.isArray(data.findings) ? data.findings.filter((x) => String(x ?? '').trim()) : []
  if (!findings.length) return { error: `${label} 的回执 findings 为空，判为空耗：${p}` }
  const evidence = Array.isArray(data.evidence) ? data.evidence.filter((x) => typeof x === 'string' && x.trim()) : []
  return { data, verdict, findings, evidence, file: p }
}

/* ───────── 阵型执行 ───────── */

/**
 * @param {object} engine dsh-arch 的 engine（start/status）
 * @param {object} ctxHooks { home, log }
 * @param {object} args 工具入参
 * @param {object} exec 工具执行上下文（尽力取调用方会话 id）
 */
export async function runFlow(engine, hooks, args, exec) {
  const home = hooks.home
  const log = hooks.log || (() => {})
  const flowId = newFlowId()
  const dir = join(home, 'flows', flowId)
  const gateFile = join(dir, 'gate.json')

  const v = validateFlowPlan(args)
  if (v.error) {
    const gate = { flowId, version: FLOW_VERSION, status: 'rejected', failures: [v.error], createdAt: new Date().toISOString() }
    try {
      mkdirSync(dir, { recursive: true })
      writeFileSync(gateFile, JSON.stringify(gate, null, 2), 'utf8')
    } catch {
      /* 落不了盘也要回裁决 */
    }
    return { ok: false, gate, gateFile, text: renderFlowFail(gate, gateFile) }
  }

  const plan = v.plan
  const base = plan.cwd ? resolvePath(plan.cwd) : process.cwd()

  /* 主会话身份复核（能取到调用方会话 id 时，硬校验等于 mainSession）。 */
  const caller = callerSessionFromExec(exec)
  if (caller && caller !== plan.mainSession) {
    const msg = `主会话不匹配：调用方会话=${caller}，声明 mainSession=${plan.mainSession}。主会话只核验，不得代跑工作。`
    const gate = { flowId, version: FLOW_VERSION, status: 'rejected', failures: [msg], createdAt: new Date().toISOString() }
    try {
      mkdirSync(dir, { recursive: true })
      writeFileSync(gateFile, JSON.stringify(gate, null, 2), 'utf8')
    } catch {
      /* 忽略 */
    }
    return { ok: false, gate, gateFile, text: renderFlowFail(gate, gateFile) }
  }

  const stageRuns = []
  const failures = []
  const warnings = []
  const hashes = new Map() // docHash -> [actorName]
  let adversarial = null
  let flowStatus = 'running'

  /* ── 子对话强隔离（v0.3.0 起，v0.3.1 换宿主新原语）：子会话由插件创建，不收调用方声明的字符串 id ── */
  const isolation = {
    mode: plan.sessionPolicy,
    createdByPlugin: plan.sessionPolicy === 'spawn',
    parentSession: caller || plan.mainSession,
    children: [],
    drained: [],
    note: '',
  }
  let subService = null
  let parentAgent = null
  let subProvider = 'spawn'
  let flowAbort = null
  let receiptsDir = ''
  let spawnSeq = 0
  if (plan.sessionPolicy === 'spawn') {
    subService = svc(hooks.ctx, 'subagents')
    if (!subService || typeof subService.startActivation !== 'function') {
      failures.push('宿主未提供子会话原语（subagents.startActivation）：强隔离口径拒绝用声明 id 冒充子对话（fail-closed）')
    } else {
      if (typeof subService.drainChildren !== 'function') {
        failures.push('宿主未提供 drainChildren：子会话无法退班释放名额（fail-closed）')
      }
      try {
        if (exec && exec.agent) parentAgent = exec.agent
      } catch {
        /* 忽略 */
      }
      if (!parentAgent) {
        const agents = svc(hooks.ctx, 'agents')
        try {
          if (agents && typeof agents.get === 'function' && caller) parentAgent = agents.get(caller) || null
        } catch {
          parentAgent = null
        }
      }
      if (!parentAgent) failures.push('取不到调用方 Agent（exec.agent / agents.get(callerSession)）：无法创建子会话')
      /* provider：默认 spawn（独立上下文、非 fork）。宿主注册名不同则取宿主清单里的候选。 */
      try {
        const known = typeof subService.list === 'function' ? subService.list() : []
        if (Array.isArray(known) && known.length) {
          const want = hooks.subagentProvider || 'spawn'
          subProvider = known.includes(want) ? want : known.includes('spawn') ? 'spawn' : known[0]
        }
      } catch {
        /* 用默认值 */
      }
    }
    isolation.provider = subProvider
    isolation.delivery = 'caller'
    /* 子会话生命期绑这条流，不绑工具调用信号：工具返回会 abort exec.signal，把仍在跑的子会话全杀掉。 */
    flowAbort = new AbortController()
    receiptsDir = join(base, '.dsh-arch-receipts', flowId)
    try {
      mkdirSync(receiptsDir, { recursive: true })
    } catch (e) {
      failures.push(`无法创建子会话回执目录：${e?.message ?? e}`)
    }
  } else {
    isolation.note = 'declared：调用方声明的会话（降级口径，已显式 allowDeclaredSessions）'
  }

  const ownCitations = async (actor, label) => {
    const out = []
    for (const c of actor.citations) {
      const p = resolvePath(c, base)
      if (!existsSync(p)) {
        failures.push(`${label} 的依据文档不存在：${p}`)
        continue
      }
      const h = sha256File(p)
      if (!h) {
        failures.push(`${label} 的依据文档无法读取：${p}`)
        continue
      }
      out.push({ path: p, hash: h })
      const owners = hashes.get(h) || []
      owners.push(label)
      hashes.set(h, owners)
    }
    return out
  }

  /** 回执点名的 evidence 必须是真实存在的文件（防编造证据）；返回不存在的那些。 */
  const missingEvidenceOf = (evidence, baseDir) => {
    const list = Array.isArray(evidence) ? evidence : []
    return list
      .map((e) => String(e || '').trim())
      .filter(Boolean)
      .filter((e) => {
        try {
          return !existsSync(resolvePath(e, baseDir))
        } catch {
          return true
        }
      })
  }

  const snapshotWatch = () => {
    const snap = new Map()
    for (const w of plan.watch) {
      const root = resolvePath(w, base)
      if (!existsSync(root)) continue
      snap.set(root, snapshotTree(root))
    }
    return snap
  }

  /** 等某个子会话在时限内交出合法回执（唯一判据：回执文件出现且通过 readActorReceipt）。 */
  const waitForReceipt = async (receiptPath, role, label, timeoutMs) => {
    const deadline = Date.now() + Math.max(5000, Number(timeoutMs) || plan.roleTimeoutMs)
    while (Date.now() < deadline) {
      if (existsSync(receiptPath)) {
        const got = readActorReceipt(receiptPath, receiptRoleOf(role), label)
        if (!got.error) return got
      }
      await sleep(200)
    }
    return null
  }

  /** 退班：名额记在点卯、还于退班；不退会撞「子 agent 活限」（上限 8）。 */
  const releaseChild = async (childId, label) => {
    try {
      await subService.drainChildren(parentAgent, [childId])
      if (!isolation.drained.includes(childId)) isolation.drained.push(childId)
      return true
    } catch (e) {
      failures.push(`${label} 子会话退班失败：${e?.message ?? e}`)
      return false
    }
  }

  /* ── v0.5.0：角色各有独立系统终端 + 按预演关键词下发 skills（与 DSH 活体技能库同步） ── */
  const terminals = []
  /** 对抗性复核（含下级/终审）用的时限：不低于 DEFAULT_ADV_TIMEOUT_MS。 */
  const advTimeoutMs = Math.max(plan.roleTimeoutMs, DEFAULT_ADV_TIMEOUT_MS)
  const skillsLog = {
    config: plan.skills,
    catalog: { source: 'off', detail: '', complete: true, total: 0, visible: 0 },
    perRole: {},
  }
  let skillCatalog = { meta: { source: 'off', detail: '本场不加载技能库', complete: true, total: 0, visible: 0, roots: [] }, entries: [] }
  if (plan.sessionPolicy === 'spawn' && plan.skills.enabled) {
    skillCatalog = await readSkillCatalog(hooks, { cwd: base, roots: plan.skills.roots })
    skillsLog.catalog = skillCatalog.meta
  }

  /** 这个角色该下发哪些技能：关键词 = 任务标题 + 角色名/职责 + 该角色终端命令。 */
  const pickSkillsForRole = (role, label, actor) => {
    if (!plan.skills.enabled || !skillCatalog.entries.length) return { picked: [], meta: skillCatalog.meta }
    const query = [plan.title, label, ROLE_DUTY[role] || role, ...actor.steps.map((s) => renderBriefCmd(s.cmd, ''))].join(' ')
    const picked = pickRoleSkills(query, skillCatalog, plan.skills)
    skillsLog.perRole[label] = picked.map((p) => ({ name: p.name, score: p.score, reason: p.reason }))
    return { picked, meta: skillCatalog.meta }
  }

  /**
   * 在「这个角色自己的系统终端」里跑它的任务（一次角色 = 一次独立终端进程 + 独立 PID + 独立日志）。
   * 终端记录写进 gate（runId/shell/steps/pid/log），是「子智能体任务确实各在各的终端里跑」的硬证据。
   * 返回 null 表示未启用或终端执行失败（失败已记 failures，调用方不要再创建子会话冒充完成）。
   */
  const runRoleTerminal = async (actor, role, label, receiptPath) => {
    if (!(plan.sessionPolicy === 'spawn' && plan.terminal === 'plugin')) return null
    let run
    try {
      run = engine.start({
        title: `${plan.title} · ${label}（独立系统终端）`,
        steps: actor.steps.map((s) => ({
          name: s.name,
          cmd: renderBriefCmd(s.cmd, receiptPath),
          cwd: s.cwd ? resolvePath(s.cwd, base) : base,
          timeoutMs: s.timeoutMs,
          expect: s.expect,
          allowFail: s.allowFail,
        })),
        cwd: base,
        shell: plan.shell || undefined,
        timeoutMs: plan.timeoutMs,
        stopOnFail: true,
        /* v0.5.1：console=true ⇒ 每个角色在自己的可见系统终端窗口里跑（一个角色一个窗口）。 */
        console: plan.console === true,
        keepOpenMs: plan.keepOpenMs,
        /* v0.6.0：每个角色的任务走宿主 ctx.terminals（dsh-terminal-bash 持久终端）里的独立会话；
           owner 必须是调用方 Agent 对象，否则引擎记 fallback 回退原生子进程。 */
        terminal: plan.terminalMode,
        owner: parentAgent,
      })
    } catch (e) {
      failures.push(`${label} 无法启动独立系统终端：${e?.message ?? e}`)
      return null
    }
    await run.done
    const runsDir = engine.runsDir || join(home, 'runs')
    const steps = (run.steps || []).map((st) => ({
      i: st.i,
      name: st.name,
      cmd: st.cmd,
      status: st.status,
      exitCode: st.exitCode ?? null,
      pid: st.pid ?? null,
      ms: st.ms ?? null,
      logPath: st.logFile ? join(runsDir, st.logFile) : null,
      tail: String(st.tail || ''),
      error: st.error || null,
    }))
    const rec = {
      role,
      label,
      runId: run.id,
      shell: run.shellKind || plan.shell || 'auto',
      console: run.console === true,
      /* v0.6.0：这个角色的任务实际跑在哪条终端路线上（pty=宿主终端会话 / process=原生子进程）。 */
      terminalMode: run.terminalMode || 'process',
      terminalFallback: run.terminalFallback || null,
      cwd: base,
      status: run.status,
      ms: run.ms,
      steps,
      pids: [...new Set(steps.map((s) => s.pid).filter(Boolean))],
      logs: steps.map((s) => s.logPath).filter(Boolean),
    }
    terminals.push(rec)
    if (run.status !== 'done' && run.status !== 'warn') {
      failures.push(`${label} 的独立系统终端执行失败（${run.status}，run=${run.id}）：任务没跑成，不接受回执冒充完成`)
      return null
    }
    return rec
  }

  const runDeclaredActor = async (actor, role, label) => {
    let run
    try {
      run = engine.start({
        title: `${plan.title} · ${label}`,
        steps: actor.steps,
        cwd: base,
        shell: plan.shell || undefined,
        timeoutMs: plan.timeoutMs,
        stopOnFail: true,
        console: plan.console === true,
        keepOpenMs: plan.keepOpenMs,
        terminal: plan.terminalMode,
        owner: parentAgent,
      })
    } catch (e) {
      failures.push(`${label} 无法启动终端执行：${e?.message ?? e}`)
      return { ok: false, run: null }
    }
    await run.done
    const rec = {
      role,
      label,
      session: actor.session,
      runId: run.id,
      receipt: run.receiptFile,
      status: run.status,
      ms: run.ms,
      exitCodes: (run.steps || []).map((s) => s.exitCode),
      actorReceipt: resolvePath(actor.receipt, base),
    }
    stageRuns.push(rec)
    if (run.status !== 'done' && run.status !== 'warn') {
      failures.push(`${label} 终端执行失败（${run.status}，run=${run.id}）`)
      return { rec, ok: false, run }
    }
    const rc = readActorReceipt(rec.actorReceipt, role, label)
    if (rc.error) {
      failures.push(rc.error)
      return { rec, ok: false, run }
    }
    rec.verdict = rc.verdict
    rec.findings = rc.findings
    rec.evidenceFiles = rc.evidence
    rec.citations = await ownCitations(actor, label)
    const missing = missingEvidenceOf(rec.evidenceFiles, base)
    if (missing.length) {
      rec.missingEvidence = missing
      failures.push(`${label} 回执 evidence 有 ${missing.length} 份文件不存在（防编造证据）：${missing.join(', ')}`)
    }
    return { rec, ok: true, run, receipt: rc }
  }

  /**
   * spawn 口径：为角色现创建一个真实子会话（独立上下文、非 fork），把 brief（含终端命令与回执契约）
   * 投给它；以「回执文件出现且合法」为这一角色办完的唯一判据，然后立即退班释放名额。
   * 子会话 id 与主会话/其他角色撞车即判隔离破坏（fail-closed）。
   * opts.keepAlive=true：首轮办完先不退班（对抗性复核还要给它派下级、再唤醒它写终审回执）。
   */
  const runSpawnActor = async (actor, role, label, opts = {}) => {
    const startedAt = Date.now()
    spawnSeq += 1
    const receiptPath = join(receiptsDir, `receipt-${String(spawnSeq).padStart(2, '0')}-${slugPart(role)}.json`)
    let childId = ''
    let messageId = ''
    /* v0.5.0 防篡改：回执必须在本次角色开工前不存在——预置一份合法回执能骗过「文件出现即办完」的唯一判据。 */
    if (existsSync(receiptPath)) {
      failures.push(`${label} 的目标回执在角色执行前就已存在（疑似预置回执，拒绝采信）：${receiptPath}`)
      stageRuns.push({
        role,
        label,
        session: '(未创建)',
        spawned: false,
        provider: subProvider,
        messageId: '',
        runId: null,
        receipt: null,
        status: 'failed',
        ms: Date.now() - startedAt,
        exitCodes: [],
        actorReceipt: receiptPath,
        terminal: null,
        skills: [],
        preExistingReceipt: true,
      })
      return { ok: false, run: null }
    }
    /* v0.5.0：这个角色的任务先在「它自己的系统终端」里跑完（插件驱动，一次独立终端进程/PID/日志）。
       子会话只拿终端真实输出做判定——防幻觉（不许自己编执行结果）；终端没跑成就不创建子会话。 */
    const term = await runRoleTerminal(actor, role, label, receiptPath)
    if (plan.sessionPolicy === 'spawn' && plan.terminal === 'plugin' && !term) {
      stageRuns.push({
        role,
        label,
        session: '(未创建)',
        spawned: false,
        provider: subProvider,
        messageId: '',
        runId: null,
        receipt: null,
        status: 'failed',
        ms: Date.now() - startedAt,
        exitCodes: [],
        actorReceipt: receiptPath,
        terminal: null,
        skills: [],
      })
      return { ok: false, run: null }
    }
    /* v0.5.0：按预演关键词下发技能（与 DSH 活体技能库同步，token 类默认常驻）。 */
    const skillsPick = pickSkillsForRole(role, label, actor)
    /* 防越权：子会话除了写自己的回执，任何写入都算越权（基线在它开工前拍）。 */
    const scopeBefore = plan.sessionPolicy === 'spawn' ? snapshotWatch() : null
    try {
      /* 宿主 API（v0.3.1）：startActivation 返回 { childId, messageId?, result, dispose }。
         delivery='caller'：完成通知不给主线（主线只核验），结果由本插件（caller）自己收。 */
      const started = await subService.startActivation({
        provider: subProvider,
        label,
        request: {
          cwd: base,
          prompt: [
            {
              type: 'text',
              text: buildRoleBrief(plan, actor, role, label, receiptPath, base, {
                ...(opts.briefOpts || {}),
                terminal: term,
                skills: skillsPick.picked,
                skillMeta: skillsPick.meta,
              }),
            },
          ],
          parent: parentAgent,
        },
        signal: flowAbort.signal,
        delivery: 'caller',
      })
      childId = String(started?.childId || '').trim()
      messageId = String(started?.messageId || '').trim()
      try {
        if (started && started.result && typeof started.result.catch === 'function') started.result.catch(() => {})
      } catch {
        /* 结果没人 await 也不能炸流 */
      }
    } catch (e) {
      failures.push(`${label} 创建子会话失败：${e?.message ?? e}`)
      return { ok: false, run: null }
    }
    if (!childId) {
      failures.push(`${label} 创建子会话后未拿到 childId（隔离无法证明）：判失败`)
      return { ok: false, run: null }
    }
    if (childId === plan.mainSession || (caller && childId === caller) || isolation.children.includes(childId)) {
      failures.push(`${label} 子会话隔离破坏：childId=${childId} 与主会话/调用方/其它角色会话相同`)
      isolation.note = isolation.note || '检测到会话 id 撞车'
      return { ok: false, run: null }
    }
    isolation.children.push(childId)
    /* 拿到这个子会话的 Agent 句柄：对抗性复核要派下级时，下级子会话的 parent 必须是它。 */
    let agentRef = null
    try {
      const agents = svc(hooks.ctx, 'agents')
      if (agents && typeof agents.get === 'function') agentRef = agents.get(childId) || null
    } catch {
      agentRef = null
    }
    const rec = {
      role,
      label,
      session: childId,
      spawned: true,
      provider: subProvider,
      messageId,
      runId: null,
      receipt: null,
      status: 'running',
      ms: 0,
      exitCodes: [],
      actorReceipt: receiptPath,
      terminal: term,
      skills: skillsPick.picked.map((p) => p.name),
    }
    stageRuns.push(rec)

    const roleWaitMs = opts.timeoutMs || plan.roleTimeoutMs
    const rc = await waitForReceipt(receiptPath, role, label, roleWaitMs)
    rec.ms = Date.now() - startedAt
    if (!rc) {
      rec.status = 'failed'
      failures.push(`${label} 子会话未在 ${Math.round(roleWaitMs / 1000)}s 内交出合法回执（空耗判定）：${receiptPath}`)
      try {
        subService.interrupt(childId, { kind: 'ancestor', agent: parentAgent })
      } catch {
        /* 子会话已结束 */
      }
      await releaseChild(childId, label)
      return { rec, ok: false, run: null, childId, agentRef }
    }
    rec.status = 'done'
    rec.verdict = rc.verdict
    rec.findings = rc.findings
    rec.evidenceFiles = rc.evidence
    rec.citations = await ownCitations(actor, label)
    /* 防编造证据：回执里点名的 evidence 必须是真实存在的文件。 */
    const missing = missingEvidenceOf(rec.evidenceFiles, base)
    if (missing.length) {
      rec.missingEvidence = missing
      failures.push(`${label} 回执 evidence 有 ${missing.length} 份文件不存在（防编造证据）：${missing.join(', ')}`)
    }
    /* 防越权：子会话开工期间的监视树变更（排除它自己的回执目录）一律判越权。 */
    if (scopeBefore) {
      const changed = diffSnapshot(scopeBefore, snapshotWatch())
      if (changed.length) {
        rec.writeViolations = changed.slice(0, 20)
        failures.push(`${label} 越权写入：执行期间监视树出现 ${changed.length} 处变更（子会话只许写自己的回执）`)
      }
    }
    if (!(opts.keepAlive && rc)) {
      /* 用毕即退班：名额记在点卯、还于退班；不退会撞「子 agent 活限」。 */
      await releaseChild(childId, label)
    }
    return { rec, ok: true, run: null, receipt: rc, childId, agentRef, drain: () => releaseChild(childId, label) }
  }

  /**
   * 下级复核：对抗性复核「久议不决」时交办的一个查点。
   * 由插件现创建（parent=对抗日 Agent），独立会话、只读、必须交非空回执；跑完即退班（守子 agent 活限）。
   */
  const runAdvSubActor = async (advAgent, advParentId, item, idx) => {
    const label = `${ADV_SUB_LABEL_PREFIX}${idx}`
    const startedAt = Date.now()
    spawnSeq += 1
    const receiptPath = join(receiptsDir, `receipt-${String(spawnSeq).padStart(2, '0')}-${slugPart(ADV_SUB_ROLE)}.json`)
    const rec = {
      role: ADV_SUB_ROLE,
      label,
      session: '',
      spawned: true,
      provider: subProvider,
      parentSession: advParentId,
      messageId: '',
      runId: null,
      receipt: null,
      status: 'running',
      ms: 0,
      exitCodes: [],
      actorReceipt: receiptPath,
      focus: item.focus,
    }
    stageRuns.push(rec)
    let childId = ''
    try {
      const started = await subService.startActivation({
        provider: subProvider,
        label,
        request: {
          cwd: base,
          prompt: [{ type: 'text', text: buildSubBrief(plan, ADV_CAMP_LABEL, item, label, receiptPath, base) }],
          parent: advAgent,
        },
        signal: flowAbort.signal,
        delivery: 'caller',
      })
      childId = String(started?.childId || '').trim()
      rec.messageId = String(started?.messageId || '').trim()
      try {
        if (started && started.result && typeof started.result.catch === 'function') started.result.catch(() => {})
      } catch {
        /* 结果没人 await 也不能炸流 */
      }
    } catch (e) {
      rec.status = 'failed'
      failures.push(`${label} 创建下级子会话失败：${e?.message ?? e}`)
      return null
    }
    rec.session = childId
    if (!childId) {
      rec.status = 'failed'
      failures.push(`${label} 创建下级子会话后未拿到 childId（隔离无法证明）：判失败`)
      return null
    }
    if (childId === plan.mainSession || (caller && childId === caller) || isolation.children.includes(childId)) {
      rec.status = 'failed'
      failures.push(`${label} 子会话隔离破坏：childId=${childId} 与主会话/调用方/其它角色会话相同`)
      isolation.note = isolation.note || '检测到会话 id 撞车'
      return null
    }
    isolation.children.push(childId)
    const rc = await waitForReceipt(receiptPath, ADV_SUB_ROLE, label, advTimeoutMs)
    rec.ms = Date.now() - startedAt
    if (!rc) {
      rec.status = 'failed'
      failures.push(`${label} 未在 ${Math.round(plan.roleTimeoutMs / 1000)}s 内交出合法回执（空耗判定）：${receiptPath}`)
      try {
        subService.interrupt(childId, { kind: 'ancestor', agent: advAgent })
      } catch {
        /* 子会话已结束 */
      }
      await releaseChild(childId, label)
      return null
    }
    rec.status = 'done'
    rec.verdict = rc.verdict
    rec.findings = rc.findings
    rec.evidenceFiles = rc.evidence
    rec.citations = await ownCitations({ citations: item.citations }, label)
    const missing = missingEvidenceOf(rec.evidenceFiles, base)
    if (missing.length) {
      rec.missingEvidence = missing
      failures.push(`${label} 回执 evidence 有 ${missing.length} 份文件不存在（防编造证据）：${missing.join(', ')}`)
    }
    /* 下级沿用同等约束：依据文档不得与非对抗阵营同内容（阵营内部共用父复核的依据是允许的）。 */
    for (const c of rec.citations) {
      const owners = (hashes.get(c.hash) || []).filter((o) => !inAdvCamp(o))
      if (owners.length) failures.push(`${label} 依据文档与「${owners.join('、')}」同一份（sha256 ${shortHash(c.hash)}）：${c.path}`)
    }
    await releaseChild(childId, label)
    return { label, session: childId, verdict: rc.verdict, findings: rc.findings, citations: rec.citations, status: 'done' }
  }

  /**
   * 终审：用 sendMessage 唤醒对抗性复核（它首轮后退班前被 keepAlive 留住），把下级回执摘要交给它，
   * 让它写终审回执（role=adversarial，同样要带 attacks），再退班。
   */
  const adjudicateAdversarial = async (advAgent, advChildId, finalReceiptPath, children, cfg) => {
    if (!cfg.adjudicate) return { status: 'skipped', note: 'subagents.adjudicate=false：下级结论直接并入终局，不再唤醒对抗性复核' }
    if (typeof subService.sendMessage !== 'function') {
      return { status: 'unavailable', note: '宿主未提供 subagents.sendMessage：无法唤醒对抗性复核写终审回执' }
    }
    const lines = []
    lines.push(`【终审】你先前判不了、交出去的 ${children.length} 个查点，下级复核已各自交出回执：`)
    for (const c of children) {
      lines.push(`- ${c.label}（会话 ${c.session}）verdict=${c.verdict}：${(c.findings || []).join(' / ')}`)
    }
    lines.push('')
    lines.push(`你必须写终审回执（role 仍是 adversarial，同样带 attacks，至少 ${plan.minAttacks} 条）：`)
    lines.push(`  终审回执路径：${finalReceiptPath}`)
    lines.push('内容：逐条处置下级结论（采纳/驳回＋理由），给出最终 verdict；findings 要含下级关键结论或明确驳回理由。')
    try {
      await subService.sendMessage(parentAgent, advChildId, [{ type: 'text', text: lines.join('\n') }], { signal: flowAbort.signal })
    } catch (e) {
      return { status: 'error', note: `唤醒对抗性复核失败：${e?.message ?? e}` }
    }
    const fin = await waitForReceipt(finalReceiptPath, 'adversarial', '对抗性复核（终审）', advTimeoutMs)
    if (!fin) return { status: 'timeout', note: '对抗性复核未在时限内交出终审回执' }
    return { status: 'done', receipt: fin }
  }

  const runActor = plan.sessionPolicy === 'spawn' ? runSpawnActor : runDeclaredActor

  /* ── 阶段 1/2：拆分 → 路径（工作前先拆任务、想路径） ── */
  for (const role of ['split', 'path']) {
    if (failures.length) break
    const actor = plan.stages.find((s) => s.role === role)
    const r = await runActor(actor, role, STAGE_CN[role])
    if (!r.ok) break
  }

  /* ── 阶段 3：对抗性复核（只读 + 极具攻击性 + 依据文档必须与他人不同；久议不决可派下级） ── */
  if (!failures.length) {
    const actor = plan.adversarial
    const cfg = plan.adversarialFanout
    const fanAllowed = Boolean(cfg && cfg.enabled === true && plan.sessionPolicy === 'spawn')
    const finalReceiptPath = fanAllowed ? join(receiptsDir, 'receipt-final-adversarial.json') : ''
    const watchBefore = snapshotWatch()
    const r = await runActor(actor, 'adversarial', ADV_CAMP_LABEL, {
      keepAlive: fanAllowed,
      timeoutMs: advTimeoutMs,
      briefOpts: fanAllowed
        ? { minAttacks: plan.minAttacks, fanout: cfg, maxChildren: cfg.maxChildren, finalReceiptPath }
        : { minAttacks: plan.minAttacks },
    })

    /* 久议不决 ⇒ 向下分发：下级各自独立会话、只读、必须交回执；再唤醒对抗日写终审。 */
    let fanout = null
    let advFirstReceipt = r.ok ? r.receipt : null
    let advFinalReceipt = null
    if (r.ok && fanAllowed) {
      const req = parseAdversarialDispatch(advFirstReceipt.data, actor, cfg)
      fanout = {
        enabled: true,
        mode: cfg.mode,
        trigger: req.trigger,
        requested: req.items.length + req.truncated,
        maxChildren: cfg.maxChildren,
        truncated: req.truncated,
        rejected: req.rejected,
        status: 'none',
        children: [],
        adjudication: null,
      }
      if (req.truncated > 0) {
        warnings.push(`对抗性复核请求分发 ${req.items.length + req.truncated} 个查点，超过上限 ${cfg.maxChildren}：已截断 ${req.truncated} 个（要更多请调大 adversarial.subagents.maxChildren，硬上限 ${HARD_MAX_ADV_SUBAGENTS}）`)
      }
      for (const bad of req.rejected) warnings.push(`分发条目被忽略：${bad}`)
      if (req.items.length) {
        const advAgent = r.agentRef || null
        if (!advAgent) {
          fanout.status = 'unavailable'
          failures.push('对抗性复核要派下级，但取不到它的 Agent 句柄（agents.get）：下级子会话无法建立（fail-closed）')
        } else {
          fanout.status = 'running'
          for (let i = 0; i < req.items.length; i++) {
            if (failures.length) break
            const child = await runAdvSubActor(advAgent, r.childId, req.items[i], i + 1)
            if (child) fanout.children.push(child)
          }
          const adj = await adjudicateAdversarial(advAgent, r.childId, finalReceiptPath, fanout.children, cfg)
          fanout.adjudication = adj
          if (adj.status === 'done') {
            advFinalReceipt = adj.receipt
            fanout.status = 'done'
          } else if (adj.status === 'skipped') {
            fanout.status = 'done-no-adjudication'
          } else {
            fanout.status = 'partial'
            warnings.push(`对抗性复核终审未完成（${adj.status}）：${adj.note}；已按「父复核 + 下级」最差判定收口`)
          }
        }
      }
    } else if (r.ok && cfg && cfg.mode === 'declared-skipped') {
      const req = parseAdversarialDispatch(advFirstReceipt.data, actor, { maxChildren: cfg.maxChildren })
      fanout = { enabled: false, mode: cfg.mode, trigger: req.trigger, requested: req.items.length, maxChildren: cfg.maxChildren, status: 'skipped', children: [], adjudication: null }
      if (req.items.length) warnings.push(`对抗性复核请求向下分发 ${req.items.length} 个查点，但 declared 口径没有子会话原语：已忽略（要分发请用 sessionPolicy=spawn）`)
    }

    const watchAfter = snapshotWatch()
    const changed = []
    for (const [root, before] of watchBefore) {
      const after = watchAfter.get(root) || new Map()
      for (const c of diffSnapshot(before, after)) changed.push(join(root, c))
    }
    /* 对抗性复核的会话到此才退班（首轮 keepAlive 留住了它，终审写完才能还名额）。 */
    if (r.ok && fanAllowed && typeof r.drain === 'function') await r.drain()

    const childVerdicts = (fanout ? fanout.children : []).map((c) => c.verdict).filter(Boolean)
    /* 终审覆盖首轮判定；下级 verdict 仍有否决权（fail-closed：任何一方判 fail 就是 fail）。 */
    let campVerdict = (advFinalReceipt ? advFinalReceipt.verdict : r.rec && r.rec.verdict) || 'fail'
    for (const cv of childVerdicts) campVerdict = worstVerdict(campVerdict, cv)
    const campFindings = dedupeStrings([
      ...((r.rec && r.rec.findings) || []),
      ...((advFinalReceipt && advFinalReceipt.findings) || []),
      ...(fanout ? fanout.children.flatMap((c) => c.findings || []) : []),
    ])
    const attacks = normAttacks(advFinalReceipt || advFirstReceipt)
    adversarial = {
      session: (r.rec && r.rec.session) || actor.session,
      spawned: Boolean(r.rec && r.rec.spawned),
      runId: (r.rec && r.rec.runId) || null,
      status: (r.rec && r.rec.status) || 'failed',
      verdict: campVerdict,
      firstVerdict: (r.rec && r.rec.verdict) || 'fail',
      finalVerdict: advFinalReceipt ? advFinalReceipt.verdict : null,
      childVerdicts,
      findings: campFindings,
      attacks,
      citations: (r.rec && r.rec.citations) || [],
      readOnly: changed.length === 0,
      changes: changed.slice(0, 20),
      dispatch: fanout,
    }
    if (!r.ok) {
      /* 失败原因已记录 */
    } else if (changed.length) {
      const msg = `对抗性复核违反只读：执行期间监视树有 ${changed.length} 处写入（${changed.slice(0, 5).join('；')}${changed.length > 5 ? ' …' : ''}）`
      failures.push(msg)
    }
    if (r.ok) {
      const gap = attackShortfall(attacks, plan.minAttacks)
      if (gap) failures.push(gap)
    }
    /* 依据文档不得与之前的角色（拆分/路径）同内容；阵营内部（对抗日 + 它的下级）共用不算撞车 */
    if (adversarial && adversarial.citations.length) {
      for (const c of adversarial.citations) {
        const owners = (hashes.get(c.hash) || []).filter((o) => !inAdvCamp(o))
        if (owners.length) failures.push(`对抗性复核依据文档与「${owners.join('、')}」同一份（sha256 ${shortHash(c.hash)}）：${c.path}`)
      }
    } else if (!failures.length) {
      failures.push('对抗性复核没有可用依据文档（citations 全部不存在或读不到）')
    }
  }

  /* ── 阶段 4..7：规划 → 隔离 → 修改 → 工作 ── */
  if (!failures.length) {
    for (const role of ['plan', 'isolate', 'modify', 'work']) {
      if (failures.length) break
      const actor = plan.stages.find((s) => s.role === role)
      const r = await runActor(actor, role, STAGE_CN[role])
      if (!r.ok) break
    }
  }

  /* ── 阶段 8：验证方（多方，按引用文档降权） ── */
  let weighted = null
  if (!failures.length) {
    const verifyRuns = []
    for (let i = 0; i < plan.verifiers.length; i++) {
      const actor = plan.verifiers[i]
      const label = `验证方 ${i + 1}`
      const r = await runActor(actor, 'verify', label)
      if (!r.ok) break
      const cited = r.rec.citations || []
      if (!cited.length) {
        failures.push(`${label} 没有引用任何依据文档（引用文件必须存在且可读）`)
        break
      }
      /* 验证方的证据文档：优先 receipt.evidence（逐文件），与 citations 合并去重 */
      const docs = []
      for (const c of cited) docs.push(c)
      for (const e of r.rec.evidenceFiles) {
        const p = resolvePath(e, base)
        const h = existsSync(p) ? sha256File(p) : null
        if (h && !docs.some((d) => d.hash === h)) docs.push({ path: p, hash: h })
      }
      for (const d of docs) {
        const owners = hashes.get(d.hash) || []
        if (!owners.includes(label)) owners.push(label)
        hashes.set(d.hash, owners)
      }
      verifyRuns.push({ ...r.rec, docs, verdictValue: VERDICT_VALUE[r.rec.verdict] })
    }

    if (!failures.length) {
      /* 降权：同一份文档被 k 个验证方引用，每个引用者在该文档上的权重 = 1/k */
      const docOwners = new Map()
      for (const vr of verifyRuns) {
        for (const d of vr.docs) {
          const set = docOwners.get(d.hash) || new Set()
          set.add(vr.label)
          docOwners.set(d.hash, set)
        }
      }
      const rows = []
      let wSum = 0
      let score = 0
      let independent = false
      for (const vr of verifyRuns) {
        let w = 0
        for (const d of vr.docs) {
          const k = (docOwners.get(d.hash) || new Set()).size || 1
          w += 1 / k
          if (k === 1) independent = true
        }
        wSum += w
        score += w * vr.verdictValue
        rows.push({ label: vr.label, cited: vr.docs.length, weight: Number(w.toFixed(3)), verdict: vr.verdict })
      }
      weighted = {
        threshold: plan.threshold,
        score: wSum ? Number((score / wSum).toFixed(3)) : 0,
        totalWeight: Number(wSum.toFixed(3)),
        independentEvidence: independent,
        rows,
        docs: [...docOwners.entries()].map(([hash, set]) => ({ hash, citedBy: [...set], weightEach: Number((1 / set.size).toFixed(3)) })),
      }
      if (!independent) failures.push('多方验证全部引用同一批文档（无独立证据），降权后无法成立')
      if (weighted.score < plan.threshold) failures.push(`验证加权得分 ${weighted.score} 低于阈值 ${plan.threshold}`)
      for (const vr of verifyRuns) {
        if (vr.verdict === 'fail') failures.push(`${vr.label} 判定失败（verdict=fail）`)
      }
      if (adversarial && adversarial.verdict === 'fail') failures.push('对抗性复核否决（verdict=fail）')
    }

    if (!failures.length) {
      /* 后段角色/验证方的依据文档与对抗性复核撞车也算违规（对抗性复核必须独立） */
      if (adversarial) {
        const advHashes = new Set(adversarial.citations.map((c) => c.hash))
        for (const [h, owners] of hashes) {
          if (!advHashes.has(h)) continue
          const others = owners.filter((o) => !inAdvCamp(o))
          if (others.length) failures.push(`对抗性复核依据文档与「${others.join('、')}」同一份（sha256 ${shortHash(h)}）`)
        }
      }
      if (weighted && weighted.score >= plan.threshold && failures.length === 0) flowStatus = 'done'
    }
  }

  /* 终局判据：无任何失败 + 多方验证已算出加权分，才算 GATE PASS；其余一律 FAIL（fail-closed）。 */
  flowStatus = failures.length === 0 && weighted ? 'done' : 'failed'

  /* v0.5.0：guards 由实际判定推导，不写死字面量——下游按字段名读时不会把「已越权」读成「未越权」。 */
  if (plan.skills.enabled && skillsLog.catalog && /error/.test(String(skillsLog.catalog.source || ''))) {
    warnings.push(`skills 活体服务不可用（${skillsLog.catalog.source}），已回退目录扫描：${skillsLog.catalog.detail || ''}`)
  }
  if (plan.skills.enabled && skillsLog.catalog && skillsLog.catalog.source === 'none') {
    warnings.push('skills 已开启但未取到任何技能库（活体服务不可用且回退目录为空）')
  }
  const writeViolations = stageRuns.filter((r) => Array.isArray(r.writeViolations) && r.writeViolations.length)
  const missingEvidenceFiles = stageRuns.reduce((n, r) => n + (Array.isArray(r.missingEvidence) ? r.missingEvidence.length : 0), 0)
  const preExistingReceipts = stageRuns.filter((r) => r.preExistingReceipt)
  const guards = {
    selfContainedBrief: true,
    terminalTruth: plan.terminal === 'plugin' && plan.sessionPolicy === 'spawn',
    childWriteScope: writeViolations.length ? 'violated' : 'receipt-only',
    childSubagents: 'forbidden',
    crossRoleContext: 'none',
    evidenceMustExist: missingEvidenceFiles === 0,
    adversarialReadOnly: adversarial ? adversarial.readOnly === true : 'n/a',
    receiptsClean: preExistingReceipts.length === 0,
    skillSource: skillsLog.catalog ? String(skillsLog.catalog.source || 'off') : 'off',
  }
  const timeouts = { stepMs: plan.timeoutMs ?? null, roleMs: plan.roleTimeoutMs, adversarialMs: advTimeoutMs }

  const gate = {
    flowId,
    version: FLOW_VERSION,
    status: flowStatus,
    title: plan.title,
    mainSession: plan.mainSession,
    callerSession: caller || '(未取到)',
    cwd: base,
    createdAt: new Date().toISOString(),
    isolation,
    /* v0.5.0：每个角色自己的系统终端（runId/PID/日志）＝「任务各在各的终端里跑」的硬证据。 */
    terminal: plan.terminal,
    /* v0.6.2：点名的终端执行路线（auto/pty/process，见 TERMINAL_ROUTES）；每个角色实际落定的路线另见 terminals[].terminalMode。 */
    terminalMode: plan.terminalMode || 'auto',
    terminals,
    skills: skillsLog,
    timeouts,
    guards,
    stages: stageRuns,
    adversarial,
    adversarialFanout: plan.adversarialFanout,
    minAttacks: plan.minAttacks,
    verify: weighted,
    failures,
    warnings,
    hashes: [...hashes.entries()].map(([hash, owners]) => ({ hash, owners })),
    gateFile,
  }
  try {
    mkdirSync(dir, { recursive: true })
    writeFileSync(gateFile, JSON.stringify(gate, null, 2), 'utf8')
  } catch (e) {
    log(`阵型回执落盘失败：${e?.message ?? e}`)
  }
  return { ok: flowStatus === 'done', gate, gateFile, text: renderFlow(gate) }
}

/* ───────── 呈现 ───────── */

function renderFlowFail(gate, gateFile) {
  return [
    '# 架构阵型 · 拒绝执行（GATE FAIL）',
    `- flowId：${gate.flowId}`,
    `- 原因：${gate.failures.join('；')}`,
    `- 回执：${gateFile}`,
  ].join('\n')
}

function renderFlow(gate) {
  const L = []
  const ok = gate.status === 'done'
  L.push(`# 架构阵型 · ${gate.title}`)
  L.push(`- flowId：${gate.flowId}`)
  L.push(`- 裁决：${ok ? 'GATE PASS' : 'GATE FAIL'}`)
  L.push(`- 阵型：拆分 → 路径 → 对抗性复核（只读）→ 规划 → 隔离 → 修改 → 工作 → 验证方（多方）`)
  L.push(`- 主会话（只核验）：${gate.mainSession}｜调用方会话：${gate.callerSession}`)
  L.push(`- 工作目录：${gate.cwd}`)
  if (gate.isolation) {
    const iso = gate.isolation
    if (iso.mode === 'spawn') {
      L.push(
        `- 子对话强隔离：spawn（插件现创建 ${iso.children.length} 个真实子会话，主会话/调用方不在其中；已退班 ${iso.drained.length} 个）`,
      )
    } else {
      L.push(`- 子对话隔离：declared（降级口径：调用方声明的会话，${iso.note || '已显式允许'}）`)
    }
  }
  L.push(`- 回执：${gate.gateFile}`)
  L.push('', '## 角色执行')
  for (const st of gate.stages || []) {
    const mark = st.status === 'done' || st.status === 'warn' ? '✓' : '✗'
    const termInfo = st.terminal
      ? `｜终端 run ${st.terminal.runId}（${st.terminal.shell}，pid ${(st.terminal.pids || []).join('/') || '-'}）`
      : ''
    L.push(
      `- ${mark}｜${st.label}（${STAGE_CN[st.role] || st.role}）｜${st.spawned ? '子会话' : '会话'} ${st.session}｜${st.spawned ? 'spawn' : `run ${st.runId}`}｜${st.status}｜${fmtMs(st.ms)}｜verdict=${st.verdict || '-'}${termInfo}`,
    )
    L.push(`  回执：${st.actorReceipt}`)
    if ((st.skills || []).length) L.push(`  下发技能：${st.skills.join('、')}`)
    if ((st.writeViolations || []).length) L.push(`  ⚠ 越权写入：${st.writeViolations.length} 处（${st.writeViolations.slice(0, 3).join('、')}…）`)
  }
  /* v0.5.0：独立系统终端与技能下发都逐条摆出来，供主会话只核验。 */
  const terms = gate.terminals || []
  if (terms.length) {
    L.push('', '## 独立系统终端（每个角色各一个终端进程，PID/日志可核）')
    L.push(`- 终端路线：${gate.terminalMode || 'auto'}（auto/pty＝优先宿主终端会话、不可用如实记 fallback 回退原生子进程；process＝强制原生子进程）`)
    for (const t of terms) {
      L.push(`- ${t.label}｜run ${t.runId}｜${t.shell}｜${t.status}｜${fmtMs(t.ms)}｜pid ${(t.pids || []).join('/') || '-'}｜${t.steps.length} 步`)
      for (const s of (t.steps || []).slice(0, 8)) {
        L.push(`  - ${s.status === 'done' ? '✓' : '✗'} ${s.name || `步骤${s.i}`}｜exit=${s.exitCode ?? '-'}｜pid=${s.pid ?? '-'}｜日志 ${s.logPath || '-'}`)
      }
    }
  } else if (gate.terminal === 'session') {
    L.push('', '## 独立系统终端')
    L.push('- terminal=session（旧口径：命令由各子会话自己的终端工具执行，插件不做终端取证）')
  }
  if (gate.skills) {
    const sk = gate.skills
    const cat = sk.catalog || {}
    L.push('', '## 技能下发（与 DSH 活体技能库同步 · 按预演关键词检索）')
    L.push(
      `- 配置：enabled=${sk.config?.enabled}｜token 类常驻=${sk.config?.tokenSavers}｜上限 ${sk.config?.max} 条/角色`,
    )
    L.push(`- 技能库：${cat.source}｜可见 ${cat.visible ?? 0}/${cat.total ?? 0} 条${cat.detail ? `（${cat.detail}）` : ''}`)
    const roleKeys = Object.keys(sk.perRole || {})
    if (!roleKeys.length) L.push('- 本场未给任何角色下发技能（技能库为空或已关闭）')
    for (const k of roleKeys) {
      const picked = sk.perRole[k] || []
      L.push(`- ${k}：${picked.length ? picked.map((p) => `${p.name}（${p.reason}）`).join('、') : '无命中'}`)
    }
  }
  if (gate.guards) {
    const g = gate.guards
    const to = gate.timeouts || {}
    L.push('', '## 防幻觉 · 防污染 · 防越权（代码强制，非 prompt 自觉）')
    L.push(`- 自包含 brief：${g.selfContainedBrief ? '每角色只拿自己的输入与终端输出，不共享其他角色上下文' : '关'}`)
    L.push(`- 终端取证优先：${g.terminalTruth ? '角色判定以插件终端真实输出为准（子会话不许自编执行结果）' : '旧口径'}`)
    L.push(
      `- 写入边界：${g.childWriteScope === 'receipt-only' ? '本次实测 0 处越权写入（子会话只许写自己的回执）' : '本次实测有越权写入，判 FAIL'}`,
    )
    L.push(`- 派生禁止：${g.childSubagents === 'forbidden' ? '子会话不得再派生子智能体、不得转交任务' : g.childSubagents}`)
    L.push(`- 证据真实性：${g.evidenceMustExist ? '回执 evidence 全部为真实存在的文件' : '有 evidence 指向不存在的文件（判 FAIL）'}`)
    L.push(
      `- 对抗性复核只读：${
        g.adversarialReadOnly === true
          ? '执行前后监视树快照比对：未写入（通过）'
          : g.adversarialReadOnly === false
            ? '检测到写入（FAIL）'
            : '本场无对抗性复核'
      }`,
    )
    L.push(`- 回执防篡改：${g.receiptsClean ? '角色开工前回执路径均不存在（无预置回执）' : '检测到预置回执（FAIL）'}`)
    L.push(`- 技能库来源：${g.skillSource}｜时限：step ${to.stepMs ?? '-'}ms｜角色 ${to.roleMs ?? '-'}ms｜对抗性复核 ${to.adversarialMs ?? '-'}ms`)
  }
  if (gate.adversarial) {
    const a = gate.adversarial
    L.push('', '## 对抗性复核（固定角色 · 只读 · 红队）')
    L.push(`- 会话：${a.session}（独立于主对话）`)
    L.push(`- 只读：${a.readOnly ? '未写入（通过）' : `违反只读（${a.changes.length} 处写入）`}`)
    L.push(
      `- 判定：${a.verdict}（首轮 ${a.firstVerdict || '-'}${a.finalVerdict ? `，终审 ${a.finalVerdict}` : ''}，下级 ${(a.childVerdicts || []).join('/') || '-'}）｜findings ${a.findings.length} 条`,
    )
    if ((a.attacks || []).length) {
      L.push(`- 攻击点：${a.attacks.length} 条（要求 ≥ ${gate.minAttacks ?? '-'}）`)
      for (const t of a.attacks.slice(0, 10)) L.push(`  - 打「${t.target}」→ ${t.failure_mode}`)
    } else {
      L.push(`- 攻击点：0 条（未达「极具攻击性」要求）`)
    }
    if (a.dispatch) {
      const d = a.dispatch
      const head = d.enabled === false ? `不启用（${d.mode}，请求 ${d.requested || 0} 个查点已忽略）` : `触发=${d.trigger}｜上限 ${d.maxChildren}｜下级 ${d.children.length} 个｜状态 ${d.status}`
      L.push(`- 久议不决向下分发：${head}`)
      for (const c of d.children || []) {
        L.push(`  - ${c.label}（会话 ${c.session}）verdict=${c.verdict}｜findings ${(c.findings || []).length} 条`)
      }
      if (d.adjudication) {
        L.push(`- 终审：${d.adjudication.status}${d.adjudication.note ? `（${d.adjudication.note}）` : ''}`)
      }
    }
    for (const c of a.citations || []) L.push(`  - 依据：${c.path}（${shortHash(c.hash)}）`)
  }
  if (gate.verify) {
    L.push('', '## 验证方（多方验证 · 引用同文档降权）')
    for (const r of gate.verify.rows) {
      L.push(`- ${r.label}｜引用 ${r.cited} 份｜权重 ${r.weight}｜verdict=${r.verdict}`)
    }
    L.push(`- 加权得分：${gate.verify.score}（阈值 ${gate.verify.threshold}，总权重 ${gate.verify.totalWeight}）`)
    L.push(`- 独立证据：${gate.verify.independentEvidence ? '有' : '无（全部撞车）'}`)
    for (const d of gate.verify.docs) {
      L.push(`  - 文档 ${shortHash(d.hash)}｜被 ${d.citedBy.join('、')} 引用｜每引用权重 ${d.weightEach}`)
    }
  }
  if ((gate.warnings || []).length) {
    L.push('', '## 警告（不阻断，已记账）')
    for (const w of gate.warnings) L.push(`- ${w}`)
  }
  if ((gate.failures || []).length) {
    L.push('', '## 失败原因（闭环保守：任一条即 FAIL）')
    for (const f of gate.failures) L.push(`- ${f}`)
  }
  L.push('', '主会话只核验：看本裁决与 gate.json 即止；要重跑就重下阵型，不要在主线里手工补做角色工作。')
  return L.join('\n')
}

/* ───────── 工具定义 ───────── */

export function buildFlowTool(engine, hooks) {
  return {
    name: 'arch_flow',
    description:
      '架构阵型（多角色 + 终端执行 + 子对话强隔离）：固定阵型「拆分 → 路径 → 对抗性复核（只读）→ 规划 → 隔离 → 修改 → 工作 → 验证方（多方）」，角色顺序、子会话创建与隔离、回执、只读与引用文档去重全部由代码强制（fail-closed），不靠 prompt。\n' +
      '默认 sessionPolicy=spawn：每个角色由插件用 subagents.startActivation 现创建真实子会话（独立上下文、非 fork），调用方不得指定 session/receipt；子会话跑完即退班。缺子会话原语一律 FAIL。\n' +
      '硬约束：① 主会话（mainSession）只核验、不得出现在任何角色会话里（spawn 口径下角色会话全由插件创建，天然满足）；② 对抗性复核固定存在、独立子会话、只读（执行前后监视树快照比对，有写入即 FAIL）；③ 对抗性复核的依据文档不得与任何其他角色依据文档同内容（sha256 级）；④ 每个角色必须交 receipt(json，含非空 findings/evidence)，缺失/空即判空耗 FAIL；⑤ 验证方至少 2 个，引用同一份文档者按 1/k 降权，全部撞车或加权分低于阈值则 FAIL。\n' +
      '⑥ 对抗性复核必须极具攻击性：回执必须带 attacks[]（默认 ≥2 条，每条 target + failure_mode）；「没发现问题/建议补充测试」这类背书不算攻击，攻击面不足直接 FAIL。\n' +
      '⑦ 久议不决可向下分发（v0.4.0，spawn 口径默认开）：对抗性复核在回执里写 dispatch[]（或 undecided+unresolved），插件为每条现创建「下级复核」子会话（parent=对抗日、独立会话、只读、同样必须交回执、同样逐个退班），跑完用 sendMessage 唤醒对抗日写终审回执；下级沿用与其他角色子会话相同的约束，依据文档不得与非对抗阵营同内容。maxChildren 默认 3、硬上限 6。\n' +
      '⑧ 每个角色的任务由插件在「它自己的系统终端」里跑（v0.5.0，terminal 默认 plugin）：一次角色＝一次独立终端进程（独立 PID 与日志，逐角色写进 gate.terminals），子会话只拿终端真实输出做判定，不许自己编执行结果；终端跑不成就 FAIL，不接受回执冒充完成。\n' +
      '⑨ 按预演关键词从 DSH 活体技能库下发技能（v0.5.0，skills.enabled 默认开）：与 ctx.get("skills") 同步（禁用过的技能不下发），按任务标题 + 角色职责 + 终端命令关键词检索，token 节省类默认常驻；每角色最多 max 条、只下发摘要，全文由子会话按需用 skill 工具加载。\n' +
      '⑩ 防幻觉 / 防对话污染 / 防越权（代码强制）：brief 自包含（不共享其他角色上下文）、子会话除自己回执外任何写入都判越权（监视树快照审计）、禁止再派生子智能体或转交任务、回执 evidence 必须真实存在（防编造证据）。\n' +
      'strong isolation 写入底层：sessionPolicy 默认 spawn 且不可由角色绕过；declared（调用方声明会话）必须显式 allowDeclaredSessions:true，gate 标 isolation=declared 供审计（declared 无子会话原语 ⇒ 向下分发只能忽略并记警告）。',
    parameters: {
      type: 'object',
      properties: {
        title: { type: 'string', description: '任务标题（进回执与 gate.json）。' },
        mainSession: { type: 'string', description: '主会话 id（只核验、不参与工作；spawn 口径下角色子会话由插件创建，因此天然与主会话不同）。' },
        sessionPolicy: {
          type: 'string',
          enum: ['spawn', 'declared'],
          description: '会话策略。spawn（默认，强隔离）：插件用 subagents.startActivation 现创建角色子会话，调用方不得传 session/receipt；declared：旧口径，调用方声明会话 id（必须同时 allowDeclaredSessions:true，gate 标 isolation=declared）。',
        },
        allowDeclaredSessions: {
          type: 'boolean',
          description: '仅 declared 口径需要：显式承认降级（绕过子对话强隔离），供审计。默认 false ⇒ declared 直接拒绝。',
        },
        terminal: {
          type: 'string',
          enum: ['plugin', 'session'],
          description:
            'v0.5.0 终端归属（默认 plugin）：plugin＝每个角色的任务由插件在它自己的系统终端里跑（独立进程/PID/日志，逐角色记进 gate.terminals，子会话只读终端输出做判定）；session＝旧口径（命令交给子会话自己的终端工具执行）。declared 口径恒为 session。',
        },
        terminalMode: {
          type: 'string',
          enum: ['auto', 'pty', 'process'],
          description:
            'v0.6.2 终端执行路线：auto（默认）/pty＝每个角色的任务优先在宿主 ctx.terminals 的独立会话里跑，拿不到服务或缺 owner 时如实记 terminalFallback 回退原生子进程；process＝强制原生子进程（不经宿主终端）。gate.terminalMode 记点名值，gate.terminals[].terminalMode 记每个角色实际落定的路线。',
        },
        console: {
          type: 'boolean',
          description:
            'v0.5.1：true=每个角色的任务在自己的可见系统终端窗口里跑（Windows Terminal，一角色一窗口）。窗口只负责看得见，退出码/超时/日志/回执判定与默认隐藏模式完全一致。默认 false。',
        },
        keepOpenMs: { type: 'integer', description: 'console=true 时窗口跑完后保留多久毫秒（默认 1500，0=立即关）。' },
        skills: {
          type: 'object',
          description:
            'v0.5.0 技能下发（默认开启）：与 DSH 活体技能库同步，按预演关键词（任务标题+角色职责+终端命令）检索后给每个角色下发 summary；token 节省类默认常驻。',          properties: {
            enabled: { type: 'boolean', description: '是否下发技能（默认 true）。' },
            tokenSavers: { type: 'boolean', description: '节省 token 类技能是否默认常驻（默认 true）。' },
            max: { type: 'integer', description: '每个角色最多下发几条（默认 4，1–8）。' },
            roots: {
              type: 'array',
              items: { type: 'string' },
              description: '回退扫描的技能目录（技能服务不可用时才用；默认 ~/.agents/skills 与 ~/.dsh/skills）。',
            },
          },
        },
        roleTimeoutMs: {
          type: 'integer',
          description: 'spawn 口径下每个角色子会话交回执的时限（毫秒，默认取 timeoutMs 或 120000；超时判空耗并 interrupt 子会话）。',
        },
        cwd: { type: 'string', description: '阵型工作目录（默认插件配置 cwd 或 DSH 进程 cwd；引用文档相对路径也按它解析）。' },
        shell: { type: 'string', enum: ['auto', 'powershell', 'pwsh', 'cmd', 'bash', 'sh'] },
        timeoutMs: { type: 'integer', description: '每个角色每一步的默认超时毫秒。' },
        watch: {
          type: 'array',
          items: { type: 'string' },
          description: '只读监视根（默认 ["."] 即 cwd）；对抗性复核执行期间这些目录下的任何写入都判违规。',
        },
        passThreshold: { type: 'number', description: '验证加权得分阈值（默认 0.6）。' },
        stages: {
          type: 'array',
          description: '六个工作角色，必须严格按 拆分/路径/规划/隔离/修改/工作 顺序各一次。',
          items: {
            type: 'object',
            properties: {
              role: { type: 'string', enum: ['split', 'path', 'plan', 'isolate', 'modify', 'work'] },
              name: { type: 'string' },
              session: { type: 'string', description: '【仅 declared 口径】该角色已存在的会话 id；spawn 口径必须留空（由插件创建）。' },
              receipt: { type: 'string', description: '【仅 declared 口径】该角色回执 json 路径；spawn 口径由插件生成、不许传。' },
              citations: { type: 'array', items: { type: 'string' }, description: '该角色依据文档路径（至少 1 份）。' },
              steps: { type: 'array', description: '终端命令（字符串或 {name,cmd,cwd,timeoutMs,expect,allowFail}）。', items: {} },
            },
            required: ['role', 'citations', 'steps'],
          },
        },
        adversarial: {
          type: 'object',
          description: '固定的对抗性复核（红队）：独立会话、只读、依据文档必须与他人不同、必须极具攻击性。',
          properties: {
            session: { type: 'string' },
            name: { type: 'string' },
            receipt: { type: 'string' },
            citations: { type: 'array', items: { type: 'string' } },
            steps: { type: 'array', items: {} },
            minAttacks: {
              type: 'integer',
              description: `攻击面下限：回执 attacks[] 至少几条（默认 ${DEFAULT_MIN_ATTACKS}，1–9）。不足即 FAIL——对抗性复核不许只背书。`,
            },
            subagents: {
              type: 'object',
              description: '久议不决时的向下分发（spawn 口径默认开）：对抗日写 dispatch[]/undecided，插件现创建下级复核子会话。',
              properties: {
                enabled: { type: 'boolean', description: '默认 spawn 口径为 true；false 关闭分发（对抗日只能自己给结论）。' },
                maxChildren: {
                  type: 'integer',
                  description: `最多派几个下级（默认 ${DEFAULT_MAX_ADV_SUBAGENTS}，范围 1–${HARD_MAX_ADV_SUBAGENTS}；子 agent 活限 8，故逐个串行点卯/退班）。`,
                },
                adjudicate: { type: 'boolean', description: '默认 true：下级跑完用 sendMessage 唤醒对抗日写终审回执；false 则直接按最差判定收口。' },
              },
            },
          },
          required: ['citations', 'steps'],
        },
        verifiers: {
          type: 'array',
          description: '多方验证（≥2）。引用同一份文档者降权 1/k；证据文档从 receipt.evidence 合并。',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              session: { type: 'string' },
              receipt: { type: 'string' },
              citations: { type: 'array', items: { type: 'string' } },
              steps: { type: 'array', items: {} },
            },
            required: ['citations', 'steps'],
          },
        },
      },
      required: ['title', 'mainSession', 'stages', 'adversarial', 'verifiers'],
    },
    output: textOut(),
    async execute(args, exec) {
      const res = await runFlow(engine, hooks, args || {}, exec)
      return res.text
    },
  }
}

export const __flowInternals = { diffSnapshot, snapshotTree, parseAdversarialDispatch, normAttacks, attackShortfall, normAdversarialFanout, buildSubBrief }
