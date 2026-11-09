/**
 * dsh-arch · 架构插件（终端执行架构）
 *
 * 设计口径（一句话）：把「任务」落成一条固定架构的流水线——
 *   规划（Plan）→ 执行（Exec：系统终端子进程）→ 校验（Verify：退出码 / 输出正则）→ 回执（Receipt：JSON + 逐步日志落盘）。
 *
 * 为什么是「架构」而不是一段脚本：
 *   1. 分层固定：每步都有 命令 / 目录 / 超时 / 判定 / 失败策略，不是随手 exec；
 *   2. 可核验：判定条件写进计划（expect），不是执行者自己说成功；
 *   3. 可回执：运行结束 receipt.json 与逐步日志落盘，事后可复查、可对比、可重放；
 *   4. 可叫停：所有子进程按运行 id 停止（Windows 用 taskkill /T /F 杀进程树）。
 *
 * 边界：本插件只「执行调用方给的终端命令」。命令从哪来、是否该跑，由调用方（模型/人）
 * 与 DSH 的沙箱/审批负责；插件不做命令白名单，也不支持交互式命令（需要 stdin/TUI 的跑不了）。
 */

import { spawn, spawnSync } from 'node:child_process'
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve, sep } from 'node:path'
import { buildFlowTool } from './flow.js'

export const name = 'dsh-arch'
export const inject = ['tools']
export const VERSION = '0.6.2'

const RUN_ID_RE = /^arch-[0-9a-z]+-[0-9a-z]+$/
const MAX_HEAD = 8192
const MAX_TAIL = 65536
const MAX_MATCH = 1048576
const KEEP_LIVE = 10

const DEFAULT_CONFIG = {
  enabled: true,
  home: '',
  shell: 'auto',
  cwd: '',
  timeoutMs: 120000,
  maxOutputBytes: 262144,
  keepRuns: 50,
  /* v0.5.0：skills 目录回退源（正常走 DSH 活体 skills 服务；只有服务不可用时才扫这两个根）。 */
  skillRoots: [],
  /* v0.6.0：终端执行路线。pty = 宿主 ctx.terminals（dsh-terminal-bash 持久 PTY）里的独立会话；
     process = 原生隐藏子进程；auto（默认）=有 terminals 服务且调用方给了 owner 时走 pty，否则 process。 */
  terminalMode: 'auto',
  /* PTY 会话的 backendType（dsh-terminal-bash 默认注册为 'shell'）。 */
  terminalType: 'shell',
}

const STATUS_CN = {
  pending: '待执行',
  running: '执行中',
  done: '完成',
  warn: '完成（有警告）',
  failed: '失败',
  stopped: '已叫停',
  skipped: '跳过',
}

const STEP_MARK = {
  done: '✓',
  warn: '△',
  failed: '✗',
  skipped: '·',
  running: '…',
  pending: '○',
  stopped: '■',
}

/* ───────── 基础助手 ───────── */

function textOut() {
  return {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: String(value ?? '') }],
  }
}

function iso(d = new Date()) {
  return d.toISOString()
}

function fmtMs(ms) {
  if (ms == null || !Number.isFinite(Number(ms))) return '-'
  const n = Number(ms)
  if (n < 1000) return `${Math.round(n)}ms`
  return `${(n / 1000).toFixed(1)}s`
}

function statusCn(s) {
  return STATUS_CN[s] || s || '-'
}

function expandHome(p) {
  const s = String(p ?? '')
  if (s === '~') return homedir()
  if (s.startsWith('~/') || s.startsWith('~\\')) return join(homedir(), s.slice(2))
  return s
}

function defaultHome() {
  return process.env.DSH_ARCH_HOME || join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'arch')
}

function trimText(s, n) {
  const t = String(s ?? '')
  return t.length <= n ? t : t.slice(0, n)
}

function slug(s) {
  return String(s || '').replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'step'
}

function newRunId() {
  return `arch-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
}

function resolveShell(spec) {
  const s = spec ?? 'auto'
  if (s && typeof s === 'object' && typeof s.exe === 'string') {
    return { exe: s.exe, args: Array.isArray(s.args) ? s.args.slice() : ['-Command'], kind: String(s.kind || s.exe) }
  }
  const key = String(s || 'auto').toLowerCase()
  if (process.platform === 'win32') {
    if (key === 'cmd') return { exe: process.env.ComSpec || 'cmd.exe', args: ['/d', '/s', '/c'], kind: 'cmd' }
    if (key === 'pwsh') return { exe: 'pwsh.exe', args: ['-NoProfile', '-NonInteractive', '-Command'], kind: 'pwsh' }
    if (key === 'bash') return { exe: 'bash.exe', args: ['-lc'], kind: 'bash' }
    if (key === 'sh') return { exe: 'sh.exe', args: ['-lc'], kind: 'sh' }
    return { exe: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command'], kind: 'powershell' }
  }
  if (key === 'bash') return { exe: 'bash', args: ['-lc'], kind: 'bash' }
  return { exe: 'sh', args: ['-lc'], kind: 'sh' }
}

/** 终止终端进程：先尝试整棵进程树，再兜底直接终止主进程。
 *
 *  实测口径（本机 DSH 沙箱，Windows）：`taskkill /PID … /T /F` 会被拒
 *  （`ERROR: Access denied`），而 `child.kill()`（TerminateProcess）可靠生效。
 *  所以两步都做：taskkill 负责收子孙进程（能收就收），250ms 内没等到退出就
 *  child.kill() 兜底——否则超时/叫停会一直等子进程自己跑完（实测 sleep 30s 跑满）。
 */
function killTree(child) {
  if (!child) return
  try {
    if (child.exitCode !== null || child.signalCode !== null) return
  } catch {
    /* 忽略 */
  }
  let treeTried = false
  try {
    if (process.platform === 'win32') {
      if (child.pid) {
        const tk = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' })
        tk.on('error', () => {})
        treeTried = true
      }
    } else if (child.pid) {
      try {
        process.kill(-child.pid, 'SIGKILL')
        treeTried = true
      } catch {
        /* 没有独立进程组，交给兜底 */
      }
    }
  } catch {
    /* 忽略 */
  }
  const hard = setTimeout(() => {
    try {
      child.kill('SIGKILL')
    } catch {
      /* 已退出 */
    }
  }, treeTried ? 250 : 0)
  if (typeof hard.unref === 'function') hard.unref()
}

/** 读文件末尾 N 行（只读最后 256KB，避免大日志爆内存）。 */
function readTailLines(file, n) {
  try {
    const st = statSync(file)
    const max = 256 * 1024
    const start = Math.max(0, st.size - max)
    const len = st.size - start
    const fd = openSync(file, 'r')
    const buf = Buffer.alloc(len)
    try {
      readSync(fd, buf, 0, len, start)
    } finally {
      closeSync(fd)
    }
    let txt = buf.toString('utf8')
    if (start > 0) {
      const cut = txt.indexOf('\n')
      if (cut >= 0) txt = txt.slice(cut + 1)
    }
    const lines = txt.split(/\r?\n/)
    return lines.slice(-Math.max(1, n)).join('\n')
  } catch (e) {
    return `（读取日志失败：${e?.message ?? e}）`
  }
}

/** 校验并规范化 expect：数字=期望退出码；对象支持 { exitCode, match, notMatch }。 */
function normalizeExpect(expect, idx) {
  if (expect == null) return {}
  if (typeof expect === 'number') {
    if (!Number.isFinite(expect)) throw new Error(`第 ${idx + 1} 步的 expect 不是合法数字`)
    return { exitCode: expect }
  }
  if (typeof expect !== 'object') throw new Error(`第 ${idx + 1} 步的 expect 不合法（应为数字或 { exitCode, match, notMatch }）`)
  const out = {}
  if (expect.exitCode !== undefined && expect.exitCode !== null) {
    const n = Number(expect.exitCode)
    if (!Number.isFinite(n)) throw new Error(`第 ${idx + 1} 步 expect.exitCode 不是数字`)
    out.exitCode = n
  }
  for (const key of ['match', 'notMatch']) {
    if (expect[key] == null) continue
    if (typeof expect[key] !== 'string') throw new Error(`第 ${idx + 1} 步 expect.${key} 应为正则字符串`)
    if (!expect[key]) continue
    try {
      // eslint-disable-next-line no-new
      new RegExp(expect[key])
    } catch (e) {
      throw new Error(`第 ${idx + 1} 步 expect.${key} 不是合法正则：${e?.message ?? e}`)
    }
    out[key] = expect[key]
  }
  return out
}

/* ───────── 引擎（四层架构的实现） ───────── */

function createEngine(ctx, cfg, log) {
  const home = resolve(expandHome(cfg.home || defaultHome()))
  const runsDir = join(home, 'runs')
  const enabled = cfg.enabled !== false && process.env.DSH_ARCH_ENABLED !== '0'
  const keepRuns = Math.max(1, Number(cfg.keepRuns) || DEFAULT_CONFIG.keepRuns)
  const maxOutputBytes = Math.max(1024, Number(cfg.maxOutputBytes) || DEFAULT_CONFIG.maxOutputBytes)
  const defaultTimeout = Number.isFinite(Number(cfg.timeoutMs)) ? Math.max(0, Number(cfg.timeoutMs)) : DEFAULT_CONFIG.timeoutMs
  const defaultShell = resolveShell(cfg.shell)
  const live = new Map()

  try {
    mkdirSync(runsDir, { recursive: true })
  } catch (e) {
    log(`创建回执目录失败：${e?.message ?? e}`)
  }

  /* ── 回执层：落盘 ── */

  function readReceipt(id) {
    if (!RUN_ID_RE.test(String(id || ''))) return null
    try {
      return JSON.parse(readFileSync(join(runsDir, id, 'receipt.json'), 'utf8'))
    } catch {
      return null
    }
  }

  function writeReceipt(run) {
    const body = {
      plugin: name,
      version: VERSION,
      receiptVersion: 1,
      id: run.id,
      title: run.title,
      status: run.status,
      startedAt: run.startedAt,
      endedAt: run.endedAt,
      ms: run.ms,
      cwd: run.cwd,
      shell: run.shellKind,
      /* v0.6.0：终端执行路线（pty=宿主 ctx.terminals 会话 / process=原生子进程），fallback 记明回退原因。 */
      terminalMode: run.terminalMode || null,
      terminalFallback: run.terminalFallback || null,
      stopOnFail: run.stopOnFail,
      summary: run.summary,
      error: run.error || null,
      steps: (run.steps || []).map((st) => ({
        i: st.i,
        name: st.name,
        cmd: st.cmd,
        cwd: st.cwd,
        status: st.status,
        exitCode: st.exitCode ?? null,
        signal: st.signal ?? null,
        timedOut: !!st.timedOut,
        allowFail: !!st.allowFail,
        ms: st.ms ?? null,
        error: st.error || null,
        bytes: st.bytes ?? null,
        logFile: st.logFile || null,
        pid: st.pid ?? null,
        head: trimText(st.head, 2000),
        tail: trimText(st.tail, 4000),
      })),
    }
    try {
      writeFileSync(join(run.logDir, 'receipt.json'), JSON.stringify(body, null, 2) + '\n')
    } catch (e) {
      log(`写回执失败 ${run.id}：${e?.message ?? e}`)
    }
  }

  function prune() {
    try {
      const dirs = readdirSync(runsDir, { withFileTypes: true })
        .filter((d) => d.isDirectory() && RUN_ID_RE.test(d.name))
        .map((d) => {
          let mtime = 0
          try {
            mtime = statSync(join(runsDir, d.name)).mtimeMs
          } catch {
            /* 忽略 */
          }
          return { name: d.name, mtime }
        })
        .sort((a, b) => b.mtime - a.mtime)
      for (const d of dirs.slice(keepRuns)) {
        if (live.has(d.name)) continue
        try {
          rmSync(join(runsDir, d.name), { recursive: true, force: true })
        } catch {
          /* 忽略 */
        }
      }
    } catch {
      /* 忽略 */
    }
  }

  /* ── 执行层：单步终端子进程 ── */

  /* v0.5.1：可见系统终端。为什么要绕这么一圈——
     1. Node 在 Windows 上 spawn（detached 与否、windowsHide 真假）都不会给子进程新建可见控制台，
        所以「直接 spawn 一个可见终端」做不到；必须借一个 GUI 进程去开窗口。
     2. `cmd /c start` 那条路在本机 Electron 宿主里不可靠（实测：窗口偶发出现、内层命令不执行、
        退出码回不来），已弃用。
     3. Windows Terminal（wt.exe）可靠：`wt -w new cmd /d /c <launcher.cmd>` 实测能弹出独立窗口，
        且内层命令照常执行。于是窗口里跑 launcher，launcher 用 node helper 跑真正的命令，
        退出码经标记文件（console-NN.code.json）回传给父进程——窗口只负责「看得见」，
        判定仍走 exitCode/expect/log，和隐藏模式完全一致。 */
  const CONSOLE_HELPER = `import { closeSync, openSync, readFileSync, writeFileSync } from 'node:fs'
import { spawn } from 'node:child_process'

const cfg = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const fd = openSync(cfg.log, 'a')
const child = spawn(cfg.exe, [...(cfg.args || []), cfg.cmd], {
  cwd: cfg.cwd,
  env: process.env,
  windowsHide: true,
  stdio: ['ignore', fd, fd],
})
try {
  closeSync(fd)
} catch {
  /* 句柄已交给子进程 */
}
let settled = false
let timer = null
const out = (rec) => {
  if (settled) return
  settled = true
  try {
    writeFileSync(cfg.marker, JSON.stringify({ ...rec, pid: child.pid ?? null, ms: Date.now() - cfg.startedAt }))
  } catch {
    /* 标记写不进去就由父进程的硬超时兜底 */
  }
}
if (cfg.timeoutMs > 0) {
  timer = setTimeout(() => {
    out({ timedOut: true, exitCode: null, signal: null })
    try {
      spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' })
    } catch {
      /* 忽略 */
    }
    try {
      child.kill('SIGKILL')
    } catch {
      /* 忽略 */
    }
  }, cfg.timeoutMs)
}
child.on('error', (e) => {
  if (timer) clearTimeout(timer)
  out({ spawnError: true, error: String(e?.message ?? e) })
})
child.on('close', (code, signal) => {
  if (timer) clearTimeout(timer)
  out({ exitCode: code ?? null, signal: signal ?? null })
})
`

  /* v0.6.0：PTY 会话里的「方言无关」启动器。
     为什么不让插件自己往 PTY 里拼 shell 语句：宿主 dsh-terminal-bash 后端可能配 bash 方言、也可能配 pwsh
     方言，而 st.cmd 是给 run.shell（powershell/pwsh/cmd/bash/sh）的——两句方言混一起必然踩引号。
     做法：PTY 里只发一句 `node "<launcher>" "<cfg>"`（两种方言都认），由这个 node 进程 spawn 真正的
     run.shell + 命令、stdio 继承 PTY，于是输出照常进会话滚动区；起止标记由 node 自己打印（不经过 shell 方言），
     退出码原样带在结束标记里回传给插件。 */
  const PTY_HELPER = `import { readFileSync } from 'node:fs'
import { spawn } from 'node:child_process'

const cfg = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const START = '__DSH_ARCH_START_' + cfg.nonce + '__'
const END = '__DSH_ARCH_END_' + cfg.nonce + '__'
const write = (s) => { try { process.stdout.write(s) } catch { /* 会话已关 */ } }
write(START + '\\n')
const child = spawn(cfg.exe, [...(cfg.args || []), cfg.cmd], {
  cwd: cfg.cwd,
  env: { ...process.env, DSH_ARCH: '1', DSH_ARCH_RUN_ID: cfg.runId || '', DSH_ARCH_STEP: String(cfg.step ?? '') },
  windowsHide: true,
  stdio: ['ignore', 'inherit', 'inherit'],
})
child.on('error', (e) => {
  write('\\n' + END + 'null:' + String(e?.message ?? e).replace(/\\s+/g, ' ').slice(0, 200) + '\\n')
  process.exit(1)
})
child.on('close', (code, signal) => {
  write('\\n' + END + (code === null ? 'null' : String(code)) + ':' + (signal || '-') + '\\n')
  process.exit(0)
})
`

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

  /* 取宿主终端服务（可选）。cordis 的 ctx.get 对未注册服务返回 undefined，不抛错。 */
  function terminalService() {
    try {
      const s = typeof ctx?.get === 'function' ? ctx.get('terminals') : undefined
      return s && typeof s.spawn === 'function' && typeof s.startSend === 'function' && typeof s.read === 'function' ? s : null
    } catch {
      return null
    }
  }

  function findWindowsTerminal() {
    if (process.platform !== 'win32') return null
    /* wt.exe 是 WindowsApps 里的 App Execution Alias（重解析点）：statSync/existsSync 会 EACCES，
       所以判存在只能用 readdirSync 看目录项，或 where.exe（status=0 即存在）。 */
    const dir = join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WindowsApps')
    try {
      if (readdirSync(dir).some((n) => n.toLowerCase() === 'wt.exe')) return 'wt.exe'
    } catch {
      /* 目录读不到就退回 where.exe */
    }
    try {
      const r = spawnSync('where.exe', ['wt'], { windowsHide: true, stdio: 'ignore' })
      if (r.status === 0) return 'wt.exe'
    } catch {
      /* 忽略 */
    }
    return null
  }

  /* 起一个可见终端窗口跑这一步；返回 { child, marker }，父进程轮询 marker 取退出码。 */
  function startConsoleWindow(run, st, logPath) {
    const wt = findWindowsTerminal()
    if (!wt) throw new Error('未找到 Windows Terminal（wt.exe），无法开可见终端窗口')
    const nn = String(st.i).padStart(2, '0')
    const helper = join(run.logDir, 'console-run.mjs')
    const cfgFile = join(run.logDir, `console-${nn}.cfg.json`)
    const marker = join(run.logDir, `console-${nn}.code.json`)
    const launcher = join(run.logDir, `console-${nn}.cmd`)
    writeFileSync(helper, CONSOLE_HELPER, 'utf8')
    writeFileSync(
      cfgFile,
      JSON.stringify({
        exe: run.shell.exe,
        args: run.shell.args,
        cmd: st.cmd,
        cwd: st.cwd,
        log: logPath,
        marker,
        timeoutMs: st.timeoutMs,
        startedAt: Date.now(),
      }),
      'utf8',
    )
    try {
      rmSync(marker, { force: true })
    } catch {
      /* 忽略 */
    }
    const title = `dsh-arch · ${run.title} · ${st.name}`.replace(/[\r\n%]/g, ' ').slice(0, 120)
    const keepOpenMs = st.keepOpenMs ?? run.keepOpenMs ?? 1500
    /* v0.6.1 修（窗口报「系统找不到指定的路径」的根因）：
       1. launcher 是 UTF-8 写的，cmd 默认按 OEM 代码页（本机 936/GBK）读 ⇒ 中文标题乱码、
          含中文的 `cd /d "<路径>"` 行被读成不存在的路径。首行 `chcp 65001` 后再解析后续行即可。
       2. 不在 launcher 里 cd：工作目录改由 node 启动器 spawn 子命令时用 cfg.cwd 指定，
          路径不再经过 cmd 解析（带空格/中文都安全），窗口本身也已在 st.cwd 启动。
       3. node 用 process.execPath 绝对路径，不依赖窗口的 PATH。 */
    const lines = [
      '@echo off',
      'chcp 65001 >nul',
      `title ${title}`,
      `"${process.execPath}" "${helper}" "${cfgFile}"`,
    ]
    if (keepOpenMs > 0) lines.push(`timeout /t ${Math.max(1, Math.round(keepOpenMs / 1000))} /nobreak >nul`)
    writeFileSync(launcher, lines.join('\r\n') + '\r\n', 'utf8')
    const child = spawn(wt, ['-w', 'new', 'cmd', '/d', '/c', launcher], {
      cwd: st.cwd,
      env: { ...process.env, DSH_ARCH: '1', DSH_ARCH_RUN_ID: run.id, DSH_ARCH_STEP: String(st.i) },
      windowsHide: false,
      detached: true,
      stdio: 'ignore',
    })
    return { child, marker }
  }

  /* v0.6.0：在宿主 PTY 会话里跑一步（dsh-terminal-bash 后端）。每步 = 一个独立终端会话 +
     独立 PID + 独立日志；输出从会话滚动区读回、起止标记回传退出码，判定仍走 settle()。 */
  async function execPtyStep(pty, run, st, logPath, onPid) {
    const nn = String(st.i).padStart(2, '0')
    const nonce = `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`
    const START = `__DSH_ARCH_START_${nonce}__`
    const END = `__DSH_ARCH_END_${nonce}__`
    const helper = join(run.logDir, `pty-${nn}.mjs`)
    const cfgFile = join(run.logDir, `pty-${nn}.cfg.json`)
    writeFileSync(helper, PTY_HELPER, 'utf8')
    writeFileSync(
      cfgFile,
      JSON.stringify({
        exe: run.shell.exe,
        args: run.shell.args,
        cmd: st.cmd,
        cwd: st.cwd,
        nonce,
        runId: run.id,
        step: st.i,
      }),
      'utf8',
    )
    const slash = (p) => String(p).replace(/\\/g, '/')
    const sp = await pty.spawn(run.owner, {
      type: run.terminalBackend || 'shell',
      name: `dsh-arch · ${run.title} · ${st.name}`.replace(/[\r\n]/g, ' ').slice(0, 120),
      cwd: st.cwd,
    })
    const sessionId = sp.sessionId
    const sessionPid = typeof sp.pid === 'number' ? sp.pid : null
    run.ptySession = { id: sessionId, pid: sessionPid }
    if (typeof onPid === 'function') onPid(sessionPid)

    let text = ''
    let sawEnd = false
    let exitCode = null
    let didTimeout = false
    const deadline = st.timeoutMs > 0 ? Date.now() + st.timeoutMs : 0
    const endRe = new RegExp(`${END}(-?\\d+|null):(\\S*)`)
    try {
      const op = pty.startSend(run.owner, sessionId, { text: `node "${slash(helper)}" "${slash(cfgFile)}"`, submit: true })
      if (op && op.done && typeof op.done.catch === 'function') op.done.catch(() => {})
    } catch (e) {
      try {
        await pty.kill(run.owner, sessionId, 'dsh-arch send failed')
      } catch {
        /* 忽略 */
      }
      throw new Error(`无法向终端会话发送命令：${e?.message ?? e}`)
    }

    for (;;) {
      try {
        const r = pty.read(run.owner, sessionId, { count: 4000 })
        if (r && typeof r.text === 'string' && r.text.length) text = r.text
      } catch {
        /* 会话可能已退出，继续看快照 */
      }
      const m = endRe.exec(text)
      if (m) {
        sawEnd = true
        exitCode = m[1] === 'null' ? null : Number(m[1])
        break
      }
      try {
        const snaps = (typeof pty.list === 'function' ? pty.list(run.owner) : []) || []
        const snap = snaps.find((s) => s && (s.sessionId === sessionId || s.id === sessionId))
        if (snap && snap.status && snap.status.kind === 'exited') {
          sawEnd = true
          exitCode = snap.status.exitCode ?? null
          break
        }
      } catch {
        /* 忽略 */
      }
      if (deadline && Date.now() > deadline) {
        didTimeout = true
        break
      }
      if (run.stopRequested) break
      await sleep(120)
    }

    const sIdx = text.lastIndexOf(START)
    const eIdx = text.lastIndexOf(END)
    const outText = sIdx >= 0 && eIdx > sIdx ? text.slice(sIdx + START.length, eIdx) : text
    try {
      const body = outText.replace(/\r\n/g, '\n').replace(/^\n+/, '')
      appendFileSync(logPath, body + (body && !body.endsWith('\n') ? '\n' : ''), 'utf8')
    } catch {
      /* 日志写不进去就让 settle 读到空内容 */
    }
    try {
      await pty.kill(run.owner, sessionId, didTimeout ? 'dsh-arch step timeout' : 'dsh-arch step finished')
    } catch {
      /* 忽略 */
    }
    run.ptySession = null
    if (didTimeout) return { exitCode: null, signal: null, timedOut: true }
    if (!sawEnd) return { spawnError: true, error: '终端会话没有回传结束标记（会话被关闭或输出被截断）' }
    return { exitCode, signal: null }
  }

  async function execStep(run, st) {
    const logName = `${String(st.i).padStart(2, '0')}-${slug(st.name)}.log`
    const logPath = join(run.logDir, logName)
    const header =
      `# dsh-arch 步骤日志\n# run: ${run.id}\n# step: ${st.i} ${st.name}\n# cmd: ${st.cmd}\n# cwd: ${st.cwd}\n` +
      `# shell: ${run.shellKind} (${run.shell.exe} ${run.shell.args.join(' ')})\n# at: ${iso()}\n---\n`
    try {
      writeFileSync(logPath, header, 'utf8')
    } catch (e) {
      return { ok: false, error: `无法创建日志文件：${e?.message ?? e}`, exitCode: null, signal: null, timedOut: false, bytes: 0, head: '', tail: '', logFile: null }
    }
    const headerBytes = Buffer.byteLength(header, 'utf8')
    const readCap = Math.max(MAX_TAIL, Math.min(maxOutputBytes, MAX_MATCH))
    const expect = st.expect || {}
    const wantCode = Number.isFinite(Number(expect.exitCode)) ? Number(expect.exitCode) : 0
    const startedAt = Date.now()
    let timedOut = false

    /* 终端输出直接由子进程写进日志文件（stdin 关闭；stdout/stderr 都指向同一个文件句柄）。
       为什么不用管道读：DSH 会话可能跑在受限沙箱里（禁止命名管道，pipe 会 EPERM），
       而「子进程写文件」不受影响——于是即使沙箱里也能真跑终端、日志照样落盘。
       代价：没有实时流式回显；要看输出用 arch_log 读日志尾部（运行中也能读到已写部分）。 */
    return await new Promise((resolveStep) => {
      let settled = false
      const settle = (record) => {
        if (settled) return
        settled = true
        let size = 0
        let text = ''
        try {
          size = statSync(logPath).size
          const n = Math.min(Math.max(0, size - headerBytes), readCap)
          if (n > 0) {
            const rfd = openSync(logPath, 'r')
            const buf = Buffer.alloc(n)
            try {
              readSync(rfd, buf, 0, n, headerBytes)
            } finally {
              closeSync(rfd)
            }
            text = buf.toString('utf8')
          }
        } catch {
          /* 日志读不到就按空处理 */
        }

        const code = record.exitCode ?? null
        const signal = record.signal ?? null
        let ok = !record.spawnError && !timedOut && !run.stopRequested && signal == null && code === wantCode
        let error = record.error ?? null
        if (!record.spawnError) {
          if (timedOut) {
            ok = false
            error = `超时（>${st.timeoutMs}ms），进程已终止`
          } else if (run.stopRequested) {
            ok = false
            error = error || '已被 arch_stop 叫停'
          } else if (signal != null) {
            ok = false
            error = `被信号终止：${signal}`
          } else if (code !== wantCode) {
            ok = false
            error = `退出码 ${code ?? '(null)'}，期望 ${wantCode}`
          }
          if (ok && expect.match) {
            try {
              if (!new RegExp(expect.match).test(text)) {
                ok = false
                error = `输出不匹配 /${expect.match}/`
              }
            } catch (e) {
              ok = false
              error = `expect.match 正则异常：${e?.message ?? e}`
            }
          }
          if (ok && expect.notMatch) {
            try {
              if (new RegExp(expect.notMatch).test(text)) {
                ok = false
                error = `输出命中排除规则 /${expect.notMatch}/`
              }
            } catch (e) {
              ok = false
              error = `expect.notMatch 正则异常：${e?.message ?? e}`
            }
          }
        }

        resolveStep({
          exitCode: code,
          signal,
          timedOut,
          ok,
          error,
          bytes: Math.max(0, size - headerBytes),
          head: text.slice(0, MAX_HEAD),
          tail: text.slice(-MAX_TAIL),
          logFile: `${run.id}/${logName}`,
          startedAt,
          /* v0.5.0：记录每步终端进程 pid —— 阵型用它证明「每个角色的任务各在自己的系统终端里跑」（pid 各不相同）。
             v0.6.0：PTY 路线记会话 pid。 */
          pid: child?.pid ?? ptyPid ?? null,
        })
      }

      let child
      let fd = -1
      let ptyPid = null

      /* v0.6.0：PTY 路线（宿主 ctx.terminals = dsh-terminal-bash 持久终端）。
         每步一个独立终端会话、独立 PID、独立日志；判定/日志/expect 与隐藏模式共用 settle()。
         拿不到 terminals 服务或缺 owner 时记明原因，回退原生子进程（不静默）。 */
      if (run.terminalIntent === 'pty') {
        const pty = terminalService()
        let backends = []
        try {
          backends = pty && typeof pty.listBackends === 'function' ? pty.listBackends() : []
        } catch {
          backends = []
        }
        if (pty && run.owner && backends.length) {
          run.terminalMode = 'pty'
          run.terminalBackend = backends.includes(run.terminalType) ? run.terminalType : backends[0]
          execPtyStep(pty, run, st, logPath, (pid) => {
            ptyPid = pid
          })
            .then((rec) => {
              if (rec && rec.timedOut) {
                timedOut = true
                return settle({ exitCode: null, signal: null })
              }
              settle(rec)
            })
            .catch((e) => settle({ spawnError: true, error: `PTY 执行失败：${e?.message ?? e}` }))
          return
        }
        run.terminalMode = 'process'
        run.terminalFallback = pty ? '缺少调用方 Agent（owner），无法在终端服务里开会话' : '宿主未提供 terminals 服务（dsh-terminal-bash 未装载）'
      }

      /* v0.5.1：可见终端窗口模式（console=true）。窗口里跑 launcher→helper→真正的命令，
         退出码/超时经标记文件回传；判定逻辑与隐藏模式共用下面的 settle()。 */
      if (run.console) {
        let win
        try {
          win = startConsoleWindow(run, st, logPath)
        } catch (e) {
          return settle({ spawnError: true, error: `无法启动终端窗口：${e?.message ?? e}` })
        }
        child = win.child
        run.proc = child
        const hardMs = (st.timeoutMs > 0 ? st.timeoutMs : 0) + 20000
        let polling = true
        const poll = setInterval(() => {
          if (!polling) return
          let raw = ''
          try {
            if (!existsSync(win.marker)) return
            raw = readFileSync(win.marker, 'utf8')
          } catch {
            return
          }
          if (!raw.trim()) return
          let rec
          try {
            rec = JSON.parse(raw)
          } catch {
            return /* 标记文件正在写，下一轮再读 */
          }
          polling = false
          clearInterval(poll)
          clearTimeout(hardTimer)
          if (rec.spawnError) return settle({ spawnError: true, error: `终端进程错误：${rec.error}` })
          if (rec.timedOut) {
            timedOut = true
            return settle({ exitCode: null, signal: null })
          }
          settle({ exitCode: rec.exitCode ?? null, signal: rec.signal ?? null })
        }, 150)
        const hardTimer = setTimeout(() => {
          if (!polling) return
          polling = false
          clearInterval(poll)
          timedOut = true
          killTree(child)
          settle({ exitCode: null, signal: null })
        }, hardMs)
        return
      }

      try {
        fd = openSync(logPath, 'a')
        child = spawn(run.shell.exe, [...run.shell.args, st.cmd], {
          cwd: st.cwd,
          env: { ...process.env, DSH_ARCH: '1', DSH_ARCH_RUN_ID: run.id, DSH_ARCH_STEP: String(st.i) },
          windowsHide: true,
          detached: process.platform !== 'win32',
          stdio: ['ignore', fd, fd],
        })
      } catch (e) {
        try {
          if (fd >= 0) closeSync(fd)
        } catch {
          /* 忽略 */
        }
        return settle({ spawnError: true, error: `无法启动终端：${e?.message ?? e}` })
      }
      try {
        closeSync(fd)
      } catch {
        /* 句柄已交给子进程 */
      }
      run.proc = child

      const timer =
        st.timeoutMs > 0
          ? setTimeout(() => {
              timedOut = true
              killTree(child)
            }, st.timeoutMs)
          : null

      child.on('error', (e) => {
        if (timer) clearTimeout(timer)
        settle({ spawnError: true, error: `终端进程错误：${e?.message ?? e}` })
      })
      child.on('close', (code, signal) => {
        if (timer) clearTimeout(timer)
        settle({ exitCode: code ?? null, signal: signal ?? null })
      })
    })
  }

  /* ── 执行层：按计划顺序跑完 ── */

  async function runAll(run) {
    writeReceipt(run)
    for (const st of run.steps) {
      if (run.stopRequested) {
        st.status = 'skipped'
        run.summary.skipped++
        continue
      }
      st.status = 'running'
      st.startedAt = iso()
      st.logFile = `${run.id}/${String(st.i).padStart(2, '0')}-${slug(st.name)}.log`
      writeReceipt(run)
      const t0 = Date.now()
      const rec = await execStep(run, st)
      st.ms = Date.now() - t0
      st.endedAt = iso()
      st.exitCode = rec.exitCode
      st.signal = rec.signal
      st.timedOut = rec.timedOut
      st.bytes = rec.bytes
      st.head = rec.head
      st.tail = rec.tail
      st.logFile = rec.logFile
      st.ok = rec.ok
      st.error = rec.error
      st.pid = rec.pid ?? null

      if (run.stopRequested) {
        st.status = 'stopped'
        st.ok = false
        st.error = st.error || '已叫停'
        run.summary.stopped++
      } else if (rec.ok) {
        st.status = 'done'
        run.summary.pass++
      } else if (st.allowFail) {
        st.status = 'warn'
        run.summary.warn++
      } else {
        st.status = 'failed'
        st.error = st.error || '步骤失败'
        run.summary.fail++
        run.status = 'failed'
      }

      writeReceipt(run)

      if (st.status === 'stopped') break
      if (st.status === 'failed' && run.stopOnFail) {
        const at = run.steps.indexOf(st)
        for (const s of run.steps.slice(at + 1)) {
          if (s.status === 'pending') {
            s.status = 'skipped'
            run.summary.skipped++
          }
        }
        break
      }
    }
    if (run.status === 'running') run.status = run.summary.warn > 0 ? 'warn' : 'done'
    if (run.stopRequested) run.status = 'stopped'
  }

  function finalize(run) {
    run.endedAt = iso()
    run.ms = Date.now() - run.startedAtMs
    run.proc = null
    if (run.status === 'running') {
      run.status = run.summary.fail ? 'failed' : run.summary.warn ? 'warn' : 'done'
    }
    writeReceipt(run)
    prune()
    const finished = [...live.values()]
      .filter((r) => r.status !== 'running')
      .sort((a, b) => b.startedAtMs - a.startedAtMs)
    for (const r of finished.slice(KEEP_LIVE)) live.delete(r.id)
    log(`运行 ${run.id} 结束：${run.status}（${fmtMs(run.ms)}｜✓${run.summary.pass} △${run.summary.warn} ✗${run.summary.fail} ·${run.summary.skipped}）`)
  }

  /* ── 规划层：校验计划、分配 id、建回执目录 ── */

  function start(opts = {}) {
    if (!enabled) throw new Error('dsh-arch 已关闭（config.enabled=false 或 DSH_ARCH_ENABLED=0）')
    const title = String(opts.title ?? '').trim() || '未命名任务'
    const rawSteps = Array.isArray(opts.steps) ? opts.steps : opts.command ? [opts.command] : []
    if (!rawSteps.length) throw new Error('缺少 steps（数组）或 command（单条命令）')
    const cwd = resolve(expandHome(opts.cwd || cfg.cwd || process.cwd()))
    if (!existsSync(cwd) || !statSync(cwd).isDirectory()) throw new Error(`工作目录不存在或不是目录：${cwd}`)
    const sh = opts.shell ? resolveShell(opts.shell) : defaultShell
    const timeoutDefault = Number.isFinite(Number(opts.timeoutMs)) ? Math.max(0, Number(opts.timeoutMs)) : defaultTimeout

    const steps = rawSteps.map((raw, idx) => {
      const o = typeof raw === 'string' ? { cmd: raw } : raw ?? {}
      if (typeof o.cmd !== 'string' || !o.cmd.trim()) throw new Error(`第 ${idx + 1} 步缺少终端命令（cmd）`)
      const stepCwd = resolve(expandHome(o.cwd || cwd))
      if (!existsSync(stepCwd) || !statSync(stepCwd).isDirectory()) throw new Error(`第 ${idx + 1} 步工作目录不存在：${stepCwd}`)
      const t = o.timeoutMs === 0 ? 0 : Number.isFinite(Number(o.timeoutMs)) ? Math.max(0, Number(o.timeoutMs)) : timeoutDefault
      return {
        i: idx + 1,
        name: String(o.name || `步骤 ${idx + 1}`).trim() || `步骤 ${idx + 1}`,
        cmd: o.cmd,
        cwd: stepCwd,
        timeoutMs: t,
        expect: normalizeExpect(o.expect, idx),
        allowFail: o.allowFail === true,
        status: 'pending',
        startedAt: null,
        endedAt: null,
        ms: 0,
        exitCode: null,
        signal: null,
        timedOut: false,
        ok: null,
        error: null,
        bytes: 0,
        logFile: null,
        pid: null,
        head: '',
        tail: '',
      }
    })

    const id = newRunId()
    const logDir = join(runsDir, id)
    try {
      mkdirSync(logDir, { recursive: true })
    } catch (e) {
      throw new Error(`创建回执目录失败：${e?.message ?? e}`)
    }

    const run = {
      id,
      title,
      status: 'running',
      startedAt: iso(),
      startedAtMs: Date.now(),
      endedAt: null,
      ms: null,
      cwd,
      shell: sh,
      shellKind: sh.kind,
      stopOnFail: opts.stopOnFail !== false,
      /* v0.5.1：console=true ⇒ 每个任务在自己的可见系统终端窗口里跑（Windows Terminal）。
         窗口只负责「看得见」；退出码/超时/日志/expect 判定与隐藏模式共用一套（token 仍落回执）。 */
      console: opts.console === true,
      keepOpenMs: Number.isFinite(Number(opts.keepOpenMs)) ? Math.max(0, Number(opts.keepOpenMs)) : 1500,
      /* v0.6.0：终端执行路线。terminal:'pty' 强制走宿主终端服务（不可用即记 fallback 走 process），
         'process' 强制原生子进程；auto/缺省由 terminalIntent 在 execStep 里按服务可用性决定。
         owner 是调用方 Agent 对象（ctx.terminals.spawn 的第一个参数），必须由工具层从 exec.agent 传入。 */
      terminalIntent:
        opts.console === true || String(opts.terminal || opts.terminalMode || cfg.terminalMode || 'auto').toLowerCase() === 'process'
          ? 'process'
          : 'pty',
      /* 强制 process 时路线已确定，直接记下来（回执里不留 null）；pty 在 execStep 里按服务可用性落定。 */
      terminalMode:
        opts.console === true || String(opts.terminal || opts.terminalMode || cfg.terminalMode || 'auto').toLowerCase() === 'process'
          ? opts.console === true
            ? 'console'
            : 'process'
          : null,
      terminalFallback: null,
      terminalBackend: null,
      terminalType: String(opts.terminalType || cfg.terminalType || 'shell'),
      owner: opts.owner || null,
      ptySession: null,
      steps,
      summary: { pass: 0, warn: 0, fail: 0, skipped: 0, stopped: 0 },
      error: null,
      stopRequested: false,
      proc: null,
      logDir,
      receiptFile: join(logDir, 'receipt.json'),
      done: null,
    }
    live.set(id, run)
    run.done = (async () => {
      try {
        await runAll(run)
      } catch (e) {
        run.error = e?.message ?? String(e)
        run.status = 'failed'
      } finally {
        finalize(run)
      }
      return run
    })()
    return run
  }

  /* ── 查询 / 叫停 ── */

  function status(id) {
    const key = String(id || '').trim()
    if (!RUN_ID_RE.test(key)) return { ok: false, error: `运行 id 不合法（应形如 arch-xxxx-yyyy）：${key || '(空)'}` }
    const mem = live.get(key)
    if (mem) return { ok: true, run: mem }
    const rec = readReceipt(key)
    if (rec) return { ok: true, run: rec }
    return { ok: false, error: `未找到运行 ${key}（可用 arch_status 不带 id 列出最近的运行）` }
  }

  function listRuns(limit = 20) {
    const n = Math.max(1, Math.min(200, Number(limit) || 20))
    const liveRuns = [...live.values()].sort((a, b) => b.startedAtMs - a.startedAtMs)
    const seen = new Set(liveRuns.map((r) => r.id))
    const disk = []
    try {
      for (const d of readdirSync(runsDir, { withFileTypes: true })) {
        if (!d.isDirectory() || !RUN_ID_RE.test(d.name) || seen.has(d.name)) continue
        const rec = readReceipt(d.name)
        if (rec) disk.push(rec)
      }
    } catch {
      /* 忽略 */
    }
    disk.sort((a, b) => String(b.startedAt || '').localeCompare(String(a.startedAt || '')))
    return [...liveRuns, ...disk].slice(0, n)
  }

  function stop(id) {
    const key = String(id || '').trim()
    if (!RUN_ID_RE.test(key)) return { ok: false, error: `运行 id 不合法：${key || '(空)'}` }
    const run = live.get(key)
    if (!run) {
      const rec = readReceipt(key)
      return { ok: false, error: rec ? `运行 ${key} 已结束（${statusCn(rec.status)}），不用叫停` : `未找到运行 ${key}` }
    }
    if (run.status !== 'running') return { ok: false, error: `运行 ${key} 已结束（${statusCn(run.status)}），不用叫停` }
    run.stopRequested = true
    killTree(run.proc)
    /* v0.6.0：PTY 路线的终端会话不在 run.proc 里，要显式关掉（kill 是异步的，不等它）。 */
    if (run.ptySession && run.owner) {
      const pty = terminalService()
      try {
        if (pty) void pty.kill(run.owner, run.ptySession.id, 'arch_stop')
      } catch {
        /* 忽略 */
      }
      run.ptySession = null
    }
    return { ok: true, id: key }
  }

  function stopAll() {
    const ids = [...live.values()].filter((r) => r.status === 'running').map((r) => r.id)
    for (const id of ids) stop(id)
    return ids
  }

  function logOf(id, stepRef, tailLines = 80) {
    const st = status(id)
    if (!st.ok) return st
    const run = st.run
    const steps = run.steps || []
    if (!steps.length) return { ok: false, error: '该运行没有步骤' }
    let step = null
    if (stepRef == null || stepRef === '') {
      step = steps[steps.length - 1]
    } else if (typeof stepRef === 'number') {
      step = steps.find((s) => Number(s.i) === stepRef) || steps[stepRef - 1]
    } else {
      const q = String(stepRef)
      step = steps.find((s) => String(s.i) === q) || steps.find((s) => String(s.name || '').includes(q))
    }
    if (!step) return { ok: false, error: `未找到步骤 ${stepRef}` }
    let file = null
    if (step.logFile) {
      const cand = resolve(runsDir, step.logFile)
      if (cand.startsWith(runsDir + sep) && existsSync(cand)) file = cand
    }
    if (!file && step.i) {
      const dir = join(runsDir, run.id)
      try {
        const prefix = `${String(step.i).padStart(2, '0')}-`
        const hit = readdirSync(dir).find((f) => f.startsWith(prefix) && f.endsWith('.log'))
        if (hit) file = join(dir, hit)
      } catch {
        /* 忽略 */
      }
    }
    if (!file) return { ok: false, error: `步骤 ${step.i} 还没有日志（该步尚未执行？）` }
    const lines = Math.max(1, Math.min(2000, Number(tailLines) || 80))
    return {
      ok: true,
      id: run.id,
      step: Number(step.i) || 0,
      name: step.name,
      status: step.status,
      file,
      tailLines: lines,
      text: readTailLines(file, lines),
    }
  }

  /* ── 呈现层 ── */

  function renderRun(run) {
    const L = []
    const shellKind = run.shellKind || (run.shell && run.shell.kind) || run.shell || '-'
    const steps = run.steps || []
    const summary = run.summary || { pass: 0, warn: 0, fail: 0, skipped: 0, stopped: 0 }
    const ms = run.ms ?? (run.startedAt ? Date.now() - Date.parse(run.startedAt) : null)
    const receipt = run.receiptFile || join(runsDir, run.id, 'receipt.json')
    L.push(`# 架构运行 · ${run.title || '(未命名任务)'}`)
    L.push(`- id：${run.id}`)
    L.push(`- 状态：${statusCn(run.status)}${run.error ? `（${run.error}）` : ''}`)
    L.push(`- 架构：规划 → 执行（系统终端：${shellKind}）→ 校验（退出码/输出正则）→ 回执`)
    /* v0.6.0：终端路线（pty = 宿主 ctx.terminals 持久终端会话；process = 原生子进程）。 */
    if (run.terminalMode || run.terminalFallback) {
      const mode =
        run.terminalMode === 'pty'
          ? `PTY 会话（${run.terminalBackend || 'shell'}）`
          : run.terminalMode === 'console'
            ? '可见终端窗口（Windows Terminal）'
            : `原生子进程${run.terminalFallback ? `（回退：${run.terminalFallback}）` : ''}`
      L.push(`- 终端路线：${mode}`)
    }
    L.push(`- 工作目录：${run.cwd || '-'}`)
    L.push(`- 用时：${fmtMs(ms)}｜摘要：通过 ${summary.pass} / 警告 ${summary.warn} / 失败 ${summary.fail} / 跳过 ${summary.skipped}`)
    L.push(`- 回执：${receipt}`)
    L.push('', '## 步骤')
    if (!steps.length) L.push('- （无步骤）')
    for (const st of steps) {
      const mark = STEP_MARK[st.status] || '?'
      const bits = [mark, `${st.i ?? '?'}. ${st.name}`, `exit=${st.exitCode ?? '-'}`, fmtMs(st.ms)]
      if (st.timedOut) bits.push('超时')
      if (st.error) bits.push(st.error)
      L.push(`- ${bits.join('｜')}`)
      L.push(`  命令：${trimText(st.cmd, 300)}`)
    }
    const bad = steps.filter((s) => s.status === 'failed' || s.status === 'warn' || s.status === 'stopped')
    if (bad.length) {
      L.push('', '## 输出摘录（失败 / 警告 / 叫停步骤，末尾若干行）')
      for (const st of bad) {
        L.push(`### ${st.i ?? '?'}. ${st.name}（${statusCn(st.status)}）`)
        const lines = String(st.tail || '').trim()
        L.push('```text')
        L.push(...(lines ? lines.split(/\r?\n/).slice(-12) : ['（无输出）']))
        L.push('```')
      }
    }
    L.push('', '下一步：arch_log { id, step } 看某步完整尾部日志；arch_status 不带 id 看历史；长任务用 background:true。')
    return L.join('\n')
  }

  function renderList(runs) {
    if (!runs.length) return '# 架构运行记录（0 条）\n\n还没有运行。用 arch_run { steps: [{ cmd: "..." }] } 起一条。'
    const L = [`# 架构运行记录（${runs.length} 条，新→旧）`]
    for (const r of runs) {
      const summary = r.summary || { pass: 0, warn: 0, fail: 0, skipped: 0 }
      const ms = r.ms ?? (r.startedAt ? Date.now() - Date.parse(r.startedAt) : null)
      L.push(
        `- ${r.id}｜${statusCn(r.status)}｜${(r.steps || []).length} 步（✓${summary.pass} △${summary.warn} ✗${summary.fail} ·${summary.skipped}）｜${fmtMs(ms)}｜${r.title || '(未命名)'}`,
      )
      L.push(`  回执：${join(runsDir, r.id, 'receipt.json')}`)
    }
    L.push('', '用 arch_status { id } 看单条详情；arch_log { id, step } 看某步日志。')
    return L.join('\n')
  }

  const api = {
    version: VERSION,
    enabled: () => enabled,
    home,
    runsDir,
    shell: () => defaultShell.kind,
    run: (opts) => start(opts),
    wait: (run) => run.done,
    status: (id) => status(id),
    stop: (id) => stop(id),
    stopAll: () => stopAll(),
    list: (n) => listRuns(n),
    log: (id, step, tailLines) => logOf(id, step, tailLines),
    render: (run) => renderRun(run),
    receiptFile: (id) => join(runsDir, id, 'receipt.json'),
  }

  return {
    enabled,
    home,
    runsDir,
    defaultShell: defaultShell.kind,
    start,
    status,
    stop,
    stopAll,
    listRuns,
    logOf,
    renderRun,
    renderList,
    api,
  }
}

/* ───────── 工具（对模型暴露的入口） ───────── */

function buildRunTool(engine) {
  return {
    name: 'arch_run',
    description:
      '架构运行器（终端执行架构）：把任务落成「规划 → 执行（系统终端）→ 校验 → 回执」四层流水线。' +
      'steps 里每条命令都在系统终端（Windows 默认 PowerShell，可切 cmd/pwsh/bash；其它平台 sh）里以子进程执行，' +
      '每步有独立工作目录、超时（超时杀整棵进程树）、退出码/输出正则判定与失败策略；运行结束落盘 receipt.json 与逐步日志，' +
      '回执可复查、可对比。判定条件写进计划（expect），不是执行者自报成功——这是本插件与「随手 exec」的区别。\n' +
      '用法：短任务直接给 steps（默认等它跑完再回执）；长任务用 background:true 拿运行 id，之后 arch_status 查、arch_log 看日志、arch_stop 叫停。\n' +
      '边界：只执行调用方给的命令，不做命令白名单；不支持交互式/TUI 命令（需要 stdin 或全屏的跑不了）。',
    parameters: {
      type: 'object',
      properties: {
        title: { type: 'string', description: '任务标题（进回执与列表，便于事后辨认）。' },
        steps: {
          type: 'array',
          description: '执行计划（按顺序执行）。元素可以是命令字符串，或 { name, cmd, cwd, timeoutMs, expect, allowFail }。',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', description: '步骤名（默认「步骤 N」）。' },
              cmd: { type: 'string', description: '在该步工作目录下、经系统终端执行的命令。' },
              cwd: { type: 'string', description: '该步工作目录（默认取 cwd 参数）。' },
              timeoutMs: { type: 'integer', description: '该步超时毫秒（0=不限；默认取 timeoutMs 参数）。超时会杀整棵进程树并判失败。' },
              expect: {
                type: 'object',
                description: '校验条件：{ exitCode: 0, match: "正则", notMatch: "正则" }；也可以直接传数字表示期望退出码。',
              },
              allowFail: { type: 'boolean', description: 'true=该步失败只记警告并继续（整体状态记为「完成（有警告）」）。' },
            },
          },
        },
        command: { type: 'string', description: '单条命令快捷方式（与 steps 二选一）。' },
        cwd: { type: 'string', description: '工作目录（默认=插件配置 cwd 或 DSH 进程 cwd）。' },
        shell: {
          type: 'string',
          enum: ['auto', 'powershell', 'pwsh', 'cmd', 'bash', 'sh'],
          description: '终端类型：auto（Windows=powershell，其它=sh）/ powershell / pwsh / cmd / bash / sh。',
        },
        stopOnFail: {
          type: 'boolean',
          description: 'true（默认）=某步失败即跳过后续步骤；false=继续跑完但整体仍记失败。',
        },
        timeoutMs: { type: 'integer', description: '单步默认超时毫秒（默认 120000）。' },
        console: {
          type: 'boolean',
          description:
            'true=每一步在自己的可见系统终端窗口里跑（Windows Terminal，一个任务一个窗口）；窗口只负责看得见，退出码/超时/日志/判定与默认隐藏模式完全一致。默认 false。需要 wt.exe。',
        },
        terminal: {
          type: 'string',
          enum: ['auto', 'pty', 'process'],
          description:
            '终端执行路线：auto（默认）=宿主提供 ctx.terminals 时说走 pty（dsh-terminal-bash 持久终端会话，每步一个独立会话/独立 PID/独立日志），否则原生子进程；pty=强制终端会话（不可用即记 fallback 走 process）；process=强制原生子进程（与 v0.5.x 行为一致）。',
        },
        keepOpenMs: { type: 'integer', description: 'console=true 时窗口跑完后保留多久毫秒（默认 1500，0=跑完立即关）。' },
        background: { type: 'boolean', description: 'true=立即返回运行 id，不等待完成（长任务用）。' },
      },
    },
    output: textOut(),
    async execute(args, exec) {
      const a = args ?? {}
      if (!engine.enabled) return '架构插件已关闭（config.enabled=false 或 DSH_ARCH_ENABLED=0）：拒绝执行。'
      let run
      try {
        run = engine.start({
          title: a.title,
          steps: a.steps,
          command: a.command,
          cwd: a.cwd,
          shell: a.shell,
          stopOnFail: a.stopOnFail,
          timeoutMs: a.timeoutMs,
          console: a.console,
          terminal: a.terminal,
          /* v0.6.0：owner 是调用方 Agent 对象——ctx.terminals.spawn 的必需第一个参数。 */
          owner: exec?.agent ?? null,
          keepOpenMs: a.keepOpenMs,
        })
      } catch (e) {
        return `架构运行未能开始：${e?.message ?? e}`
      }

      if (a.background === true) {
        return (
          `架构运行已在后台开始：${run.id}\n` +
          `标题：${run.title}｜${run.steps.length} 步｜终端：${run.shellKind}｜工作目录：${run.cwd}\n` +
          `用 arch_status { "id": "${run.id}" } 查进度；arch_log { "id": "${run.id}", "step": 1 } 看日志；arch_stop { "id": "${run.id}" } 叫停。`
        )
      }

      let onAbort = null
      try {
        if (exec && exec.signal && typeof exec.signal.addEventListener === 'function') {
          onAbort = () => {
            try {
              engine.stop(run.id)
            } catch {
              /* 忽略 */
            }
          }
          if (exec.signal.aborted) onAbort()
          else exec.signal.addEventListener('abort', onAbort, { once: true })
        }
      } catch {
        /* 忽略 */
      }

      try {
        await run.done
      } finally {
        try {
          if (onAbort && exec?.signal?.removeEventListener) exec.signal.removeEventListener('abort', onAbort)
        } catch {
          /* 忽略 */
        }
      }
      return engine.renderRun(run)
    },
  }
}

function buildStatusTool(engine) {
  return {
    name: 'arch_status',
    description:
      '查看架构运行：不带 id 列出最近运行（id/状态/步数/用时/回执路径）；带 id 给出该次运行的回执详情（逐步状态、退出码、失败步骤输出摘录）。',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: '运行 id（arch_run 返回，形如 arch-xxxx-yyyy）。留空=列出最近运行。' },
        limit: { type: 'integer', description: '列表条数上限（默认 20）。' },
      },
    },
    output: textOut(),
    async execute(args) {
      const a = args ?? {}
      if (a.id) {
        const r = engine.status(a.id)
        return r.ok ? engine.renderRun(r.run) : r.error
      }
      return engine.renderList(engine.listRuns(a.limit ?? 20))
    },
  }
}

function buildLogTool(engine) {
  return {
    name: 'arch_log',
    description:
      '读某一步的终端日志尾部（默认最后 80 行）。日志文件在运行时已落盘，读尾部不会把整份大日志塞进上下文——要更多行就调 tailLines。',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: '运行 id。' },
        step: { type: 'string', description: '步骤序号（1 起）或步骤名片段；留空=最后一步。' },
        tailLines: { type: 'integer', description: '取末尾多少行（默认 80，最大 2000）。' },
      },
      required: ['id'],
    },
    output: textOut(),
    async execute(args) {
      const a = args ?? {}
      const r = engine.logOf(a.id, a.step, a.tailLines)
      if (!r.ok) return r.error
      const lines = [
        `# ${r.id} · 步骤 ${r.step} ${r.name}（${statusCn(r.status)}）`,
        `# 日志文件：${r.file}`,
        `# 末尾 ${r.tailLines} 行：`,
        '```text',
        r.text,
        '```',
      ]
      return lines.join('\n')
    },
  }
}

function buildStopTool(engine) {
  return {
    name: 'arch_stop',
    description:
      '叫停架构运行：杀当前步骤的整棵终端进程树，运行状态记为「已叫停」，已产出的步骤日志与回执保留。必须给 id，或显式 all:true（防误触把全部运行一锅端）。',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: '要叫停的运行 id。' },
        all: { type: 'boolean', description: 'true=叫停全部进行中的运行（与 id 二选一，须显式传）。' },
      },
    },
    output: textOut(),
    async execute(args) {
      const a = args ?? {}
      if (!a.id && a.all !== true) {
        const running = [...engine.listRuns(200)].filter((r) => r.status === 'running').map((r) => r.id)
        return running.length
          ? `驳回：arch_stop 需指明 id，或显式 all:true 才停全部。当前在跑：${running.join(', ')}`
          : '驳回：没有正在跑的架构运行（未指定 id）。'
      }
      if (a.all === true) {
        const ids = engine.stopAll()
        return ids.length ? `已叫停 ${ids.length} 条运行：${ids.join(', ')}` : '没有正在跑的架构运行。'
      }
      const r = engine.stop(a.id)
      return r.ok ? `已叫停：${r.id}（回执与已产出日志保留；arch_status { "id": "${r.id}" } 可复盘）` : r.error
    },
  }
}

/* ───────── 插件入口 ───────── */

export function apply(ctx, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...(config && typeof config === 'object' ? config : {}) }
  const logger = ctx.logger ?? console
  const log = (m) => {
    try {
      const fn = logger.info || logger.log || (() => {})
      fn.call(logger, `[dsh-arch] ${m}`)
    } catch {
      /* 忽略 */
    }
  }

  const engine = createEngine(ctx, cfg, log)
  const flowTool = buildFlowTool(engine, { home: engine.home, log, ctx, skillRoots: cfg.skillRoots })
  const tools = [buildRunTool(engine), buildStatusTool(engine), buildLogTool(engine), buildStopTool(engine), flowTool]

  for (const tool of tools) {
    const register = () => ctx.tools.register(tool)
    try {
      if (typeof ctx.effect === 'function') ctx.effect(register, `dsh-arch: ${tool.name}`)
      else register()
    } catch (e) {
      log(`工具注册失败 ${tool.name}：${e?.message ?? e}`)
    }
  }

  try {
    if (typeof ctx.provide === 'function') ctx.provide('arch', engine.api)
    else if (typeof ctx.set === 'function') ctx.set('arch', engine.api)
  } catch (e) {
    log(`服务注册失败（不影响工具）：${e?.message ?? e}`)
  }

  /* 装载留痕：装进 profile 后，从磁盘就能确认「apply 真跑过」。
     DSH 插件热重载/装载失败时往往只在日志里留一句、工具却不见，这份文件就是装机验收判据。 */
  try {
    mkdirSync(engine.home, { recursive: true })
    appendFileSync(
      join(engine.home, 'dsh-arch-apply.log'),
      `${iso()} [apply] v${VERSION} pid=${process.pid} home=${engine.home} shell=${engine.defaultShell} tools=${tools.map((t) => t.name).join(',')}\n`,
      'utf8',
    )
  } catch {
    /* 落不了盘不影响插件功能 */
  }

  log(`v${VERSION} 已装载：home=${engine.home}｜shell=${engine.defaultShell}｜工具=${tools.map((t) => t.name).join(' / ')}`)
}

export const __internals = {
  DEFAULT_CONFIG,
  normalizeExpect,
  resolveShell,
  slug,
  newRunId,
}
