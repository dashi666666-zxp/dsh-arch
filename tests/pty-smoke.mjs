/**
 * dsh-arch pty-smoke：v0.6.0 的终端路线（宿主 ctx.terminals = dsh-terminal-bash 持久终端）单测。
 *
 * 不起 DSH、不依赖真 PTY：用一个假的 terminals 服务（spawn/startSend/read/list/kill 语义照真服务），
 * 它把「插件发到会话里的那一行 node <launcher> <cfg>」真跑起来（真子进程），于是能验证——
 *   1. 有力 terminals 服务时走 pty 路线（每步一个会话、会话 pid 记进回执）；
 *   2. 退出码经结束标记回传，expect.match/notMatch 照旧生效，日志落盘；
 *   3. 超时判 timedOut，并且会话被 kill；
 *   4. 没有 terminals 服务时回退原生子进程，并如实记 fallback 原因；
 *   5. receipt.json 带 terminalMode 字段。
 *
 * 跑法：node tests/pty-smoke.mjs
 */

import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const HOME = join(HERE, '.tmp-arch-pty')
const isWin = process.platform === 'win32'

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

const echo = (t) => (isWin ? `Write-Output '${t}'` : `printf '%s\\n' '${t}'`)
const failCode = (n) => `exit ${n}`
const sleepCmd = (sec) => (isWin ? `Start-Sleep -Seconds ${sec}` : `sleep ${sec}`)

/* 假 terminals 服务：语义照 ctx.terminals（spawn/startSend/read/list/kill）。
   注意：本机 DSH 沙箱禁命名管道，`spawn(...)` 用默认 stdio（pipe）会同步抛 EPERM ⇒ 拿不到任何输出。
   所以这里照插件 process 分支（index.js execStep）同一手法：子进程输出直接写文件句柄，read() 再读文件。 */
function makeFakeTerminals() {
  const sessions = new Map()
  const killed = []
  const outDir = join(HOME, 'pty-out')
  mkdirSync(outDir, { recursive: true })
  const outFileOf = (id) => join(outDir, `${id}.log`)
  const textOf = (id) => {
    try {
      return readFileSync(outFileOf(id), 'utf8')
    } catch {
      return ''
    }
  }
  let seq = 0
  return {
    killed,
    sessions,
    listBackends: () => ['shell'],
    async spawn(owner, req = {}) {
      if (!owner) throw new Error('fake terminals: owner required')
      const id = `sess-${++seq}`
      sessions.set(id, { id, cwd: req.cwd || process.cwd(), status: { kind: 'running' }, pid: 40000 + seq })
      return { sessionId: id, name: req.name || id, type: req.type || 'shell', pid: 40000 + seq, status: { kind: 'running' }, motd: '' }
    },
    startSend(owner, id, { text } = {}) {
      const s = sessions.get(id)
      if (!s) throw new Error(`fake terminals: no session ${id}`)
      const outFile = outFileOf(id)
      const m = /^node "([^"]+)" "([^"]+)"$/.exec(String(text || '').trim())
      const done = (async () => {
        if (!m) {
          appendFileSync(outFile, `\nunknown command: ${text}\n`)
          return { viewport: textOf(id), waitReason: 'stdin_read', sessionStatus: s.status, truncated: false }
        }
        await new Promise((done2) => {
          const fd = openSync(outFile, 'a')
          let child
          try {
            child = spawn(process.execPath, [m[1], m[2]], { cwd: s.cwd, windowsHide: true, stdio: ['ignore', fd, fd] })
          } finally {
            closeSync(fd)
          }
          child.on('error', (e) => {
            appendFileSync(outFile, `\nspawn error: ${e?.message ?? e}\n`)
            done2()
          })
          child.on('close', (code) => {
            s.status = { kind: 'exited', exitCode: code ?? null, signal: null }
            done2()
          })
        })
        return { viewport: textOf(id), waitReason: 'session_exit', sessionStatus: s.status, truncated: false }
      })()
      return { done, readOutput: () => textOf(id), cancel() {} }
    },
    read(owner, id, { count } = {}) {
      const s = sessions.get(id)
      if (!s) throw new Error(`fake terminals: no session ${id}`)
      const text = textOf(id)
      const lines = text.split('\n')
      const n = Math.max(1, Math.min(lines.length, Number(count) || 4000))
      return { text: lines.slice(-n).join('\n'), totalLines: lines.length, lineBegin: lines.length - n, lineEnd: lines.length, truncated: false }
    },
    list(owner) {
      return [...sessions.values()].map((s) => ({ sessionId: s.id, name: s.id, type: 'shell', pid: s.pid, status: s.status }))
    },
    async kill(owner, id) {
      killed.push(id)
      const s = sessions.get(id)
      if (s && s.status.kind === 'running') s.status = { kind: 'exited', exitCode: null, signal: 'SIGTERM' }
    },
  }
}

function makeCtx(terminals) {
  const tools = new Map()
  const services = new Map()
  if (terminals) services.set('terminals', terminals)
  return {
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
    get(n) {
      return services.get(n)
    },
    logger: { info() {}, log() {} },
    _tools: tools,
    _services: services,
  }
}

async function boot({ terminals, cfg = {} } = {}) {
  const ctx = makeCtx(terminals)
  const mod = await import(pathToFileURL(join(ROOT, 'lib', 'index.js')).href + `?v=${Date.now()}${Math.random()}`)
  mod.apply(ctx, { home: HOME, timeoutMs: 20000, ...cfg })
  const tool = ctx._tools.get('arch_run')
  if (!tool) throw new Error('arch_run 未注册')
  return { ctx, mod, tool, run: (args, exec = {}) => tool.execute(args, exec) }
}

async function main() {
  try {
    rmSync(HOME, { recursive: true, force: true })
  } catch {
    /* 忽略 */
  }
  const agent = { id: 'agent-pty-smoke', sessionId: 'session-pty-smoke' }

  section('1. pty 路线：每步一个终端会话，输出/退出码/expect 都可用')
  {
    const terminals = makeFakeTerminals()
    const { tool } = await boot({ terminals })
    const out = await tool.execute(
      {
        title: 'pty 主用例',
        steps: [
          { name: '回声', cmd: echo('HELLO_PTY'), expect: { exitCode: 0, match: 'HELLO_PTY' } },
          { name: '退出码 3', cmd: failCode(3), expect: { exitCode: 3 } },
        ],
        terminal: 'pty',
      },
      { agent },
    )
    const m = /id：(arch-[0-9a-z]+-[0-9a-z]+)/.exec(out)
    check('返回运行 id', !!m, out.slice(0, 200))
    const id = m ? m[1] : ''
    const receiptFile = join(HOME, 'runs', id, 'receipt.json')
    check('回执落盘', existsSync(receiptFile))
    const rec = JSON.parse(readFileSync(receiptFile, 'utf8'))
    check('整体状态 done', rec.status === 'done', rec.status)
    check('receipt.terminalMode = pty', rec.terminalMode === 'pty', String(rec.terminalMode))
    check('每步一个会话（两个不同 pid）', rec.steps.length === 2 && rec.steps[0].pid && rec.steps[1].pid && rec.steps[0].pid !== rec.steps[1].pid, JSON.stringify(rec.steps.map((s) => s.pid)))
    check('退出码经标记回传', rec.steps[1].exitCode === 3, String(rec.steps[1].exitCode))
    check('expect.match 生效（第 1 步 done）', rec.steps[0].status === 'done', rec.steps[0].status)
    const log0 = readFileSync(join(HOME, 'runs', id, rec.steps[0].logFile.split('/').pop()), 'utf8')
    check('步日志含命令输出且不含起止标记', log0.includes('HELLO_PTY') && !log0.includes('__DSH_ARCH_START_'), log0.split('\n').slice(-3).join('|'))
    check('会话跑完被关闭', terminals.killed.length === 2, String(terminals.killed.length))
    check('输出里带终端路线说明', out.includes('终端路线：PTY 会话'), out.split('\n').slice(0, 6).join('|'))
  }

  section('2. pty 路线：超时判 timedOut 并 kill 会话')
  {
    const terminals = makeFakeTerminals()
    const { tool } = await boot({ terminals })
    const out = await tool.execute(
      { title: 'pty 超时', steps: [{ name: '慢步', cmd: sleepCmd(10), timeoutMs: 600 }], terminal: 'pty', stopOnFail: false },
      { agent },
    )
    const id = (/id：(arch-[0-9a-z]+-[0-9a-z]+)/.exec(out) || [])[1] || ''
    const rec = JSON.parse(readFileSync(join(HOME, 'runs', id, 'receipt.json'), 'utf8'))
    check('step.timedOut = true', rec.steps[0].timedOut === true, String(rec.steps[0].timedOut))
    check('超时步骤 failed', rec.steps[0].status === 'failed', rec.steps[0].status)
    check('超时时会话被 kill', terminals.killed.length >= 1, String(terminals.killed.length))
  }

  section('3. 无 terminals 服务：回退原生子进程并记明原因')
  {
    const { tool } = await boot({ terminals: null })
    const out = await tool.execute({ title: '回退用例', steps: [{ name: '回声', cmd: echo('FALLBACK_OK'), expect: { match: 'FALLBACK_OK' } }] }, { agent })
    const id = (/id：(arch-[0-9a-z]+-[0-9a-z]+)/.exec(out) || [])[1] || ''
    const rec = JSON.parse(readFileSync(join(HOME, 'runs', id, 'receipt.json'), 'utf8'))
    check('receipt.terminalMode = process', rec.terminalMode === 'process', String(rec.terminalMode))
    check('fallback 原因写明 terminals 服务缺失', /terminals/.test(String(rec.terminalFallback || '')), String(rec.terminalFallback))
    check('回退后仍能跑通', rec.status === 'done', rec.status)
  }

  section('4. terminal:process 强制原生子进程（不走会话）')
  {
    const terminals = makeFakeTerminals()
    const { tool } = await boot({ terminals })
    const out = await tool.execute({ title: '强制 process', steps: [{ name: '回声', cmd: echo('FORCED_PROC'), expect: { match: 'FORCED_PROC' } }], terminal: 'process' }, { agent })
    const id = (/id：(arch-[0-9a-z]+-[0-9a-z]+)/.exec(out) || [])[1] || ''
    const rec = JSON.parse(readFileSync(join(HOME, 'runs', id, 'receipt.json'), 'utf8'))
    check('terminal=process ⇒ receipt.terminalMode = process', rec.terminalMode === 'process', String(rec.terminalMode))
    check('没有创建终端会话', terminals.sessions.size === 0, String(terminals.sessions.size))
  }

  try {
    rmSync(HOME, { recursive: true, force: true })
  } catch {
    /* 忽略 */
  }
  console.log(`\nPTY_SMOKE ${pass > 0 && fail === 0 ? 'PASS' : 'FAIL'} | pass=${pass} fail=${fail}`)
  process.exit(fail === 0 ? 0 : 1)
}

main().catch((e) => {
  console.error('PTY_SMOKE 崩溃：', e)
  process.exit(1)
})
