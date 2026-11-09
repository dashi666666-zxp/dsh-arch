/**
 * dsh-arch console-smoke：验证 v0.5.1「可见系统终端窗口」模式。
 *
 * 判两条独立事实：
 *   ① 功能等价——窗口模式下退出码/expect/日志/超时全部与隐藏模式一致（判定链没被窗口换掉）；
 *   ② 窗口真的出现——运行期间确实有 Windows Terminal 窗口，且标题带 dsh-arch。
 *
 * 跑法：node tests/console-smoke.mjs
 */

import { spawn } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const HOME = join(HERE, '.tmp-arch-console')
const isWin = process.platform === 'win32'
const WT = join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WindowsApps', 'wt.exe')

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
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

/* 用文件重定向抓 Windows Terminal 的窗口标题（DSH 沙箱禁止管道 stdio，故不用 execFileSync）。 */
async function windowTitles() {
  if (!isWin) return []
  const out = join(HERE, '.tmp-arch-console', 'win-titles.txt')
  try {
    rmSync(out, { force: true })
  } catch {
    /* 忽略 */
  }
  const ps =
    'Get-Process WindowsTerminal -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle } | ' +
    `ForEach-Object { $_.MainWindowTitle } | Out-File -FilePath "${out}" -Encoding utf8`
  await new Promise((done) => {
    const c = spawn('powershell', ['-NoProfile', '-Command', ps], { windowsHide: true, stdio: 'ignore' })
    c.on('close', done)
    c.on('error', done)
  })
  try {
    return readFileSync(out, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
  } catch {
    return []
  }
}

rmSync(HOME, { recursive: true, force: true })

const mod = await import(pathToFileURL(join(ROOT, 'lib', 'index.js')).href)
const tools = []
const services = {}
const ctx = {
  logger: { info() {} },
  tools: { register: (t) => tools.push(t) },
  provide: (id, v) => {
    services[id] = v
  },
  get: (id) => services[id],
}
mod.apply(ctx, { home: HOME, enabled: true })

console.log('\n== 装载 ==')
check('导出版本号形如 0.x.y', /^0\.\d+\.\d+$/.test(mod.VERSION), mod.VERSION)
check('arch_run 工具已注册', tools.some((t) => t.name === 'arch_run'))
const arch = services.arch
check('arch 服务已注册', !!arch && typeof arch.run === 'function')

console.log('\n== console 参数（工具 schema） ==')
const runTool = tools.find((t) => t.name === 'arch_run')
const props = runTool?.parameters?.properties ?? {}
check('arch_run 暴露 console 参数', !!props.console)
check('arch_run 暴露 keepOpenMs 参数', !!props.keepOpenMs)

console.log('\n== 窗口模式：功能等价 ==')
const run = arch.run({
  title: 'console smoke',
  console: true,
  keepOpenMs: 0,
  shell: 'cmd',
  timeoutMs: 30000,
  steps: [
    { name: 'ok', cmd: 'echo CONSOLE_A', expect: { exitCode: 0, match: 'CONSOLE_A' } },
    { name: 'code3', cmd: 'exit 3', expect: { exitCode: 3 } },
  ],
})

/* 运行期间探窗：窗口标题应带 dsh-arch */
let seenTitles = []
let sawWindow = false
const probe = (async () => {
  for (let i = 0; i < 10 && !run.doneSettled; i++) {
    await sleep(400)
    const titles = await windowTitles()
    for (const t of titles) {
      seenTitles.push(t)
      if (/dsh-arch/i.test(t)) sawWindow = true
    }
    if (sawWindow) break
  }
})()
await run.done
run.doneSettled = true
await probe

check('run.console === true', run.console === true)
check('运行状态 done', run.status === 'done', run.status)
const [s1, s2] = run.steps
check('第 1 步 退出码 0', s1.exitCode === 0, String(s1.exitCode))
check('第 1 步判定通过（expect.match 生效）', s1.ok === true && !s1.error, s1.error || '')
check('第 1 步日志含输出', String(s1.tail || '').includes('CONSOLE_A'), s1.tail || '')
check('第 2 步 退出码 3', s2.exitCode === 3, String(s2.exitCode))
check('第 2 步判定通过（expect.exitCode=3）', s2.ok === true && !s2.error, s2.error || '')

console.log('\n== 窗口产物 ==')
const files = existsSync(HOME) ? readdirSync(join(HOME, 'runs', run.id)) : []
check('落 console-run.mjs helper', files.includes('console-run.mjs'))
check('落 console-01.cfg.json', files.includes('console-01.cfg.json'))
check('落 console-01.code.json（退出码回传标记）', files.includes('console-01.code.json'))
let marker = null
try {
  marker = JSON.parse(readFileSync(join(HOME, 'runs', run.id, 'console-01.code.json'), 'utf8'))
} catch {
  /* 忽略 */
}
check('标记文件含真实 pid', Number.isFinite(marker?.pid) && marker.pid > 0, JSON.stringify(marker))
check('标记文件 exitCode=0', marker?.exitCode === 0, JSON.stringify(marker))
check('每步一个独立日志文件', files.filter((f) => f.endsWith('.log')).length === 2, files.join(','))

console.log('\n== 窗口真的出现过 ==')
check('探测到 Windows Terminal 窗口', existsSync(WT) ? sawWindow : true, sawWindow ? '含 dsh-arch 标题' : `titles=${JSON.stringify([...new Set(seenTitles)].slice(0, 6))}`)

console.log('\n== 窗口模式：超时仍按超时判 ==')
const tRun = arch.run({
  title: 'console timeout',
  console: true,
  keepOpenMs: 0,
  shell: 'cmd',
  steps: [{ name: 'sleepy', cmd: 'ping -n 20 127.0.0.1 >nul', timeoutMs: 1200, allowFail: true, expect: { exitCode: 0 } }],
})
await tRun.done
const ts = tRun.steps[0]
check('超时标记 timedOut=true', ts.timedOut === true, JSON.stringify({ timedOut: ts.timedOut, err: ts.error }))
check('超时后判失败(warn)', ts.ok === false, `${ts.ok} / ${ts.error}`)

rmSync(HOME, { recursive: true, force: true })
console.log(`\n${fail === 0 ? 'CONSOLE_SMOKE PASS' : 'CONSOLE_SMOKE FAIL'}  pass=${pass} fail=${fail}`)
process.exit(fail === 0 ? 0 : 1)
