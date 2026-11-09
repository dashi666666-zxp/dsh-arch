/**
 * dsh-arch host-smoke：不启动 DSH，用 mock ctx 直接调 apply()，真跑系统终端命令。
 *
 * 覆盖：导出形态 / 工具注册 / 服务注册 / 单步成功与回执落盘 / 多步失败与跳过 /
 *       allowFail / stopOnFail:false / expect（退出码与输出正则）/ 超时杀进程树 /
 *       background 轮询 / arch_log 尾读 / arch_stop 叫停 / 非法 id 守卫 / 关闭态 / 列表。
 *
 * 跑法：node tests/host-smoke.mjs
 */

import { existsSync, readFileSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const HOME = join(HERE, '.tmp-arch-smoke')
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
function section(title) {
  console.log(`\n== ${title} ==`)
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}
async function waitFor(fn, timeoutMs = 20000) {
  const t0 = Date.now()
  while (Date.now() - t0 < timeoutMs) {
    const v = await fn()
    if (v) return v
    await sleep(100)
  }
  return null
}

/* 平台无关的终端命令 */
const echo = (t) => (isWin ? `Write-Output '${t}'` : `printf '%s\\n' '${t}'`)
const failCode = (n) => `exit ${n}`
const sleepCmd = (sec) => (isWin ? `Start-Sleep -Seconds ${sec}` : `sleep ${sec}`)

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

async function main() {
  rmSync(HOME, { recursive: true, force: true })

  section('模块形态')
  const mod = await import(pathToFileURL(join(ROOT, 'lib', 'index.js')).href)
  check('导出 name = dsh-arch', mod.name === 'dsh-arch')
  check('inject 含 tools', Array.isArray(mod.inject) && mod.inject.includes('tools'))
  check('有 apply / VERSION', typeof mod.apply === 'function' && typeof mod.VERSION === 'string')

  section('装载：工具与服务')
  const { ctx, tools, services } = makeCtx()
  mod.apply(ctx, { home: HOME, shell: isWin ? 'powershell' : 'sh', timeoutMs: 60000 })
  const tool = (n) => {
    const t = tools.get(n)
    if (!t) throw new Error(`工具 ${n} 未注册`)
    return t
  }
  for (const n of ['arch_run', 'arch_status', 'arch_log', 'arch_stop']) check(`注册工具 ${n}`, tools.has(n))
  const arch = services.get('arch')
  check('注册服务 ctx.arch（含 run/status/stop/list）', !!arch && typeof arch.run === 'function' && typeof arch.status === 'function')
  const schemaOk = ['arch_run', 'arch_status', 'arch_log', 'arch_stop'].every((n) => {
    const o = tool(n).output
    return o && o.schema && typeof o.render === 'function' && Array.isArray(o.render(null, 'x')) && o.render(null, 'x')[0].type === 'text'
  })
  check('四个工具 output 渲染契约一致', schemaOk)

  section('单步成功 + 回执落盘 + 日志')
  const out1 = await tool('arch_run').execute({ title: 'smoke-echo', steps: [{ name: 'hello', cmd: echo('hello-arch') }] }, {})
  check('回执含 id', /- id：(arch-[0-9a-z]+-[0-9a-z]+)/.test(out1), out1.slice(0, 200))
  check('回执状态=完成', /- 状态：完成/.test(out1))
  const id1 = (out1.match(/- id：(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  const receipt1 = JSON.parse(readFileSync(join(HOME, 'runs', id1, 'receipt.json'), 'utf8'))
  check('receipt.json 状态 done', receipt1.status === 'done')
  check('receipt.json 步骤 exitCode=0', receipt1.steps[0].exitCode === 0 && receipt1.steps[0].status === 'done')
  check('receipt.json 有 logFile', typeof receipt1.steps[0].logFile === 'string' && receipt1.steps[0].logFile.includes(id1))
  const log1 = readFileSync(join(HOME, 'runs', receipt1.steps[0].logFile), 'utf8')
  check('日志文件含命令与输出', log1.includes('hello-arch') && log1.includes('Write-Output') || log1.includes("printf"))
  check('summary 计数正确', receipt1.summary.pass === 1 && receipt1.summary.fail === 0)

  section('arch_log 读尾')
  const outLog1 = await tool('arch_log').execute({ id: id1, step: 1 }, {})
  check('arch_log 含输出文本', outLog1.includes('hello-arch'), outLog1.slice(0, 200))
  check('arch_log 头部含步骤信息', outLog1.includes('步骤 1') && outLog1.includes(id1))

  section('多步失败：跳过后续 + 失败摘录')
  const out2 = await tool('arch_run').execute(
    {
      title: 'smoke-fail',
      steps: [
        { name: 'ok1', cmd: echo('first') },
        { name: 'boom', cmd: failCode(3) },
        { name: 'never', cmd: echo('should-not-run') },
      ],
    },
    {},
  )
  const id2 = (out2.match(/- id：(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  const st2 = arch.status(id2)
  check('整体状态 failed', st2.ok && st2.run.status === 'failed')
  check('第 3 步被跳过', st2.run.steps[2].status === 'skipped')
  check('失败步 exitCode=3', st2.run.steps[1].exitCode === 3)
  check('回执展示失败状态', /- 状态：失败/.test(out2))

  section('allowFail：失败记警告继续')
  const out3 = await tool('arch_run').execute(
    {
      title: 'smoke-warn',
      steps: [
        { name: 'fails-ok', cmd: failCode(2), allowFail: true },
        { name: 'after', cmd: echo('after-warn') },
      ],
    },
    {},
  )
  const id3 = (out3.match(/- id：(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  const st3 = arch.status(id3)
  check('整体状态 warn', st3.ok && st3.run.status === 'warn')
  check('第 2 步仍执行', st3.run.steps[1].status === 'done')
  check('summary.warn = 1', st3.run.summary.warn === 1)

  section('stopOnFail:false：失败不阻断')
  const out4 = await tool('arch_run').execute(
    {
      title: 'smoke-continue',
      stopOnFail: false,
      steps: [
        { name: 'fail', cmd: failCode(1) },
        { name: 'after', cmd: echo('continued') },
      ],
    },
    {},
  )
  const id4 = (out4.match(/- id：(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  const st4 = arch.status(id4)
  check('整体仍 failed', st4.run.status === 'failed')
  check('第 2 步已执行（未被跳过）', st4.run.steps[1].status === 'done')

  section('expect：退出码 / 输出正则')
  const out5 = await tool('arch_run').execute(
    {
      title: 'smoke-expect',
      steps: [
        { name: 'code-ok', cmd: failCode(3), expect: 3 },
        { name: 'match-ok', cmd: echo('needle-42'), expect: { match: 'needle-\\d+' } },
      ],
    },
    {},
  )
  const id5 = (out5.match(/- id：(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  check('expect 退出码 3 通过', arch.status(id5).run.status === 'done')

  const out6 = await tool('arch_run').execute(
    {
      title: 'smoke-expect-bad',
      steps: [{ name: 'match-bad', cmd: echo('actual'), expect: { match: 'expected-xyz' } }],
    },
    {},
  )
  const id6 = (out6.match(/- id：(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  const st6 = arch.status(id6)
  check('输出不匹配判失败', st6.run.status === 'failed')
  check('失败原因含「输出不匹配」', String(st6.run.steps[0].error || '').includes('输出不匹配'), String(st6.run.steps[0].error))

  section('超时：杀进程树且快速返回')
  const t0 = Date.now()
  const out7 = await tool('arch_run').execute(
    { title: 'smoke-timeout', steps: [{ name: 'slow', cmd: sleepCmd(5), timeoutMs: 500 }] },
    {},
  )
  const elapsed = Date.now() - t0
  const id7 = (out7.match(/- id：(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  const st7 = arch.status(id7)
  check('超时判失败', st7.run.status === 'failed' && st7.run.steps[0].timedOut === true)
  check('超时不等到 5s（实测 ' + elapsed + 'ms）', elapsed < 4000)

  section('background：立即返回 + 轮询')
  const bgStart = Date.now()
  const out8 = await tool('arch_run').execute(
    { title: 'smoke-bg', background: true, steps: [{ name: 'sleepy', cmd: sleepCmd(1) }] },
    {},
  )
  const bgReturnMs = Date.now() - bgStart
  const id8 = (out8.match(/(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  check('background 立即返回（实测 ' + bgReturnMs + 'ms）', bgReturnMs < 3000 && /后台开始/.test(out8))
  const done8 = await waitFor(() => {
    const st = arch.status(id8)
    return st.ok && st.run.status !== 'running' ? st.run : null
  })
  check('轮询到运行结束且状态 done', !!done8 && done8.status === 'done', done8 ? done8.status : 'timeout')

  section('arch_stop：叫停正在跑的终端')
  const out9 = await tool('arch_run').execute(
    { title: 'smoke-stop', background: true, steps: [{ name: 'long', cmd: sleepCmd(30) }] },
    {},
  )
  const id9 = (out9.match(/(arch-[0-9a-z]+-[0-9a-z]+)/) || [])[1]
  await sleep(400)
  const stopOut = await tool('arch_stop').execute({ id: id9 }, {})
  check('arch_stop 回执', /已叫停/.test(stopOut), stopOut)
  const stopped9 = await waitFor(() => {
    const st = arch.status(id9)
    return st.ok && st.run.status !== 'running' ? st.run : null
  }, 8000)
  check('叫停后状态 stopped', !!stopped9 && stopped9.status === 'stopped', stopped9 ? stopped9.status : 'timeout')
  check('叫停步骤带「已叫停」原因', !!stopped9 && String(stopped9.steps[0].error || '').includes('叫停'))

  section('arch_stop 安全性：无 id 无 all 驳回')
  const stopBad = await tool('arch_stop').execute({}, {})
  check('未指明 id 时驳回', /驳回/.test(stopBad), stopBad)

  section('命令校验与 id 守卫')
  const badPlan = await tool('arch_run').execute({ steps: [{ name: 'no-cmd' }] }, {})
  check('缺 cmd 拒绝', /缺少终端命令/.test(badPlan), badPlan)
  const badId = await tool('arch_status').execute({ id: '../etc' }, {})
  check('非法 id 拒绝（arch_status）', /不合法/.test(badId), badId)
  const badLog = await tool('arch_log').execute({ id: '../../x', step: 1 }, {})
  check('非法 id 拒绝（arch_log）', /不合法/.test(badLog), badLog)

  section('arch_status 列表')
  const listOut = await tool('arch_status').execute({ limit: 50 }, {})
  check('列表包含刚跑的运行', listOut.includes(id1) && listOut.includes(id2))
  check('列表含回执路径', listOut.includes('receipt.json'))

  section('关闭态')
  const ctx2pack = makeCtx()
  mod.apply(ctx2pack.ctx, { home: HOME, enabled: false })
  const offOut = await ctx2pack.tools.get('arch_run').execute({ command: echo('nope') }, {})
  check('启用 arch_run 返回关闭提示', /已关闭/.test(offOut), offOut)

  section('清理')
  arch.stopAll()
  await sleep(300)
  rmSync(HOME, { recursive: true, force: true })
  check('临时回执目录已清理', !existsSync(HOME))

  console.log(`\nARCH_SMOKE ${fail ? 'FAIL' : 'PASS'} | pass=${pass} fail=${fail}`)
  process.exit(fail ? 1 : 0)
}

main().catch((e) => {
  console.error('\nARCH_SMOKE CRASH:', e?.stack ?? e)
  process.exit(1)
})
