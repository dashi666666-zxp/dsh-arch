#!/usr/bin/env node
/* 把 dsh-arch 装进 / 从 desktop profile 卸载。
 *
 * 为什么不用 pnpm/`dsh plugin add`：本机 desktop profile 归桌面应用独占管理，
 * CLI 会拒绝，且 pnpm 在本机不可用（store 漂移 + 缺 git）。本机已验证的装法是
 * 「profile package.json 里加 link 依赖 + bundles 追加 + node_modules 建 junction」，
 * 配置热加载会自动建 loader entry。
 *
 * 沙箱注意：profile 在会话工作区之外，本脚本必须在 danger-full-access 下运行，
 * 否则写 package.json / 建 junction 会被拒。
 *
 * 用法（在插件目录里）：
 *   node scripts\install-desktop.mjs            # 安装
 *   node scripts\install-desktop.mjs --uninstall # 卸载
 *   node scripts\install-desktop.mjs --dry       # 只打印将要做什么
 */
import { existsSync, readFileSync, writeFileSync, lstatSync, rmSync, symlinkSync, readlinkSync, copyFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const PKG = 'dsh-arch'
const here = dirname(fileURLToPath(import.meta.url))
const pluginDir = resolve(here, '..')
const mode = process.argv.includes('--uninstall') ? 'uninstall' : 'install'
const dry = process.argv.includes('--dry')
const profileDir = resolve(process.env.DSH_PROFILE_DIR || join(homedir(), '.dsh', 'profiles', 'desktop'))
const pkgPath = join(profileDir, 'package.json')
const linkPath = join(profileDir, 'node_modules', PKG)

const log = (m) => console.log(m)
const fail = (m) => {
  console.error(`[dsh-arch] ${m}`)
  process.exitCode = 1
}

if (!existsSync(pkgPath)) {
  fail(`找不到 profile package.json：${pkgPath}`)
  process.exit(1)
}

const before = readFileSync(pkgPath, 'utf8')
let cfg
try {
  cfg = JSON.parse(before)
} catch (e) {
  fail(`profile package.json 不是合法 JSON：${e.message}`)
  process.exit(1)
}
if (!cfg.dsh || !cfg.dsh.profile || !Array.isArray(cfg.dsh.profile.bundles)) {
  fail('profile package.json 缺 dsh.profile.bundles 数组')
  process.exit(1)
}
cfg.dependencies = cfg.dependencies && typeof cfg.dependencies === 'object' ? cfg.dependencies : {}

const want = `link:${pluginDir}`
const plan = []
if (mode === 'install') {
  plan.push(`dependencies["${PKG}"] = ${JSON.stringify(want)}`)
  cfg.dependencies[PKG] = want
  if (!cfg.dsh.profile.bundles.includes(PKG)) {
    plan.push(`dsh.profile.bundles += "${PKG}"`)
    cfg.dsh.profile.bundles.push(PKG)
  } else {
    plan.push(`dsh.profile.bundles 已含 "${PKG}"（不动）`)
  }
  plan.push(`junction ${linkPath} -> ${pluginDir}`)
} else {
  plan.push(`删除 dependencies["${PKG}"]`)
  delete cfg.dependencies[PKG]
  const i = cfg.dsh.profile.bundles.indexOf(PKG)
  if (i >= 0) {
    plan.push(`dsh.profile.bundles -= "${PKG}"`)
    cfg.dsh.profile.bundles.splice(i, 1)
  } else {
    plan.push(`dsh.profile.bundles 不含 "${PKG}"（不动）`)
  }
  plan.push(`删除 junction ${linkPath}`)
}

log(`[dsh-arch] profile: ${profileDir}`)
log(`[dsh-arch] plugin : ${pluginDir}`)
log(`[dsh-arch] 计划：`)
for (const p of plan) log(`  - ${p}`)
if (dry) {
  log('[dsh-arch] --dry：未写盘')
  process.exit(process.exitCode ?? 0)
}

// 1) package.json：先备份，再写（UTF-8 无 BOM），写完回读校验
const backup = `${pkgPath}.bak-dsh-arch-${new Date().toISOString().replace(/[:.]/g, '-')}`
copyFileSync(pkgPath, backup)
log(`[dsh-arch] 已备份 package.json -> ${backup}`)
const next = JSON.stringify(cfg, null, 2) + '\n'
writeFileSync(pkgPath, next, 'utf8')
const readback = JSON.parse(readFileSync(pkgPath, 'utf8'))
const okPkg =
  mode === 'install'
    ? readback.dependencies?.[PKG] === want && readback.dsh.profile.bundles.includes(PKG)
    : !readback.dependencies?.[PKG] && !readback.dsh.profile.bundles.includes(PKG)
if (!okPkg) fail('package.json 回读校验失败')
else log('[dsh-arch] package.json 回读校验 OK')

// 2) node_modules junction
function linkState() {
  try {
    const st = lstatSync(linkPath)
    if (st.isSymbolicLink()) return { kind: 'link', target: readlinkSync(linkPath) }
    return { kind: st.isDirectory() ? 'dir' : 'other', target: null }
  } catch (e) {
    if (e.code === 'ENOENT') return { kind: 'none', target: null }
    throw e
  }
}
try {
  const st = linkState()
  if (mode === 'install') {
    if (st.kind === 'link' && resolve(st.target) === pluginDir) {
      log('[dsh-arch] junction 已存在且指向本插件（不动）')
    } else {
      if (st.kind !== 'none') {
        rmSync(linkPath, { recursive: true, force: true })
        log(`[dsh-arch] 清掉旧 ${st.kind}：${linkPath}`)
      }
      symlinkSync(pluginDir, linkPath, 'junction')
      log(`[dsh-arch] 已建 junction：${linkPath} -> ${pluginDir}`)
    }
  } else if (st.kind !== 'none') {
    rmSync(linkPath, { recursive: true, force: true })
    log(`[dsh-arch] 已删 junction：${linkPath}`)
  }
  const after = linkState()
  if (mode === 'install' && !(after.kind === 'link' && resolve(after.target) === pluginDir)) {
    fail('junction 回读校验失败')
  }
  if (mode === 'uninstall' && after.kind !== 'none') fail('junction 未删净')
} catch (e) {
  fail(`junction 操作失败：${e.message}`)
}

log(`[dsh-arch] ${mode === 'install' ? '安装' : '卸载'}完成${process.exitCode ? '（有失败项，见上）' : ''}`)
