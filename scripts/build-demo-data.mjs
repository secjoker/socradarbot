// 生成 Cloudflare 只读预览用的脱敏演示数据。
// 输入：本地 data/vulns/*/meta.json（不随仓库发布）
// 输出：deploy/cloudflare/demo-data.json（仅公开漏洞元数据，不含 PoC/模板正文）
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const vulnDir = path.join(root, 'data', 'vulns')
const outFile = path.join(root, 'deploy', 'cloudflare', 'demo-data.json')

function safeText(s, max = 600) {
  let t = String(s || '')
    .replace(/\r/g, '')
    .replace(/https?:\/\/(127\.0\.0\.1|localhost)[^\s]*/gi, '')
    .replace(/\b(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(\.\d{1,3})?\b/g, '')
    .replace(/[A-Z]:\\[^\s"']+/g, '')
    .trim()
  if (t.length > max) t = t.slice(0, max) + '…'
  return t
}

function isZh(s) {
  return /[\u4e00-\u9fff]/.test(s || '')
}

const bySource = new Map()
const pocPool = []
const mediumPool = []
for (const id of fs.readdirSync(vulnDir)) {
  const p = path.join(vulnDir, id, 'meta.json')
  if (!fs.existsSync(p)) continue
  let m
  try { m = JSON.parse(fs.readFileSync(p, 'utf8')) } catch { continue }
  if (String(m.source || '').startsWith('nuclei')) continue
  if (!m.cves || !m.cves.length) continue
  if (!['critical', 'high', 'medium'].includes(m.severity)) continue
  if (!m.name || m.name.length < 8 || m.name.length > 110) continue
  if (!m.summary || m.summary.length < 30) continue
  const list = bySource.get(m.source) || []
  list.push(m)
  bySource.set(m.source, list)
  if (m.poc_disclosed || m.poc_source === 'article' || m.poc_source === 'ai') pocPool.push(m)
  if (!m.high_value && (m.score || 0) >= 35) mediumPool.push(m)
}

const picked = []
for (const [, list] of bySource) {
  list.sort((a, b) => (b.score || 0) - (a.score || 0))
  picked.push(...list.slice(0, 9))
}
picked.sort((a, b) => (b.score || 0) - (a.score || 0))
const selected = picked.slice(0, 60)
// 保证预览里能看到 PoC 标记：额外补几条第 PoC 样本
pocPool.sort((a, b) => (b.score || 0) - (a.score || 0))
for (const m of pocPool) {
  if (selected.length >= 58) break
  if (!selected.some((x) => x.id === m.id)) selected.push(m)
}
// 补充中低分样本，让「仅高价值」筛选在预览中可验证
mediumPool.sort((a, b) => (b.score || 0) - (a.score || 0))
for (const m of mediumPool) {
  if (selected.length >= 72) break
  if (!selected.some((x) => x.id === m.id)) selected.push(m)
}

const items = selected.map((m) => {
  const published = m.published || (m.created_at || '').slice(0, 10)
  const affected = (m.affected || []).map((x) => safeText(x, 80)).filter(Boolean).slice(0, 5)
  const refs = (m.refs || []).filter((u) => /^https?:\/\//.test(u)).slice(0, 6)
  const tags = (m.tags || []).map((x) => safeText(x, 30)).filter(Boolean)
  const poc = !!(m.poc_disclosed || m.poc_source === 'article' || m.poc_source === 'ai')
  return {
    id: m.id,
    name: safeText(m.name, 160),
    source: m.source,
    summary: safeText(m.summary, 600),
    principle: safeText(m.principle, 600),
    attack_scope: safeText(m.attack_scope, 400),
    published,
    created_at: m.created_at || '',
    cvss: m.cvss ?? null,
    severity: m.severity || 'unknown',
    cves: m.cves || [],
    cwe: m.cwe || [],
    tags,
    refs,
    affected_products: affected,
    epss: m.epss || 0,
    epss_percentile: m.epss_percentile || 0,
    kev: !!m.kev,
    kev_date: m.kev_date || '',
    poc,
    poc_disclosed: !!m.poc_disclosed,
    score: m.score || 0,
    high_value: !!m.high_value,
    score_reasons: (m.score_reasons || []).map((x) => safeText(x, 40)).slice(0, 8),
    translated: !!m.translated || isZh(m.name),
    pushed: false,
    has_nuclei: false,
    entry_date: (published || (m.created_at || '').slice(0, 10) || '').slice(0, 10),
    entry_iso: published || (m.created_at || '').slice(0, 10),
    // 预览不提供可执行内容（poc 字段在列表中是布尔标记，详情响应由 Worker 置空）
    poc_source: 'none',
    nuclei_yaml: '',
  }
})

const countBySource = {}
for (const it of items) countBySource[it.source] = (countBySource[it.source] || 0) + 1

const demo = {
  generated_at: new Date().toISOString(),
  items,
  stats: {
    total: items.length,
    high_value: items.filter((x) => x.high_value).length,
    unpushed_high_value: items.filter((x) => x.high_value).length,
    today: 0,
    translated: items.filter((x) => x.translated).length,
    pending_translate: items.filter((x) => !x.translated).length,
    kev: items.filter((x) => x.kev).length,
    poc: items.filter((x) => x.poc).length,
    by_source: countBySource,
    templates: 0,
    collect_running: false,
    sync_running: false,
    last_collect: '2026-10-28T16:00:00',
    push_enabled: false,
    push_channels: 0,
    llm_available: false,
    version: '1.2.0',
  },
  sources: {
    builtin: [
      ['seebug', 'Seebug Paper', 'rss', 'https://paper.seebug.org/rss/', '知道创宇 Seebug 漏洞文章 RSS'],
      ['先知', '先知社区', 'rss', 'https://xz.aliyun.com/feed', '阿里云先知社区技术文章 RSS'],
      ['exploit-db', 'Exploit-DB', 'rss', 'https://www.exploit-db.com/rss.xml', '公开 Exploit 数据库 RSS'],
      ['chaitin', '长亭漏洞库', 'json', 'https://stack.chaitin.com/vuldb/index', 'CT Stack 公开 API，含 CT 编号 / CVSS / CVE'],
      ['oscs', 'OSCS 开源安全情报', 'json', 'https://www.oscs1024.com/cm', '墨菲安全开源组件漏洞预警'],
      ['qianxin-ti', '奇安信威胁情报中心', 'json', 'https://ti.qianxin.com/', '一日重点漏洞与 PoC/EXP 新增'],
      ['cisa-kev', 'CISA KEV', 'json', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', '已知在野利用漏洞目录'],
      ['nvd', 'NVD', 'json', 'https://nvd.nist.gov/', 'CVE / CVSS / CPE 官方数据'],
      ['github-advisory', 'GitHub Advisory', 'json', 'https://github.com/advisories', 'GitHub 安全公告'],
    ].map(([id, name, kind, url, description], i) => ({
      id, name, kind, url, description, builtin: true, enabled: i < 6,
    })),
    custom: [],
  },
  settings: {
    llm: { base: 'https://api.openai.com', key: '', model: 'gpt-4o-mini', timeout: 60 },
    collect: { interval_minutes: 10, fetch_limit: 10, keep_days: 90, auto_translate: true, article_fetch: true, timeout_seconds: 25 },
    nuclei: { repo: 'projectdiscovery/nuclei-templates', ref: 'main', remote_limit: 20, fetch_remote: false, gen_templates: true, sync_enabled: true, sync_limit: 0 },
    enrich: { enabled: true, epss: true, kev: true, github_advisory: true, nvd: true, timeout_seconds: 20, cache_hours: 24, github_token: '' },
    sources: { custom: [], disabled: [] },
    push: { enabled: false, min_score: 60, min_severity: '', require_cve: false, require_poc: false, keywords_include: [], keywords_exclude: [], max_per_batch: 10, cooldown_minutes: 30, channels: [] },
    config_file: 'demo (read-only)',
    key_set: false,
  },
  push: {
    enabled: false, min_score: 60, min_severity: '', require_cve: false, require_poc: false,
    keywords_include: [], keywords_exclude: [], max_per_batch: 10, cooldown_minutes: 30,
    channels: [], pending: 0,
  },
  history: [],
  collect_status: { running: false, last_run: '2026-10-28T16:00:00', last_result: { fetched: 60, kept: 60, high_value: 42 }, interval_minutes: 10, next_run: '2026-10-28T16:10:00' },
  llm_status: { available: false, model: 'gpt-4o-mini', base: 'https://api.openai.com', key_set: false, pending_translate: items.filter((x) => !x.translated).length },
  nuclei_status: { cloned: false, last_commit: '', last_commit_short: '', last_sync: '', last_imported: 0, local_templates: 0, running: false, last_run: '', last_result: null, repo: 'projectdiscovery/nuclei-templates', ref: 'main' },
  templates: { dir: 'demo (read-only)', items: [] },
}

fs.mkdirSync(path.dirname(outFile), { recursive: true })
fs.writeFileSync(outFile, JSON.stringify(demo, null, 2))
console.log(`demo items: ${items.length}; sources: ${Object.keys(countBySource).join(', ')}`)
console.log(`written: ${outFile} (${(fs.statSync(outFile).size / 1024).toFixed(1)} KB)`)
