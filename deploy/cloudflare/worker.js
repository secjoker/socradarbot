// Cloudflare Worker：SocradarBot 在线预览
// 静态资源来自 web/dist；/api/* 由内置的脱敏演示数据提供只读响应。
import demo from './demo-data.json'

const READONLY = {
  detail: '在线预览为只读演示：写操作已禁用。完整功能请在本地部署后使用。',
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  })

const num = (v, def) => {
  const n = Number.parseInt(v, 10)
  return Number.isFinite(n) ? n : def
}

function listVulns(url) {
  const p = url.searchParams
  let rows = demo.items.slice()

  const source = p.get('source') || ''
  const q = (p.get('q') || '').trim().toLowerCase()
  const severity = (p.get('severity') || '').toLowerCase()
  const vendor = (p.get('vendor') || '').trim().toLowerCase()
  const kev = p.get('kev') === '1' || p.get('kev') === 'true'
  const poc = p.get('poc') === '1' || p.get('poc') === 'true'
  const highValue = p.get('high_value') === '1' || p.get('high_value') === 'true'
  const minScore = num(p.get('min_score'), 0)

  rows = rows.filter((v) => {
    if (source && v.source !== source) return false
    if (severity && v.severity !== severity) return false
    if (kev && !v.kev) return false
    if (poc && !v.poc) return false
    if (highValue && !v.high_value) return false
    if (minScore > 0 && v.score < minScore) return false
    if (q) {
      const blob = `${v.name} ${v.summary} ${(v.cves || []).join(' ')}`.toLowerCase()
      if (!blob.includes(q)) return false
    }
    if (vendor) {
      const blob = `${v.name} ${(v.affected_products || []).join(' ')}`.toLowerCase()
      if (!blob.includes(vendor)) return false
    }
    return true
  })

  const sort = (p.get('sort') || 'latest').toLowerCase()
  const byCvss = (v) => (typeof v.cvss === 'number' ? v.cvss : -1)
  if (sort === 'score') rows.sort((a, b) => b.score - a.score)
  else if (sort === 'cvss') rows.sort((a, b) => byCvss(b) - byCvss(a))
  else if (sort === 'published') rows.sort((a, b) => String(b.published).localeCompare(String(a.published)))
  else rows.sort((a, b) => String(b.entry_iso).localeCompare(String(a.entry_iso)))

  const total = rows.length
  const pageSize = Math.min(100, Math.max(1, num(p.get('page_size'), 10)))
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const page = Math.min(Math.max(1, num(p.get('page'), 1)), pages)
  const items = rows.slice((page - 1) * pageSize, page * pageSize).map((v) => ({
    id: v.id,
    name: v.name,
    source: v.source,
    summary: v.summary,
    published: v.published,
    cvss: v.cvss,
    severity: v.severity,
    cves: v.cves,
    translated: v.translated,
    has_nuclei: false,
    entry_date: v.entry_date,
    entry_iso: v.entry_iso,
    epss: v.epss,
    kev: v.kev,
    poc: v.poc,
    score: v.score,
    high_value: v.high_value,
    pushed: false,
    tags: v.tags,
    affected_products: v.affected_products,
  }))

  return {
    items,
    total,
    page,
    pages,
    page_size: pageSize,
    all_total: demo.items.length,
    counts: demo.stats.by_source,
    high_value_total: demo.stats.high_value,
  }
}

function api(request, url) {
  const path = url.pathname
  const method = request.method.toUpperCase()

  if (path === '/api/health') {
    return json({ ok: true, name: 'SocradarBot Preview', version: '1.2.0', time: new Date().toISOString() })
  }
  if (path === '/api/stats' && method === 'GET') return json(demo.stats)
  if (path === '/api/sources' && method === 'GET') return json(demo.sources)
  if (path === '/api/settings' && method === 'GET') return json(demo.settings)
  if (path === '/api/llm/status' && method === 'GET') return json(demo.llm_status)
  if (path === '/api/collect/status' && method === 'GET') return json(demo.collect_status)
  if (path === '/api/push' && method === 'GET') return json(demo.push)
  if (path === '/api/push/history' && method === 'GET') return json({ items: demo.history })
  if (path === '/api/nuclei/sync' && method === 'GET') return json(demo.nuclei_status)
  if (path === '/api/nuclei/templates' && method === 'GET') return json(demo.templates)
  if (path === '/api/vulns' && method === 'GET') return json(listVulns(url))

  const detail = path.match(/^\/api\/vulns\/([^/]+)$/)
  if (detail && method === 'GET') {
    const id = decodeURIComponent(detail[1])
    const v = demo.items.find((x) => x.id === id)
    return v
      ? json({ ...v, poc: '', nuclei_yaml: '' })
      : json({ detail: '漏洞不存在（在线预览仅包含少量演示样本）' }, 404)
  }

  if (path.startsWith('/api/vulns/') && method === 'POST') return json(READONLY, 403)
  if (path.startsWith('/api/') && method === 'POST') return json(READONLY, 403)

  return json({ detail: '接口不存在' }, 404)
}

const BANNER = `
<div style="background:#fffaeb;border-bottom:1px solid #fedf89;color:#8a5a00;font:12px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;padding:7px 16px;text-align:center">
  在线预览 · 只读演示 ｜ 数据为脱敏样本，抓取/保存/推送等写操作已禁用 ｜
  <a href="https://github.com/secjoker/socradarbot" style="color:#b54708" target="_blank" rel="noreferrer">GitHub 仓库</a>
</div>`

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    if (url.pathname.startsWith('/api/')) {
      try {
        return api(request, url)
      } catch (e) {
        return json({ detail: `预览接口异常：${e.message}` }, 500)
      }
    }

    const res = await env.ASSETS.fetch(request)
    const type = res.headers.get('content-type') || ''
    if (!type.includes('text/html')) return res

    let html = await res.text()
    html = html.replace('<div id="app"></div>', `${BANNER}<div id="app"></div>`)
    const headers = new Headers(res.headers)
    headers.delete('content-length')
    headers.set('x-content-type-options', 'nosniff')
    headers.set('referrer-policy', 'strict-origin-when-cross-origin')
    return new Response(html, { status: res.status, headers })
  },
}
