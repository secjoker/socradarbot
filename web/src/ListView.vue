<template>
  <div class="library">
    <section class="hero">
      <div class="hero-main">
        <p class="eyebrow">CVE INTELLIGENCE LIBRARY</p>
        <h1>漏洞情报库</h1>
        <p class="hero-sub">
          聚合 9 个情报源 · 自动补全 CVE / CVSS / EPSS / KEV · 高风险情报自动推送
          <span v-if="lastRunText"> · 上次抓取 {{ lastRunText }}</span>
        </p>
        <div class="hero-badges">
          <span class="chip chip-cve">收录 <b>{{ statsData?.total ?? allTotal }}</b></span>
          <span class="chip chip-kev">已在野利用 <b>{{ statsData?.kev ?? 0 }}</b></span>
          <span class="chip chip-poc">PoC 公开 <b>{{ statsData?.poc ?? 0 }}</b></span>
          <span class="chip chip-ok">高价值 <b>{{ statsData?.high_value ?? 0 }}</b></span>
        </div>
      </div>
      <div class="hero-actions">
        <button v-if="pagePending" class="btn btn-ghost" :disabled="!llmOk || translating" @click="translatePage"
                :title="llmOk ? '把本页英文情报译成中文' : '未配置 LLM，无法翻译'">
          {{ translating ? `翻译中 ${done}/${pagePending}` : `翻译本页 ${pagePending} 条` }}
        </button>
        <button class="btn btn-primary" :disabled="collecting" @click="collect">
          <span v-if="collecting" class="spinner"></span>
          {{ collecting ? '抓取中…' : '立即抓取' }}
        </button>
      </div>
    </section>

    <div v-if="toast" class="notice notice-ok page-notice">{{ toast }}</div>
    <div v-if="error" class="notice notice-err page-notice">{{ error }}</div>

    <section class="filters panel">
      <div class="filter-grid">
        <div class="field f-keyword">
          <label>关键词 / CVE 编号</label>
          <input v-model="keyword" placeholder="例如 CVE-2026-1234、Apache、反序列化" @keyup.enter="search" />
        </div>
        <div class="field">
          <label>来源</label>
          <select v-model="source" @change="search">
            <option value="">全部来源（{{ allTotal }}）</option>
            <option v-for="(c, name) in counts" :key="name" :value="name">{{ name }}（{{ c }}）</option>
          </select>
        </div>
        <div class="field">
          <label>风险等级</label>
          <select v-model="severity" @change="search">
            <option value="">全部等级</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
        </div>
        <div class="field">
          <label>厂商 / 产品</label>
          <input v-model="vendor" placeholder="例如 Apache、WordPress" @keyup.enter="search" />
        </div>
        <div class="field">
          <label>排序</label>
          <select v-model="sort" @change="search">
            <option value="latest">最新收录</option>
            <option value="score">风险评分</option>
            <option value="cvss">CVSS 分值</option>
            <option value="published">披露时间</option>
          </select>
        </div>
        <div class="filter-submit">
          <button class="btn btn-primary" @click="search">查询</button>
          <button class="btn" @click="reset">重置</button>
        </div>
      </div>

      <div class="quick-row">
        <label class="quick"><input v-model="kevOnly" type="checkbox" @change="search" /> KEV 限定</label>
        <label class="quick"><input v-model="pocOnly" type="checkbox" @change="search" /> 有 PoC</label>
        <label class="quick"><input v-model="highOnly" type="checkbox" @change="search" /> 仅高价值</label>
        <span class="quick-summary">
          共 <b>{{ total }}</b> 条
          <template v-if="hasFilters"> · 已筛选</template>
        </span>
      </div>
    </section>

    <section class="panel list-panel">
      <div class="list-head">
        <div class="list-title">
          <h2>漏洞清单</h2>
          <span class="muted">{{ total }} 条 · 第 {{ page }} / {{ pages }} 页</span>
        </div>
        <div class="list-tools">
          <label class="page-size">
            每页
            <select v-model.number="pageSize" @change="search">
              <option :value="10">10</option>
              <option :value="20">20</option>
              <option :value="50">50</option>
            </select>
          </label>
        </div>
      </div>

      <div v-if="loading" class="loading-rows">
        <div v-for="i in 8" :key="i" class="loading-row">
          <div class="skeleton" style="width: 110px; height: 14px"></div>
          <div class="skeleton" style="width: 42%; height: 14px"></div>
          <div class="skeleton" style="width: 90px; height: 14px"></div>
          <div class="skeleton" style="width: 54px; height: 14px"></div>
        </div>
      </div>

      <div v-else-if="!items.length" class="empty">
        <b>{{ hasFilters ? '没有匹配的情报' : '情报库还是空的' }}</b>
        {{ hasFilters ? '尝试减少筛选条件或更换关键词。' : '点右上角「立即抓取」从已启用的情报源拉取。' }}
      </div>

      <template v-else>
        <!-- 桌面：高密度表格 -->
        <div class="table-wrap">
          <table class="vuln-table">
            <thead>
              <tr>
                <th class="col-cve">CVE / ID</th>
                <th>标题</th>
                <th class="col-src">来源</th>
                <th class="col-vendor">厂商 / 产品</th>
                <th class="col-sev">等级</th>
                <th class="num">CVSS</th>
                <th class="num col-epss">EPSS</th>
                <th class="num col-score">评分</th>
                <th class="col-date">披露时间</th>
                <th class="col-op"></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="v in items" :key="v.id" tabindex="0" role="link" @click="open(v)" @keyup.enter="open(v)">
                <td class="col-cve">
                  <span v-if="primaryCVE(v)" class="cve-link mono">{{ primaryCVE(v) }}</span>
                  <span v-else class="cve-empty mono">{{ shortID(v.id) }}</span>
                </td>
                <td class="title-cell">
                  <div class="t-title">{{ v.name }}</div>
                  <div class="t-flags">
                    <span v-if="v.kev" class="chip chip-kev">KEV</span>
                    <span v-if="v.poc" class="chip chip-poc">PoC</span>
                    <span v-if="v.high_value" class="chip chip-ok">高价值</span>
                    <span v-if="v.has_nuclei" class="chip">nuclei</span>
                    <span v-if="!v.translated" class="chip">EN</span>
                  </div>
                </td>
                <td class="col-src"><span class="src-pill">{{ v.source }}</span></td>
                <td class="col-vendor"><span class="vendor">{{ displayVendor(v) }}</span></td>
                <td class="col-sev"><span class="sev" :class="'sev-' + sevKey(v.severity)">{{ sevLabel(v.severity) }}</span></td>
                <td class="num">{{ v.cvss ?? '—' }}</td>
                <td class="num col-epss">{{ epssText(v.epss) }}</td>
                <td class="num col-score"><b class="score" :class="{ hot: v.score >= 80 }">{{ v.score || 0 }}</b></td>
                <td class="col-date mono">{{ v.entry_date || '—' }}</td>
                <td class="col-op"><span class="row-action">详情</span></td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 移动：卡片列表 -->
        <div class="mobile-list">
          <article v-for="v in items" :key="v.id" class="m-card" @click="open(v)">
            <div class="m-card-top">
              <span class="sev" :class="'sev-' + sevKey(v.severity)">{{ sevLabel(v.severity) }}</span>
              <span v-if="primaryCVE(v)" class="chip chip-cve mono">{{ primaryCVE(v) }}</span>
              <b class="m-score" :class="{ hot: v.score >= 80 }">{{ v.score || 0 }}</b>
            </div>
            <h3>{{ v.name }}</h3>
            <p class="m-summary">{{ v.summary || '暂无摘要' }}</p>
            <div class="m-meta">
              <span class="src-pill">{{ v.source }}</span>
              <span v-if="v.kev" class="chip chip-kev">KEV</span>
              <span v-if="v.poc" class="chip chip-poc">PoC</span>
              <span class="m-date mono">{{ v.entry_date || '—' }}</span>
            </div>
          </article>
        </div>
      </template>

      <div v-if="pages > 1" class="pager">
        <button class="btn btn-sm" :disabled="page <= 1" @click="go(1)">首页</button>
        <button class="btn btn-sm" :disabled="page <= 1" @click="go(page - 1)">上一页</button>
        <span class="pager-info">第 <b>{{ page }}</b> / {{ pages }} 页</span>
        <button class="btn btn-sm" :disabled="page >= pages" @click="go(page + 1)">下一页</button>
        <button class="btn btn-sm" :disabled="page >= pages" @click="go(pages)">末页</button>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { backfillTranslate, collectStatus, listVulns, llmStatus, runCollect, stats } from './api'

const router = useRouter()
const items = ref([])
const counts = ref({})
const allTotal = ref(0)
const total = ref(0)
const page = ref(1)
const pages = ref(1)
const pageSize = ref(10)

const keyword = ref('')
const source = ref('')
const severity = ref('')
const vendor = ref('')
const sort = ref('latest')
const kevOnly = ref(false)
const pocOnly = ref(false)
const highOnly = ref(false)

const loading = ref(false)
const error = ref('')
const toast = ref('')
const collecting = ref(false)
const translating = ref(false)
const done = ref(0)
const llmOk = ref(true)
const st = ref(null)
const statsData = ref(null)

const hasFilters = computed(() =>
  keyword.value.trim() !== '' || source.value !== '' || severity.value !== '' ||
  vendor.value.trim() !== '' || kevOnly.value || pocOnly.value || highOnly.value)
const pagePending = computed(() => items.value.filter((i) => !i.translated).length)
const lastRunText = computed(() => (st.value?.last_run ? st.value.last_run.slice(5, 16).replace('T', ' ') : ''))

function sevKey(s) {
  const k = (s || 'unknown').toLowerCase()
  return ['critical', 'high', 'medium', 'low', 'info'].includes(k) ? k : 'unknown'
}
function sevLabel(s) {
  return { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }[sevKey(s)] || '未知'
}
function primaryCVE(v) {
  return (v.cves && v.cves[0]) || ''
}
function shortID(id) {
  return String(id || '').length > 16 ? String(id).slice(0, 16) + '…' : String(id || '')
}
function displayVendor(v) {
  const affected = (v.affected_products && v.affected_products[0]) || ''
  if (affected) return affected
  const m = String(v.name || '').match(/^[A-Za-z][A-Za-z0-9._-]*/)
  if (!m || /^(CVE|QVD|CNVD|CNNVD)-/i.test(m[0])) return 'Unknown'
  return m[0]
}
function epssText(value) {
  if (!(value > 0.0005)) return '—'
  const p = value * 100
  return (p < 1 ? p.toFixed(1) : Math.round(p)) + '%'
}
function open(v) {
  router.push(`/vuln/${encodeURIComponent(v.id)}`)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const r = await listVulns({
      page: page.value,
      page_size: pageSize.value,
      source: source.value,
      q: keyword.value.trim(),
      severity: severity.value,
      vendor: vendor.value.trim(),
      sort: sort.value,
      kev: kevOnly.value ? 1 : '',
      poc: pocOnly.value ? 1 : '',
      high_value: highOnly.value ? 1 : '',
    })
    items.value = r.items || []
    counts.value = r.counts || {}
    allTotal.value = r.all_total
    total.value = r.total
    pages.value = r.pages
    page.value = r.page
  } catch (e) {
    error.value = `加载失败：${e.message}`
  } finally {
    loading.value = false
  }
}

async function loadMeta() {
  try { statsData.value = await stats() } catch { /* 辅助信息 */ }
  try { st.value = await collectStatus() } catch { /* 同上 */ }
  try {
    const s = await llmStatus()
    llmOk.value = s.available
  } catch {
    llmOk.value = false
  }
}

function search() {
  page.value = 1
  load()
}
function reset() {
  keyword.value = ''
  source.value = ''
  severity.value = ''
  vendor.value = ''
  sort.value = 'latest'
  kevOnly.value = false
  pocOnly.value = false
  highOnly.value = false
  page.value = 1
  load()
}
function go(p) {
  page.value = Math.max(1, Math.min(p, pages.value))
  load()
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

async function translatePage() {
  translating.value = true
  done.value = 0
  error.value = ''
  const ids = items.value.filter((i) => !i.translated).map((i) => i.id)
  try {
    const r = await backfillTranslate(ids.length, ids)
    done.value = r.ok
    if (r.failed?.length) error.value = `${r.ok} 条已译，${r.failed.length} 条失败：${r.failed[0].reason}`
    else toast.value = `已翻译 ${r.ok} 条`
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    translating.value = false
  }
}

async function collect() {
  collecting.value = true
  error.value = ''
  toast.value = ''
  try {
    const r = await runCollect()
    if (r.skipped) toast.value = r.reason || '已有抓取任务在运行'
    else {
      const parts = [`抓取 ${r.fetched ?? 0} 条`, `入库 ${r.kept ?? 0} 条`, `高价值 ${r.high_value ?? 0} 条`]
      if (r.push?.pushed) parts.push(`推送 ${r.push.pushed} 条`)
      toast.value = parts.join(' · ')
    }
    await Promise.all([load(), loadMeta()])
  } catch (e) {
    error.value = `抓取失败：${e.message}`
  } finally {
    collecting.value = false
  }
}

onMounted(() => { load(); loadMeta() })
</script>

<style scoped>
.library { display: flex; flex-direction: column; gap: 14px; }

/* Hero */
.hero { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; padding: 6px 2px 2px; }
.hero h1 { font-size: 27px; line-height: 1.2; margin: 4px 0 6px; letter-spacing: -0.01em; color: var(--text); }
.hero-sub { margin: 0; color: var(--muted); font-size: 12.5px; }
.hero-badges { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 12px; }
.hero-badges b { font-weight: 650; }
.hero-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.spinner { width: 13px; height: 13px; border-radius: 50%; border: 2px solid rgba(255,255,255,.45);
  border-top-color: #fff; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.page-notice { margin-bottom: 2px; }

/* 筛选 */
.filters { padding: 14px 16px 10px; }
.filter-grid { display: grid; grid-template-columns: minmax(220px, 1.6fr) repeat(4, minmax(120px, 0.8fr)) auto; gap: 10px 12px; align-items: end; }
.filter-grid .field { gap: 5px; }
.filter-grid label { font-size: 11.5px; }
.filter-grid input, .filter-grid select { padding: 7px 10px; font-size: 12.5px; }
.filter-submit { display: flex; gap: 6px; }
.filter-submit .btn { padding: 7px 14px; }
.quick-row { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; margin-top: 11px; padding-top: 10px; border-top: 1px solid var(--line); }
.quick { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); cursor: pointer; }
.quick input { width: 14px; height: 14px; accent-color: var(--brand); }
.quick-summary { margin-left: auto; color: var(--dim); font-size: 12px; }
.quick-summary b { color: var(--text); }

/* 清单 */
.list-panel { overflow: hidden; }
.list-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px; border-bottom: 1px solid var(--line); }
.list-title { display: flex; align-items: baseline; gap: 10px; }
.list-title h2 { font-size: 14px; margin: 0; font-weight: 650; }
.list-title span { font-size: 12px; }
.list-tools { display: flex; align-items: center; gap: 10px; }
.page-size { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); }
.page-size select { width: auto; padding: 4px 8px; font-size: 12px; }

.table-wrap { overflow-x: auto; }
.vuln-table { width: 100%; border-collapse: collapse; font-size: 12.8px; }
.vuln-table thead th {
  text-align: left; font-weight: 600; color: var(--muted); font-size: 11.5px;
  padding: 9px 10px; background: var(--surface-subtle); border-bottom: 1px solid var(--line);
  white-space: nowrap;
}
.vuln-table tbody td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: middle; }
.vuln-table tbody tr { cursor: pointer; transition: background .12s; }
.vuln-table tbody tr:hover { background: #f7f9fc; }
.vuln-table tbody tr:hover .row-action { color: var(--brand); }
.vuln-table tbody tr:last-child td { border-bottom: 0; }
.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.col-cve { width: 128px; white-space: nowrap; }
.cve-link { color: var(--link); font-size: 12px; }
.cve-empty { color: var(--dim); font-size: 11.5px; }
.title-cell { min-width: 260px; }
.t-title { color: var(--text); font-weight: 550; line-height: 1.45; }
.t-flags { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
.t-flags .chip { padding: 0 6px; font-size: 10.5px; }
.col-src { width: 96px; }
.src-pill { font-size: 11px; color: var(--muted); background: #f2f4f7; padding: 1px 7px; border-radius: 4px; white-space: nowrap; }
.col-vendor { width: 160px; color: var(--muted); font-size: 12px; }
.vendor { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.col-sev { width: 70px; }
.col-score { width: 56px; }
.score { font-size: 13.5px; color: var(--text); }
.score.hot { color: var(--critical); }
.col-date { width: 96px; color: var(--dim); font-size: 11.5px; white-space: nowrap; }
.col-op { width: 48px; text-align: right; }
.row-action { font-size: 12px; color: var(--dim); }

/* 移动卡片 */
.mobile-list { display: none; }
.loading-rows { padding: 10px 16px; }
.loading-row { display: flex; align-items: center; gap: 14px; padding: 12px 0; border-bottom: 1px solid var(--line); }

.pager { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 12px; border-top: 1px solid var(--line); }
.pager-info { color: var(--muted); font-size: 12px; margin: 0 6px; }
.pager-info b { color: var(--text); }

@media (max-width: 1160px) {
  .filter-grid { grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr) minmax(0, 1fr); }
  .filter-submit { grid-row: auto; align-self: end; }
  .col-vendor { display: none; }
}
@media (max-width: 900px) {
  .hero { flex-direction: column; align-items: flex-start; }
  .hero-actions { width: 100%; }
  .hero-actions .btn { flex: 1; }
  .filter-grid { grid-template-columns: 1fr 1fr; }
  .filter-submit { grid-column: span 2; grid-row: auto; }
  .table-wrap { display: none; }
  .mobile-list { display: flex; flex-direction: column; }
  .m-card { padding: 13px 14px; border-bottom: 1px solid var(--line); cursor: pointer; }
  .m-card:last-child { border-bottom: 0; }
  .m-card:active { background: var(--surface-subtle); }
  .m-card-top { display: flex; align-items: center; gap: 7px; }
  .m-score { margin-left: auto; font-size: 17px; font-variant-numeric: tabular-nums; color: var(--muted); }
  .m-score.hot { color: var(--critical); }
  .m-card h3 { font-size: 14px; line-height: 1.45; margin: 7px 0 4px; }
  .m-summary { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.6;
    display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .m-meta { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
  .m-date { margin-left: auto; font-size: 11px; color: var(--dim); }
}
@media (max-width: 640px) {
  .hero h1 { font-size: 23px; }
  .filter-grid { grid-template-columns: 1fr 1fr; }
  .filter-grid .field:first-child { grid-column: span 2; }
  .filter-submit { grid-column: span 2; grid-row: auto; }
  .quick-row { gap: 12px; }
  .quick-summary { width: 100%; margin-left: 0; }
  .page-size { display: none; }
  .pager { gap: 5px; }
  .pager .btn { padding: 5px 8px; }
  .pager-info { font-size: 11px; }
}
</style>
