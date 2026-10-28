<template>
  <div class="templates-page">
    <div class="page-head">
      <div>
        <p class="eyebrow">NUCLEI TEMPLATES</p>
        <h1>模板库</h1>
        <p class="page-sub">本地模板可直接 <code>nuclei -l</code> 执行 · 上游增量同步</p>
      </div>
      <div class="head-actions">
        <button class="btn btn-primary" :disabled="busy" @click="doSync({})">
          {{ syncing ? '同步中…' : '同步增量' }}
        </button>
        <button class="btn" :disabled="busy" @click="doSync({ full: true })" title="忽略上次进度，重新扫全量">全量重扫</button>
      </div>
    </div>

    <div class="sync-panel panel panel-pad">
      <div class="sync-info">
        <span class="eyebrow">SYNC STATUS</span>
        <div class="sync-line">
          <template v-if="sync.cloned">
            <span>上次同步 <code>{{ sync.last_commit_short || '—' }}</code></span>
            <span v-if="sync.last_sync" class="muted">{{ sync.last_sync.replace('T', ' ').slice(0, 16) }}</span>
            <span class="chip">{{ sync.local_templates }} 个模板</span>
            <span v-if="sync.last_imported" class="chip chip-ok">上轮入库 {{ sync.last_imported }}</span>
          </template>
          <template v-else>
            <span class="muted">模板仓库尚未克隆，首次同步需下载约 1.5w 个模板</span>
          </template>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <div class="tabs">
        <button class="tab" :class="{ on: mode === 'local' }" @click="switchMode('local')">
          本地模板库 <i>{{ local.length }}</i>
        </button>
        <button class="tab" :class="{ on: mode === 'remote' }" @click="switchMode('remote')">
          远程模板库
        </button>
      </div>
      <span v-if="mode === 'local'" class="hint mono">{{ dir }}</span>
    </div>

    <div v-if="mode === 'remote'" class="filters panel panel-pad">
      <div class="field">
        <label>严重性</label>
        <select v-model="severity" @change="preview">
          <option value="">全部</option>
          <option v-for="s in severities" :key="s" :value="s">{{ s }}</option>
        </select>
      </div>
      <div class="field">
        <label>Tag / 路径关键字</label>
        <input v-model="tag" placeholder="如 cve, rce, apache" @keyup.enter="preview" />
      </div>
      <div class="field narrow">
        <label>条数</label>
        <input v-model.number="limit" type="number" min="1" max="50" />
      </div>
      <div class="filter-actions">
        <button class="btn" :disabled="busy" @click="preview">预览</button>
        <button class="btn btn-primary" :disabled="busy" @click="pull">
          {{ busy ? '拉取中…' : '拉取入库' }}
        </button>
      </div>
    </div>

    <div v-if="msg" class="notice notice-ok">{{ msg }}</div>
    <div v-if="error" class="notice notice-err">{{ error }}</div>

    <div v-if="!rows.length" class="panel empty">
      <b>{{ mode === 'local' ? '模板库还是空的' : '还没有远程预览结果' }}</b>
      {{ mode === 'local' ? '在漏洞详情页生成模板，或从远程拉取一批。' : '设置筛选条件后点「预览」取样。' }}
    </div>

    <div v-else class="tpl-list">
      <article v-for="t in rows" :key="t.id" class="tpl-card panel" :class="{ link: mode === 'local' }" @click="open(t)">
        <div class="tpl-main">
          <div class="tpl-head">
            <span class="sev" :class="'sev-' + (t.severity || 'unknown')">{{ t.severity || 'unknown' }}</span>
            <h3>{{ t.name }}</h3>
          </div>
          <p class="tpl-desc">{{ t.description || t.path || t.file }}</p>
          <div class="tpl-meta">
            <span v-if="t.id" class="chip mono">{{ t.id }}</span>
            <span v-if="t.requests != null" class="chip">{{ t.requests }} 个请求</span>
            <span v-if="t.tags" class="chip">{{ String(t.tags).slice(0, 40) }}</span>
          </div>
        </div>
        <span v-if="mode === 'local'" class="open-hint">打开 →</span>
      </article>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { listTemplates, previewRemote, pullRemote, runSync, syncStatus } from './api'

const severities = ['critical', 'high', 'medium', 'low', 'info']
const router = useRouter()

const mode = ref('local')
const local = ref([])
const remote = ref([])
const dir = ref('')
const limit = ref(10)
const severity = ref('')
const tag = ref('')
const busy = ref(false)
const syncing = ref(false)
const error = ref('')
const msg = ref('')
const sync = ref({ cloned: false, local_templates: 0, last_imported: 0 })

const rows = computed(() => (mode.value === 'local' ? local.value : remote.value))

async function loadSync() {
  try { sync.value = await syncStatus() } catch { /* 辅助信息 */ }
}

async function doSync(body) {
  busy.value = true
  syncing.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await runSync(body)
    if (r.error) error.value = r.error
    else if (r.skipped) msg.value = r.reason
    else {
      msg.value = `变更 ${r.changed} 个模板 → 入库 ${r.imported} 条` +
        (r.skipped ? `，跳过 ${r.skipped} 条` : '') +
        (r.failed ? `，失败 ${r.failed} 条` : '')
    }
    await Promise.all([loadSync(), loadLocal()])
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
    syncing.value = false
  }
}

async function loadLocal() {
  error.value = ''
  try {
    const r = await listTemplates()
    local.value = r.items || []
    dir.value = r.dir
  } catch (e) {
    error.value = e.message
  }
}

function switchMode(m) {
  mode.value = m
  msg.value = ''
  error.value = ''
}

async function preview() {
  busy.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await previewRemote({ limit: limit.value, severity: severity.value, tag: tag.value })
    remote.value = r.items || []
    msg.value = `${r.repo}@${r.ref} → ${r.items.length} 条`
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function pull() {
  busy.value = true
  error.value = ''
  msg.value = ''
  try {
    const r = await pullRemote({ limit: limit.value, severity: severity.value, tag: tag.value })
    msg.value = `拉取 ${r.fetched} 条 → 入库 ${r.saved.length} 条` +
      (r.skipped.length ? `，跳过 ${r.skipped.length} 条` : '')
    await loadLocal()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

function open(t) {
  if (mode.value === 'local' && t.vid) router.push(`/vuln/${encodeURIComponent(t.vid)}`)
}

onMounted(() => { loadLocal(); loadSync() })
</script>

<style scoped>
.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 18px; margin-bottom: 18px; }
.page-head h1 { font-size: 26px; margin: 4px 0 5px; letter-spacing: -0.01em; }
.page-sub { margin: 0; color: var(--muted); font-size: 12.5px; }
.page-sub code { background: #f2f4f7; padding: 1px 6px; border-radius: 5px; font-family: var(--mono); font-size: 11.5px; }
.head-actions { display: flex; gap: 8px; }

.sync-panel { margin-bottom: 14px; }
.sync-line { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: 6px; font-size: 12.5px; color: var(--muted); }
.sync-line code { background: #f2f4f7; padding: 1px 6px; border-radius: 5px; font-family: var(--mono); font-size: 11.5px; }

.toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.tabs { display: flex; gap: 6px; }
.tab { background: transparent; border: 1px solid transparent; color: var(--muted); padding: 6px 13px; border-radius: 999px; font-size: 12.5px; cursor: pointer; }
.tab i { font-style: normal; font-size: 11px; color: var(--dim); margin-left: 5px; }
.tab.on { background: var(--brand); border-color: var(--brand); color: #fff; }
.hint { font-size: 11px; color: var(--dim); max-width: 46%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.filters { display: flex; align-items: flex-end; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
.filters .field { min-width: 180px; }
.filters .field.narrow input { max-width: 90px; }
.filter-actions { display: flex; gap: 8px; margin-left: auto; }

.notice { margin-bottom: 12px; }
.tpl-list { display: flex; flex-direction: column; gap: 10px; }
.tpl-card { display: flex; align-items: center; gap: 16px; padding: 15px 18px; }
.tpl-card.link { cursor: pointer; }
.tpl-card.link:hover { border-color: rgba(122, 27, 61, 0.35); }
.tpl-main { flex: 1; min-width: 0; }
.tpl-head { display: flex; align-items: center; gap: 9px; }
.tpl-head h3 { margin: 0; font-size: 14px; font-weight: 620; line-height: 1.4; }
.tpl-desc { margin: 6px 0 0; color: var(--muted); font-size: 12px; line-height: 1.6;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.tpl-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
.open-hint { flex: none; font-size: 12px; color: var(--dim); }
.tpl-card:hover .open-hint { color: var(--brand); }

@media (max-width: 640px) {
  .page-head { flex-direction: column; align-items: flex-start; }
  .head-actions { width: 100%; }
  .head-actions .btn { flex: 1; }
  .filters .field { min-width: 100%; }
  .filter-actions { width: 100%; margin-left: 0; }
  .filter-actions .btn { flex: 1; }
  .hint { display: none; }
}
</style>
