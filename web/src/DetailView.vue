<template>
  <div class="detail-page">
    <button class="back" @click="$router.push('/')">
      <span>←</span> 返回情报流
    </button>

    <div v-if="error" class="notice notice-err">{{ error }}</div>
    <div v-else-if="!v" class="loading-panel panel">
      <div class="skeleton" style="width: 40%; height: 20px"></div>
      <div class="skeleton" style="width: 72%; height: 26px; margin-top: 14px"></div>
      <div class="skeleton" style="width: 100%; height: 16px; margin-top: 16px"></div>
      <div class="skeleton" style="width: 88%; height: 16px; margin-top: 8px"></div>
    </div>

    <template v-else>
      <div class="hero panel">
        <div class="hero-main">
          <div class="badges">
            <span class="sev" :class="'sev-' + sevKey(v.severity)">{{ sevLabel(v.severity) }}</span>
            <span v-if="v.high_value" class="chip chip-kev">高价值</span>
            <span v-if="v.kev" class="chip chip-kev">CISA KEV</span>
            <span v-if="v.poc_disclosed" class="chip chip-poc">PoC 已公开</span>
            <span v-if="v.translated" class="chip chip-ok">中文</span>
            <span v-if="v.nuclei_yaml" class="chip chip-ok">nuclei 模板</span>
          </div>
          <h1>{{ v.name }}</h1>
          <div class="hero-meta">
            <span>来源 <b>{{ v.source }}</b></span>
            <span v-if="v.cves && v.cves.length">CVE <b class="mono">{{ v.cves.join(', ') }}</b></span>
            <span v-if="v.published">披露 <b class="mono">{{ v.published }}</b></span>
            <span v-if="v.created_at">收录 <b class="mono">{{ v.created_at.slice(0, 10) }}</b></span>
          </div>
        </div>
        <div class="hero-side">
          <div class="score-badge" :class="{ hot: v.score >= 80 }">
            <b>{{ v.score || 0 }}</b>
            <span>风险分</span>
          </div>
        </div>
      </div>

      <div class="action-row">
        <button v-if="needZh" class="btn" :disabled="!!busy || !llmOk" @click="doTranslate">
          {{ busy === 'zh' ? '翻译中…' : '译成中文' }}
        </button>
        <button class="btn" :disabled="pushing" @click="doPush">
          {{ pushing ? '推送中…' : '推送此条' }}
        </button>
        <a v-if="firstRef" class="btn btn-ghost" :href="firstRef" target="_blank" rel="noreferrer">查看原文 ↗</a>
      </div>
      <div v-if="pushMsg" class="notice" :class="pushOk ? 'notice-ok' : 'notice-err'">{{ pushMsg }}</div>

      <div class="detail-grid">
        <div class="col-main">
          <section class="panel panel-pad">
            <h2 class="sec-h">漏洞简介</h2>
            <p class="prose">{{ v.summary || '暂无摘要。' }}</p>
          </section>

          <section class="panel panel-pad">
            <h2 class="sec-h">漏洞原理</h2>
            <p class="prose pre">{{ v.principle || '暂无原理说明，建议参考原文与官方公告。' }}</p>
          </section>

          <section class="panel panel-pad">
            <h2 class="sec-h">攻击范围</h2>
            <p class="prose">{{ v.attack_scope || '以官方公告为准。' }}</p>
            <div v-if="v.affected_products && v.affected_products.length" class="affected">
              <span class="field-label">影响产品</span>
              <div class="chips">
                <span v-for="p in v.affected_products" :key="p" class="chip chip-line">{{ p }}</span>
              </div>
            </div>
          </section>

          <section class="panel">
            <div class="sec-head">
              <h2 class="sec-h">PoC 验证代码</h2>
              <div class="sec-actions">
                <button v-if="v.poc" class="btn btn-sm" @click="copy('poc')">{{ copied === 'poc' ? '已复制' : '复制' }}</button>
                <button class="btn btn-sm btn-primary" :disabled="!llmOk || busy !== ''" @click="doGenPoc">
                  {{ busy === 'poc' ? '生成中…' : (v.poc ? '重新生成' : 'AI 生成') }}
                </button>
              </div>
            </div>
            <div class="sec-body">
              <p v-if="pocMsg" class="notice notice-err">{{ pocMsg }}</p>
              <template v-if="v.poc">
                <pre class="code poc" :class="{ folded: !pocOpen }"><code>{{ v.poc }}</code></pre>
                <button class="fold" @click="pocOpen = !pocOpen">
                  {{ pocOpen ? '收起 ▲' : `展开全文（${lineCount(v.poc)} 行）▼` }}
                </button>
              </template>
              <p v-else class="none">
                {{ v.poc_source === 'nuclei' ? '该条目来自 nuclei 模板库，仅含模板，可按公开思路生成独立脚本。' : '暂无 PoC。' }}
              </p>
            </div>
          </section>

          <section class="panel">
            <div class="sec-head">
              <h2 class="sec-h">nuclei 模板</h2>
              <div class="sec-actions">
                <button v-if="v.nuclei_yaml" class="btn btn-sm" @click="copy('nuclei')">{{ copied === 'nuclei' ? '已复制' : '复制' }}</button>
                <button v-if="!v.nuclei_yaml && v.poc_source !== 'nuclei'" class="btn btn-sm btn-primary" :disabled="genning" @click="gen">
                  {{ genning ? '生成中…' : '生成模板' }}
                </button>
              </div>
            </div>
            <div class="sec-body">
              <pre v-if="v.nuclei_yaml" class="code yaml"><code>{{ v.nuclei_yaml }}</code></pre>
              <p v-else class="none">{{ genMsg || '暂无模板。' }}</p>
            </div>
          </section>

          <section v-if="v.refs && v.refs.length" class="panel panel-pad">
            <h2 class="sec-h">参考链接</h2>
            <ul class="refs">
              <li v-for="r in v.refs" :key="r">
                <a :href="r" target="_blank" rel="noopener noreferrer">{{ r }}</a>
              </li>
            </ul>
          </section>
        </div>

        <aside class="col-side">
          <section class="panel panel-pad risk-card">
            <div class="risk-head">
              <h2 class="sec-h">风险画像</h2>
              <span class="sev" :class="'sev-' + sevKey(v.severity)">{{ sevLabel(v.severity) }}</span>
            </div>
            <div class="metrics">
              <div class="metric">
                <span>CVSS</span>
                <b>{{ v.cvss ?? '—' }}</b>
              </div>
              <div class="metric">
                <span>EPSS</span>
                <b>{{ v.epss ? Math.round(v.epss * 100) + '%' : '—' }}</b>
              </div>
              <div class="metric">
                <span>KEV</span>
                <b :class="{ good: v.kev }">{{ v.kev ? '在野' : '否' }}</b>
              </div>
              <div class="metric">
                <span>PoC</span>
                <b :class="{ good: v.poc || v.poc_disclosed }">{{ v.poc || v.poc_disclosed ? '可用' : '无' }}</b>
              </div>
            </div>
            <div v-if="v.score_reasons && v.score_reasons.length" class="reasons">
              <span class="field-label">判定依据</span>
              <ul>
                <li v-for="r in v.score_reasons" :key="r">{{ r }}</li>
              </ul>
            </div>
            <div v-if="v.tags && v.tags.length" class="tags">
              <span v-for="t in v.tags" :key="t" class="chip">{{ t }}</span>
            </div>
          </section>

          <section class="panel panel-pad meta-card">
            <h2 class="sec-h">元数据</h2>
            <dl>
              <div><dt>情报 ID</dt><dd class="mono">{{ v.id }}</dd></div>
              <div><dt>严重性</dt><dd>{{ sevLabel(v.severity) }}<span v-if="v.severity_inferred" class="dim">（推断）</span></dd></div>
              <div v-if="v.cwe && v.cwe.length"><dt>CWE</dt><dd class="mono">{{ v.cwe.join(', ') }}</dd></div>
              <div><dt>PoC 来源</dt><dd>{{ pocSourceLabel(v.poc_source) }}</dd></div>
              <div><dt>推送状态</dt><dd>{{ v.pushed ? '已推送' : (v.high_value ? '待推送' : '不满足推送规则') }}</dd></div>
              <div v-if="v.pushed_at"><dt>推送时间</dt><dd class="mono">{{ v.pushed_at.replace('T', ' ') }}</dd></div>
            </dl>
          </section>
        </aside>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { genNuclei, genPoc, getVuln, llmStatus, pushVuln, translateVuln } from './api'

const route = useRoute()
const v = ref(null)
const error = ref('')
const copied = ref('')
const genning = ref(false)
const genMsg = ref('')
const pocMsg = ref('')
const pocOpen = ref(false)
const busy = ref('')
const llmOk = ref(true)
const needZh = ref(false)
const pushing = ref(false)
const pushMsg = ref('')
const pushOk = ref(false)

const firstRef = computed(() => (v.value?.refs || []).find((r) => /^https?:\/\//.test(r)) || '')
const hasZh = (s) => /[\u4e00-\u9fff]/.test(s || '')

function sevKey(s) {
  const k = (s || 'unknown').toLowerCase()
  return ['critical', 'high', 'medium', 'low', 'info'].includes(k) ? k : 'unknown'
}
function sevLabel(s) {
  return { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }[sevKey(s)] || '未知'
}
function pocSourceLabel(s) {
  return { article: '原文提取', ai: 'AI 生成', nuclei: '模板库', none: '无' }[s] || '无'
}
function lineCount(s) {
  return (s.match(/\n/g) || []).length + 1
}

async function load(id) {
  v.value = null
  error.value = ''
  genMsg.value = ''
  pocMsg.value = ''
  pushMsg.value = ''
  pocOpen.value = false
  try {
    v.value = await getVuln(id)
    needZh.value = !hasZh(v.value.name) && !v.value.translated
  } catch (e) {
    error.value = `加载失败：${e.message}`
  }
}

async function copy(which) {
  try {
    await navigator.clipboard.writeText(v.value[which === 'poc' ? 'poc' : 'nuclei_yaml'] || '')
    copied.value = which
    setTimeout(() => (copied.value = ''), 1500)
  } catch {
    copied.value = ''
  }
}

async function doGenPoc() {
  busy.value = 'poc'
  pocMsg.value = ''
  try {
    await genPoc(v.value.id)
    await load(v.value.id)
  } catch (e) {
    pocMsg.value = e.message
  } finally {
    busy.value = ''
  }
}

async function doTranslate() {
  busy.value = 'zh'
  genMsg.value = ''
  try {
    await translateVuln(v.value.id)
    await load(v.value.id)
  } catch (e) {
    genMsg.value = e.message
  } finally {
    busy.value = ''
  }
}

async function gen() {
  genning.value = true
  genMsg.value = ''
  try {
    const r = await genNuclei(v.value.id)
    genMsg.value = r.ok ? '' : r.reason
    if (r.ok) await load(v.value.id)
  } catch (e) {
    genMsg.value = e.message
  } finally {
    genning.value = false
  }
}

async function doPush() {
  pushing.value = true
  pushMsg.value = ''
  try {
    const r = await pushVuln(v.value.id)
    pushOk.value = !!r.pushed
    pushMsg.value = r.message || (r.pushed ? '已推送' : '推送失败')
    await load(v.value.id)
  } catch (e) {
    pushOk.value = false
    pushMsg.value = e.message
  } finally {
    pushing.value = false
  }
}

onMounted(() => {
  load(route.params.id)
  llmStatus().then((s) => (llmOk.value = s.available)).catch(() => (llmOk.value = false))
})
watch(() => route.params.id, (id) => id && load(id))
</script>

<style scoped>
.detail-page { max-width: 1080px; margin: 0 auto; }
.back {
  background: none; border: 0; color: var(--muted); font-size: 12.5px; cursor: pointer;
  padding: 4px 0; margin-bottom: 12px; display: inline-flex; align-items: center; gap: 6px;
}
.back:hover { color: var(--text); }
.loading-panel { padding: 26px; }

.hero { display: flex; align-items: stretch; gap: 20px; padding: 22px 24px; margin-bottom: 14px; }
.hero-main { flex: 1; min-width: 0; }
.badges { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
.hero h1 { font-size: 22px; line-height: 1.4; margin: 10px 0 10px; letter-spacing: -0.005em; }
.hero-meta { display: flex; flex-wrap: wrap; gap: 8px 18px; color: var(--dim); font-size: 12px; }
.hero-meta b { color: var(--muted); font-weight: 550; }
.hero-side { flex: none; display: flex; align-items: center; }
.score-badge {
  min-width: 92px; padding: 12px 14px; border-radius: 12px; text-align: center;
  background: var(--surface-subtle); border: 1px solid var(--line);
}
.score-badge b { display: block; font-size: 32px; line-height: 1; font-weight: 700; color: var(--muted); font-variant-numeric: tabular-nums; }
.score-badge span { font-size: 10.5px; color: var(--dim); }
.score-badge.hot { background: rgba(255, 95, 109, 0.1); border-color: rgba(255, 95, 109, 0.3); }
.score-badge.hot b { color: var(--critical); }

.action-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
.action-row + .notice { margin-bottom: 14px; }

.detail-grid { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 14px; align-items: start; }
.col-main { display: flex; flex-direction: column; gap: 14px; min-width: 0; }
.col-side { display: flex; flex-direction: column; gap: 14px; position: sticky; top: 82px; }

.sec-h { font-size: 14px; font-weight: 620; margin: 0 0 10px; color: var(--text); }
.sec-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 16px 20px 0; }
.sec-head .sec-h { margin: 0; }
.sec-actions { display: flex; gap: 6px; }
.sec-body { padding: 14px 20px 18px; }
.prose { margin: 0; color: #344054; font-size: 13.5px; line-height: 1.75; }
.prose.pre { white-space: pre-wrap; }
.affected { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }

.code {
  margin: 0; padding: 15px 16px; border-radius: 10px; overflow-x: auto;
  background: var(--code-bg); border: 1px solid #1e293b;
  font-family: var(--mono); font-size: 12.3px; line-height: 1.65; color: #a7e8c9;
}
.code.yaml { color: #ffd98a; white-space: pre-wrap; }
.code.poc.folded { max-height: 340px; overflow: hidden;
  -webkit-mask-image: linear-gradient(#000 76%, transparent); mask-image: linear-gradient(#000 76%, transparent); }
.fold { display: block; margin: 8px auto 0; background: none; border: 1px solid var(--line-strong);
  color: var(--muted); border-radius: 7px; padding: 4px 12px; font-size: 11.5px; cursor: pointer; }
.fold:hover { color: var(--text); }
.none { color: var(--dim); font-size: 12.5px; margin: 0; }

.risk-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.risk-head .sec-h { margin: 0; }
.metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.metric { background: var(--surface-subtle); border-radius: 8px; padding: 9px 11px; }
.metric span { display: block; font-size: 10.5px; color: var(--dim); }
.metric b { font-size: 15px; font-variant-numeric: tabular-nums; }
.metric b.good { color: var(--ok); }
.reasons { margin-top: 14px; }
.reasons ul { margin: 7px 0 0; padding-left: 16px; color: var(--muted); font-size: 12px; line-height: 1.7; }
.tags { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 14px; }

.meta-card dl { margin: 0; display: flex; flex-direction: column; gap: 9px; }
.meta-card dl > div { display: flex; justify-content: space-between; gap: 12px; font-size: 12px; }
.meta-card dt { color: var(--dim); flex: none; }
.meta-card dd { margin: 0; color: var(--muted); text-align: right; word-break: break-all; }

.refs { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 7px; }
.refs a { font-size: 12px; color: #8fb8ff; word-break: break-all; }

@media (max-width: 900px) {
  .detail-grid { grid-template-columns: 1fr; }
  .col-side { position: static; }
}
@media (max-width: 640px) {
  .hero { flex-direction: column; padding: 18px; gap: 14px; }
  .hero h1 { font-size: 19px; }
  .hero-side { align-self: flex-start; }
  .score-badge { display: flex; align-items: baseline; gap: 8px; min-width: 0; padding: 8px 12px; }
  .score-badge b { font-size: 24px; }
  .sec-head { padding: 14px 16px 0; flex-wrap: wrap; }
  .sec-body { padding: 12px 16px 16px; }
  .code { font-size: 11.5px; padding: 12px; }
}
</style>
