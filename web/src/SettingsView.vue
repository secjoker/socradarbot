<template>
  <div class="settings-page">
    <div class="page-head">
      <div>
        <p class="eyebrow">CONFIGURATION</p>
        <h1>配置</h1>
        <p class="page-sub">保存后立即生效 · 配置文件 <code>{{ configFile || 'config.yaml' }}</code></p>
      </div>
      <div class="head-actions">
        <span v-if="msg" class="notice notice-ok inline">{{ msg }}</span>
      </div>
    </div>

    <div v-if="error" class="notice notice-err">{{ error }}</div>

    <div class="tabs">
      <button v-for="t in tabs" :key="t.id" class="tab" :class="{ on: tab === t.id }" @click="tab = t.id">
        {{ t.label }}
      </button>
    </div>

    <!-- ── AI 接口 ─────────────────────────────── -->
    <section v-if="tab === 'ai'" class="panel panel-pad">
      <div class="section-head">
        <div>
          <h2 class="section-title">AI 接口</h2>
          <p class="section-desc">OpenAI 兼容端点，用于情报补全、翻译与 PoC 生成。留空 Key 表示保持原值。</p>
        </div>
        <span class="chip" :class="keySet ? 'chip-ok' : ''">{{ keySet ? '已配置密钥' : '未配置' }}</span>
      </div>

      <div class="form-grid">
        <div class="field">
          <label>接口地址</label>
          <input v-model.trim="llm.base" placeholder="https://api.example.com" />
          <small>不含 /v1，系统自动拼接</small>
        </div>
        <div class="field">
          <label>API Key</label>
          <input v-model="llm.key" type="password" :placeholder="keyPlaceholder" autocomplete="off" />
          <small>{{ keySet ? '已保存，留空则不改动' : '尚未配置，AI 功能不可用' }}</small>
        </div>
        <div class="field">
          <label>模型名</label>
          <input v-model.trim="llm.model" placeholder="gpt-4o-mini" />
        </div>
        <div class="field">
          <label>超时（秒）</label>
          <input v-model.number="llm.timeout" type="number" min="1" max="600" />
        </div>
      </div>

      <div class="actions">
        <button class="btn btn-primary" :disabled="busy" @click="saveMain">保存配置</button>
        <button class="btn" :disabled="busy || testing" @click="test">
          {{ testing ? '测试中…' : '测试连通性' }}
        </button>
        <span v-if="testMsg" class="notice notice-ok inline">{{ testMsg }}</span>
      </div>
    </section>

    <!-- ── 采集与源 ────────────────────────────── -->
    <template v-if="tab === 'collect'">
      <section class="panel panel-pad">
        <div class="section-head">
          <div>
            <h2 class="section-title">采集策略</h2>
            <p class="section-desc">定时抓取、保留周期与正文抓取。抓取与模板同步互不阻塞。</p>
          </div>
        </div>
        <div class="form-grid-3">
          <div class="field">
            <label>定时间隔（分钟）</label>
            <input v-model.number="collect.interval_minutes" type="number" min="1" max="1440" />
          </div>
          <div class="field">
            <label>单源条数上限</label>
            <input v-model.number="collect.fetch_limit" type="number" min="1" max="100" />
            <small>每个源每轮最多抓取多少条</small>
          </div>
          <div class="field">
            <label>保留天数</label>
            <input v-model.number="collect.keep_days" type="number" min="0" max="3650" />
            <small>0 = 不按日期清理</small>
          </div>
        </div>
        <div class="check-grid">
          <label class="check-row">
            <input v-model="collect.auto_translate" type="checkbox" />
            <span>自动中文化<small>英文情报入库时翻译标题 / 简介 / 原理</small></span>
          </label>
          <label class="check-row">
            <input v-model="collect.article_fetch" type="checkbox" />
            <span>抓取文章正文<small>用于 PoC 提取与 AI 情报补全</small></span>
          </label>
        </div>
        <div class="actions">
          <button class="btn btn-primary" :disabled="busy" @click="saveMain">保存配置</button>
          <button class="btn" :disabled="busy" @click="purge">{{ purging ? '清理中…' : '立即清理过期漏洞' }}</button>
          <span v-if="purgeMsg" class="notice notice-ok inline">{{ purgeMsg }}</span>
        </div>
      </section>

      <section class="panel panel-pad">
        <div class="section-head">
          <div>
            <h2 class="section-title">数据富化</h2>
            <p class="section-desc">CVE / CVSS / EPSS / KEV / 影响范围补全，直接影响风险评分与推送判定。</p>
          </div>
          <span class="chip" :class="enrich.enabled ? 'chip-ok' : ''">{{ enrich.enabled ? '已启用' : '已关闭' }}</span>
        </div>
        <div class="check-grid">
          <label class="check-row"><input v-model="enrich.enabled" type="checkbox" /><span>富化总开关</span></label>
          <label class="check-row"><input v-model="enrich.epss" type="checkbox" /><span>EPSS 利用概率</span></label>
          <label class="check-row"><input v-model="enrich.kev" type="checkbox" /><span>CISA KEV 在野利用</span></label>
          <label class="check-row"><input v-model="enrich.nvd" type="checkbox" /><span>NVD（CVSS / CPE）</span></label>
          <label class="check-row"><input v-model="enrich.github_advisory" type="checkbox" /><span>GitHub Advisory</span></label>
        </div>
        <div class="form-grid-3" style="margin-top: 16px">
          <div class="field">
            <label>外部请求超时（秒）</label>
            <input v-model.number="enrich.timeout_seconds" type="number" min="5" max="120" />
          </div>
          <div class="field">
            <label>缓存时长（小时）</label>
            <input v-model.number="enrich.cache_hours" type="number" min="1" max="168" />
          </div>
          <div class="field">
            <label>GitHub Token</label>
            <input v-model="enrich.github_token" type="password" :placeholder="githubTokenSet ? '已配置，留空不改' : '可选，提升 API 限流'" />
          </div>
        </div>
        <div class="actions">
          <button class="btn btn-primary" :disabled="busy" @click="saveMain">保存配置</button>
          <button class="btn" :disabled="rebuilding" @click="rebuild">
            {{ rebuilding ? '重算中…' : '存量重新富化' }}
          </button>
          <span v-if="rebuildMsg" class="notice notice-ok inline">{{ rebuildMsg }}</span>
        </div>
      </section>

      <section class="panel panel-pad">
        <div class="section-head">
          <div>
            <h2 class="section-title">情报源</h2>
            <p class="section-desc">内置源可直接启停；自定义 RSS 与内置源叠加抓取。</p>
          </div>
          <span class="chip">{{ enabledBuiltin }} / {{ builtin.length }} 启用</span>
        </div>

        <div class="source-list">
          <div v-for="s in builtin" :key="s.id" class="source-row">
            <div class="source-main">
              <div class="source-title">
                <b>{{ s.name }}</b>
                <span class="chip">{{ s.kind === 'json' ? '结构化' : 'RSS' }}</span>
                <span class="chip" :class="s.enabled ? 'chip-ok' : ''">{{ s.enabled ? '启用' : '停用' }}</span>
              </div>
              <a class="source-url" :href="s.url" target="_blank" rel="noreferrer">{{ s.url }}</a>
              <p class="source-desc">{{ s.description }}</p>
            </div>
            <label class="switch" :title="s.enabled ? '点击停用' : '点击启用'">
              <input type="checkbox" :checked="s.enabled" @change="toggleSource(s.id, $event.target.checked)" />
              <span></span>
            </label>
          </div>
        </div>

        <div class="sub-head">
          <h3>自定义源</h3>
          <span class="muted">{{ custom.length }} 个</span>
        </div>
        <div v-if="custom.length" class="custom-list">
          <div v-for="s in custom" :key="s.name" class="custom-row">
            <div class="custom-main">
              <b>{{ s.name }}</b>
              <a :href="s.url" target="_blank" rel="noreferrer">{{ s.url }}</a>
            </div>
            <button class="btn btn-sm btn-danger" @click="remove(s.name)">移除</button>
          </div>
        </div>
        <p v-else class="none">尚未接入自定义源，可在下方探测并接入。</p>

        <div class="probe">
          <div class="field">
            <label>探测新社区</label>
            <div class="probe-row">
              <input v-model.trim="probeUrl" placeholder="https://xz.aliyun.com" @keyup.enter="probe" />
              <button class="btn" :disabled="probing" @click="probe">{{ probing ? '探测中…' : '探测 feed' }}</button>
            </div>
            <small>填社区首页，自动尝试常见 RSS 路径并判断是否为漏洞社区</small>
          </div>
          <label class="check-row"><input v-model="probeJudge" type="checkbox" /><span>使用 AI 判活</span></label>
          <p v-if="probeMsg" class="notice" :class="cands.length ? 'notice-ok' : 'notice-err'">{{ probeMsg }}</p>

          <div v-if="cands.length" class="cands">
            <div v-for="c in cands" :key="c.url" class="cand">
              <div class="cand-head">
                <b>{{ c.verdict.suggested_name || c.url }}</b>
                <span class="chip" :class="c.verdict.is_vuln_source ? 'chip-ok' : 'chip-kev'">
                  {{ c.verdict.is_vuln_source ? '可用' : '疑似非漏洞源' }}
                </span>
                <span class="muted">{{ c.entries }} 条</span>
              </div>
              <a class="source-url" :href="c.url" target="_blank" rel="noreferrer">{{ c.url }}</a>
              <p class="source-desc">{{ c.verdict.reason }}</p>
              <div class="cand-actions">
                <input v-model.trim="c.name" placeholder="源名称，如「先知」" />
                <button class="btn btn-sm btn-primary" :disabled="busy || !c.name" @click="attach(c)">接入</button>
              </div>
            </div>
          </div>
        </div>

        <div class="actions">
          <button class="btn btn-primary" :disabled="busy" @click="saveMain">保存源配置</button>
        </div>
      </section>
    </template>

    <!-- ── 情报推送 ────────────────────────────── -->
    <template v-if="tab === 'push'">
      <section class="panel panel-pad">
        <div class="section-head">
          <div>
            <h2 class="section-title">高价值情报推送</h2>
            <p class="section-desc">评分达标才推送；同批同 CVE 只推一次，冷却窗口内不重复。</p>
          </div>
          <label class="switch" title="推送总开关">
            <input v-model="push.enabled" type="checkbox" />
            <span></span>
          </label>
        </div>

        <div class="form-grid">
          <div class="field">
            <label>最低风险分（0–100）</label>
            <input v-model.number="push.min_score" type="number" min="0" max="100" />
            <small>默认 60；评分模型见 README</small>
          </div>
          <div class="field">
            <label>严重性下限</label>
            <select v-model="push.min_severity">
              <option value="">不限</option>
              <option value="medium">中危及以上</option>
              <option value="high">高危及以上</option>
              <option value="critical">仅严重</option>
            </select>
          </div>
          <div class="field">
            <label>单批最多推送</label>
            <input v-model.number="push.max_per_batch" type="number" min="1" max="100" />
          </div>
          <div class="field">
            <label>冷却窗口（分钟）</label>
            <input v-model.number="push.cooldown_minutes" type="number" min="0" max="10080" />
          </div>
        </div>

        <div class="check-grid" style="margin-top: 16px">
          <label class="check-row"><input v-model="push.require_cve" type="checkbox" /><span>必须关联 CVE</span></label>
          <label class="check-row"><input v-model="push.require_poc" type="checkbox" /><span>必须存在 PoC / 模板</span></label>
        </div>

        <div class="form-grid" style="margin-top: 16px">
          <div class="field">
            <label>关键词白名单</label>
            <textarea v-model="includeText" placeholder="逗号或换行分隔，命中任一才推送；留空表示不限"></textarea>
            <small>作用于标题 + 摘要，例如：RCE, 反序列化, 未授权</small>
          </div>
          <div class="field">
            <label>关键词黑名单</label>
            <textarea v-model="excludeText" placeholder="逗号或换行分隔，标题命中则不推送"></textarea>
            <small>仅检查标题，避免描述误杀</small>
          </div>
        </div>

        <div class="sub-head">
          <h3>推送渠道</h3>
          <div class="add-channel">
            <select v-model="newType">
              <option v-for="t in channelTypes" :key="t.value" :value="t.value">{{ t.label }}</option>
            </select>
            <button class="btn btn-sm" @click="addChannel">+ 添加</button>
          </div>
        </div>

        <div v-if="!channels.length" class="empty small">
          <b>还没有配置推送渠道</b>添加企业微信、钉钉、飞书、Slack、Telegram 或通用 Webhook。
        </div>

        <div v-for="(ch, i) in channels" :key="i" class="channel-card">
          <div class="channel-head">
            <div class="channel-title">
              <span class="chip">{{ typeLabel(ch.type) }}</span>
              <b>{{ ch.name || '未命名渠道' }}</b>
              <span v-if="ch.webhook_set && !ch.webhook" class="chip chip-ok">已保存地址</span>
            </div>
            <div class="channel-ops">
              <label class="switch" title="启用该渠道">
                <input v-model="ch.enabled" type="checkbox" />
                <span></span>
              </label>
              <button class="btn btn-sm btn-danger" @click="removeChannel(i)">删除</button>
            </div>
          </div>
          <div class="form-grid" style="margin-top: 12px">
            <div class="field">
              <label>渠道名称</label>
              <input v-model.trim="ch.name" placeholder="如：安全运营群" />
            </div>
            <div class="field">
              <label>渠道类型</label>
              <select v-model="ch.type">
                <option v-for="t in channelTypes" :key="t.value" :value="t.value">{{ t.label }}</option>
              </select>
            </div>
            <div class="field span-2">
              <label>Webhook 地址</label>
              <input v-model.trim="ch.webhook" :placeholder="ch.webhook_set ? '已配置，留空保持不变' : 'https://...'" />
              <small v-if="ch.type === 'telegram'">可填完整 sendMessage 地址，或只填 Bot Token</small>
              <small v-else>机器人 Webhook 完整 URL</small>
            </div>
            <div class="field">
              <label>签名密钥（可选）</label>
              <input v-model.trim="ch.secret" :placeholder="ch.secret_set ? '已配置，留空保持不变' : '钉钉加签 / 飞书签名'" />
            </div>
            <div class="field">
              <label>Telegram Chat IDs</label>
              <input v-model.trim="ch.chat_ids_text" placeholder="多个用逗号分隔；其他渠道忽略" />
            </div>
            <div v-if="ch.type === 'slack'" class="field">
              <label>Slack 频道（可选）</label>
              <input v-model.trim="ch.channel" placeholder="#security" />
            </div>
          </div>
        </div>

        <div class="actions push-actions">
          <button class="btn btn-primary" :disabled="savingPush" @click="savePushConfig">
            {{ savingPush ? '保存中…' : '保存推送配置' }}
          </button>
          <button class="btn" :disabled="testingPush" @click="testPushConfig">
            {{ testingPush ? '发送中…' : '发送测试消息' }}
          </button>
          <button class="btn" :disabled="runningPush" @click="runPushNow">
            {{ runningPush ? '推送中…' : '立即推送待推队列' }}
          </button>
        </div>

        <div v-if="pushResult" class="notice" :class="pushOk ? 'notice-ok' : 'notice-err'">
          {{ pushResult }}
          <div v-if="pushChannels.length" class="push-channels">
            <span v-for="c in pushChannels" :key="c.name" class="chip" :class="c.ok ? 'chip-ok' : 'chip-kev'">
              {{ c.name }} · {{ c.ok ? '成功' : (c.error || '失败') }}
            </span>
          </div>
        </div>
      </section>

      <section class="panel panel-pad">
        <div class="section-head">
          <div>
            <h2 class="section-title">最近推送</h2>
            <p class="section-desc">最多保留 100 条记录，含触发方式、条数与各渠道结果。</p>
          </div>
          <button class="btn btn-sm" @click="loadHistory">刷新</button>
        </div>
        <div v-if="!history.length" class="empty small">暂无推送记录。</div>
        <div v-else class="history">
          <div v-for="(h, i) in history.slice(0, 8)" :key="i" class="history-row">
            <div class="history-main">
              <span class="chip">{{ triggerLabel(h.trigger) }}</span>
              <b>{{ h.pushed }} / {{ h.selected }} 条</b>
              <span class="muted">{{ h.message }}</span>
            </div>
            <span class="history-time mono">{{ fmtTime(h.at) }}</span>
          </div>
        </div>
      </section>
    </template>

    <!-- ── 模板库 ──────────────────────────────── -->
    <section v-if="tab === 'nuclei'" class="panel panel-pad">
      <div class="section-head">
        <div>
          <h2 class="section-title">nuclei 模板库</h2>
          <p class="section-desc">上游模板增量同步与本地模板生成。模板目录可直接 <code>nuclei -l</code> 执行。</p>
        </div>
      </div>
      <div class="form-grid">
        <div class="field">
          <label>仓库</label>
          <input v-model.trim="nuclei.repo" placeholder="projectdiscovery/nuclei-templates" />
        </div>
        <div class="field">
          <label>分支</label>
          <input v-model.trim="nuclei.ref" placeholder="main" />
        </div>
        <div class="field">
          <label>单次同步入库上限</label>
          <input v-model.number="nuclei.sync_limit" type="number" min="0" max="5000" />
          <small>0 = 不限</small>
        </div>
        <div class="field">
          <label>远程抽样条数</label>
          <input v-model.number="nuclei.remote_limit" type="number" min="1" max="200" />
        </div>
      </div>
      <div class="check-grid" style="margin-top: 16px">
        <label class="check-row"><input v-model="nuclei.sync_enabled" type="checkbox" /><span>定时同步模板库增量</span></label>
        <label class="check-row"><input v-model="nuclei.fetch_remote" type="checkbox" /><span>流水线拉取远程模板</span></label>
        <label class="check-row"><input v-model="nuclei.gen_templates" type="checkbox" /><span>为收录漏洞生成模板</span></label>
      </div>
      <div class="actions">
        <button class="btn btn-primary" :disabled="busy" @click="saveMain">保存配置</button>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import {
  addSource, delSource, discoverSource, getPush, getSettings, listSources,
  pushHistory, purgeExpired, rebuildEnrich, runPush, savePush, saveSettings,
  testLlm, testPush,
} from './api'

const tabs = [
  { id: 'ai', label: 'AI 接口' },
  { id: 'collect', label: '采集与源' },
  { id: 'push', label: '情报推送' },
  { id: 'nuclei', label: '模板库' },
]
const tab = ref('push')
const channelTypes = [
  { value: 'wecom', label: '企业微信' },
  { value: 'dingtalk', label: '钉钉' },
  { value: 'feishu', label: '飞书' },
  { value: 'slack', label: 'Slack' },
  { value: 'telegram', label: 'Telegram' },
  { value: 'webhook', label: '通用 Webhook' },
]

const configFile = ref('')
const keySet = ref(false)
const githubTokenSet = ref(false)
const llm = ref({ base: '', key: '', model: '', timeout: 60 })
const collect = ref({ interval_minutes: 10, fetch_limit: 10, keep_days: 90, auto_translate: true, article_fetch: true })
const nuclei = ref({ repo: '', ref: 'main', sync_enabled: true, sync_limit: 0, remote_limit: 20, fetch_remote: false, gen_templates: true })
const enrich = ref({ enabled: true, epss: true, kev: true, nvd: true, github_advisory: true, timeout_seconds: 20, cache_hours: 24, github_token: '' })

const busy = ref(false)
const testing = ref(false)
const purging = ref(false)
const rebuilding = ref(false)
const msg = ref('')
const testMsg = ref('')
const purgeMsg = ref('')
const rebuildMsg = ref('')
const error = ref('')
const keyPlaceholder = ref('sk-...')

const builtin = ref([])
const custom = ref([])
const disabledIds = ref([])
const probeUrl = ref('')
const probeJudge = ref(true)
const probing = ref(false)
const probeMsg = ref('')
const cands = ref([])

const push = ref({
  enabled: false, min_score: 60, min_severity: '', require_cve: false, require_poc: false,
  max_per_batch: 10, cooldown_minutes: 30,
})
const channels = ref([])
const includeText = ref('')
const excludeText = ref('')
const newType = ref('wecom')
const savingPush = ref(false)
const testingPush = ref(false)
const runningPush = ref(false)
const pushResult = ref('')
const pushOk = ref(false)
const pushChannels = ref([])
const history = ref([])

const enabledBuiltin = computed(() => builtin.value.filter((s) => s.enabled).length)

function typeLabel(t) {
  return channelTypes.find((x) => x.value === t)?.label || t
}
function triggerLabel(t) {
  return { collect: '自动', manual: '手动', test: '测试', single: '单条' }[t] || t
}
function fmtTime(s) {
  if (!s) return '—'
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return String(s).replace('T', ' ').slice(0, 19)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
function splitList(s) {
  return (s || '').split(/[,，\n]/).map((x) => x.trim()).filter(Boolean)
}

async function loadSettings() {
  error.value = ''
  try {
    const s = await getSettings()
    llm.value = { ...s.llm, key: '' }
    collect.value = s.collect
    nuclei.value = s.nuclei
    enrich.value = { ...enrich.value, ...(s.enrich || {}), github_token: '' }
    githubTokenSet.value = !!s.enrich?.github_token
    configFile.value = s.config_file
    keySet.value = s.key_set
    keyPlaceholder.value = s.key_set ? '已配置，留空则不改动' : 'sk-...'
    disabledIds.value = s.sources?.disabled || []
  } catch (e) {
    error.value = e.message
  }
}

async function loadSources() {
  try {
    const r = await listSources()
    builtin.value = r.builtin || []
    custom.value = r.custom || []
  } catch (e) {
    error.value = e.message
  }
}

function toggleSource(id, enabled) {
  if (enabled) disabledIds.value = disabledIds.value.filter((x) => x !== id)
  else if (!disabledIds.value.includes(id)) disabledIds.value = [...disabledIds.value, id]
  const s = builtin.value.find((x) => x.id === id)
  if (s) s.enabled = enabled
}

async function saveMain() {
  busy.value = true
  msg.value = ''
  error.value = ''
  try {
    await saveSettings({
      llm: llm.value,
      collect: collect.value,
      nuclei: nuclei.value,
      enrich: enrich.value,
      sources: { custom: custom.value.map((s) => ({ name: s.name, url: s.url, enabled: s.enabled })), disabled: disabledIds.value },
    })
    msg.value = '配置已保存'
    await loadSettings()
    await loadSources()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
    setTimeout(() => (msg.value = ''), 3000)
  }
}

async function test() {
  testing.value = true
  testMsg.value = ''
  error.value = ''
  try {
    const r = await testLlm(llm.value)
    testMsg.value = `连通正常：${r.base} → ${r.model}（${r.reply}）`
  } catch (e) {
    error.value = e.message
  } finally {
    testing.value = false
  }
}

async function purge() {
  purging.value = true
  purgeMsg.value = ''
  error.value = ''
  try {
    const r = await purgeExpired()
    purgeMsg.value = r.removed ? `已清理 ${r.removed} 条` : '没有过期漏洞'
    await loadSettings()
  } catch (e) {
    error.value = e.message
  } finally {
    purging.value = false
  }
}

async function rebuild() {
  rebuilding.value = true
  rebuildMsg.value = ''
  error.value = ''
  try {
    const r = await rebuildEnrich()
    rebuildMsg.value = `已重算 ${r.updated} 条，其中高价值 ${r.high_value} 条`
  } catch (e) {
    error.value = e.message
  } finally {
    rebuilding.value = false
  }
}

async function probe() {
  probing.value = true
  probeMsg.value = ''
  cands.value = []
  error.value = ''
  try {
    const r = await discoverSource(probeUrl.value, probeJudge.value)
    if (!r.ok) {
      probeMsg.value = r.message
      return
    }
    cands.value = r.candidates.map((c) => ({ ...c, name: c.verdict.suggested_name || '' }))
    probeMsg.value = r.message
  } catch (e) {
    probeMsg.value = e.message
  } finally {
    probing.value = false
  }
}

async function attach(c) {
  busy.value = true
  error.value = ''
  try {
    await addSource({ name: c.name, url: c.url, enabled: true })
    cands.value = cands.value.filter((x) => x.url !== c.url)
    await loadSources()
    await loadSettings()
    msg.value = `已接入 ${c.name}`
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function remove(name) {
  busy.value = true
  error.value = ''
  try {
    await delSource(name)
    await loadSources()
    await loadSettings()
    msg.value = `已移除 ${name}`
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

// ── 推送配置 ─────────────────────────────────────
async function loadPush() {
  try {
    const p = await getPush()
    push.value = {
      enabled: !!p.enabled,
      min_score: p.min_score ?? 60,
      min_severity: p.min_severity || '',
      require_cve: !!p.require_cve,
      require_poc: !!p.require_poc,
      max_per_batch: p.max_per_batch ?? 10,
      cooldown_minutes: p.cooldown_minutes ?? 30,
    }
    includeText.value = (p.keywords_include || []).join(', ')
    excludeText.value = (p.keywords_exclude || []).join(', ')
    channels.value = (p.channels || []).map((c) => ({
      name: c.name || '',
      type: c.type || 'wecom',
      webhook: '',
      webhook_set: !!c.webhook_set,
      secret: '',
      secret_set: !!c.secret_set,
      enabled: !!c.enabled,
      chat_ids_text: (c.chat_ids || []).join(', '),
      channel: c.channel || '',
    }))
  } catch (e) {
    error.value = e.message
  }
}

function addChannel() {
  channels.value.push({
    name: '', type: newType.value, webhook: '', webhook_set: false,
    secret: '', secret_set: false, enabled: true, chat_ids_text: '', channel: '',
  })
}
function removeChannel(i) {
  channels.value.splice(i, 1)
}

async function savePushConfig() {
  savingPush.value = true
  pushResult.value = ''
  error.value = ''
  try {
    await savePush({
      enabled: push.value.enabled,
      min_score: Number(push.value.min_score),
      min_severity: push.value.min_severity,
      require_cve: push.value.require_cve,
      require_poc: push.value.require_poc,
      max_per_batch: Number(push.value.max_per_batch),
      cooldown_minutes: Number(push.value.cooldown_minutes),
      keywords_include: splitList(includeText.value),
      keywords_exclude: splitList(excludeText.value),
      channels: channels.value.map((c) => ({
        name: c.name,
        type: c.type,
        webhook: c.webhook || '',
        secret: c.secret || '',
        enabled: !!c.enabled,
        chat_ids: splitList(c.chat_ids_text),
        channel: c.channel || '',
      })),
    })
    pushOk.value = true
    pushResult.value = '推送配置已保存'
    await loadPush()
  } catch (e) {
    pushOk.value = false
    pushResult.value = e.message
  } finally {
    savingPush.value = false
  }
}

async function testPushConfig() {
  testingPush.value = true
  pushResult.value = ''
  pushChannels.value = []
  try {
    const r = await testPush()
    pushOk.value = r.pushed > 0
    pushResult.value = r.message || '测试完成'
    pushChannels.value = r.channels || []
    await loadHistory()
  } catch (e) {
    pushOk.value = false
    pushResult.value = e.message
  } finally {
    testingPush.value = false
  }
}

async function runPushNow() {
  runningPush.value = true
  pushResult.value = ''
  pushChannels.value = []
  try {
    const r = await runPush()
    pushOk.value = r.pushed > 0
    pushResult.value = r.message || '推送完成'
    pushChannels.value = r.channels || []
    await loadHistory()
  } catch (e) {
    pushOk.value = false
    pushResult.value = e.message
  } finally {
    runningPush.value = false
  }
}

async function loadHistory() {
  try {
    const r = await pushHistory()
    history.value = r.items || []
  } catch { /* 历史是辅助信息 */ }
}

onMounted(() => {
  loadSettings()
  loadSources()
  loadPush()
  loadHistory()
})
</script>

<style scoped>
.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.page-head h1 { font-size: 26px; margin: 4px 0 5px; letter-spacing: -0.01em; }
.page-sub { margin: 0; color: var(--muted); font-size: 12.5px; }
.page-sub code { background: #f2f4f7; padding: 1px 6px; border-radius: 5px; font-family: var(--mono); font-size: 11.5px; }
.head-actions { display: flex; align-items: center; gap: 8px; }
.inline { display: inline-flex; align-items: center; }

.tabs { display: flex; gap: 6px; margin-bottom: 14px; overflow-x: auto; scrollbar-width: none; }
.tabs::-webkit-scrollbar { display: none; }
.tab {
  flex: none; background: transparent; border: 1px solid transparent; color: var(--muted);
  padding: 7px 14px; border-radius: 9px; font-size: 13px; font-weight: 550; cursor: pointer;
}
.tab:hover { color: var(--text); background: var(--surface-hover); }
.tab.on { background: var(--panel-2); border-color: var(--line-strong); color: var(--text); }

section.panel { margin-bottom: 14px; }
.section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 16px; }
.form-grid .span-2 { grid-column: span 2; }
.check-grid { display: flex; flex-wrap: wrap; gap: 12px 26px; }
.actions { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; margin-top: 18px; }
.actions .notice { margin-left: 4px; }

.sub-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin: 22px 0 12px; flex-wrap: wrap; }
.sub-head h3 { font-size: 13px; margin: 0; font-weight: 620; white-space: nowrap; }

.source-list { display: flex; flex-direction: column; border: 1px solid var(--line); border-radius: 11px; overflow: hidden; }
.source-row { display: flex; align-items: center; gap: 14px; padding: 13px 15px; border-bottom: 1px solid var(--line); }
.source-row:last-child { border-bottom: 0; }
.source-row:hover { background: #fafbfc; }
.source-main { flex: 1; min-width: 0; }
.source-title { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
.source-title b { font-size: 13px; }
.source-url { display: block; font-size: 11px; color: var(--dim); word-break: break-all; margin-top: 2px; }
.source-desc { margin: 3px 0 0; font-size: 11.5px; color: var(--muted); }
.source-row .switch { flex: none; }

.custom-list { display: flex; flex-direction: column; gap: 8px; }
.custom-row { display: flex; align-items: center; justify-content: space-between; gap: 12px;
  border: 1px solid var(--line); border-radius: 9px; padding: 10px 13px; }
.custom-main { min-width: 0; }
.custom-main b { display: block; font-size: 12.5px; }
.custom-main a { font-size: 11px; color: var(--dim); word-break: break-all; }
.none { color: var(--dim); font-size: 12px; }

.probe { margin-top: 20px; border-top: 1px dashed var(--line); padding-top: 16px; display: flex; flex-direction: column; gap: 12px; }
.probe-row { display: flex; gap: 8px; }
.probe-row input { flex: 1; }
.cands { display: flex; flex-direction: column; gap: 10px; }
.cand { border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; background: #fafbfc; }
.cand-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.cand-actions { display: flex; gap: 8px; margin-top: 10px; }
.cand-actions input { flex: 1; }

/* 推送渠道 */
.add-channel { display: flex; align-items: center; gap: 8px; }
.add-channel select { width: auto; min-width: 130px; padding: 6px 10px; }
.empty.small { padding: 26px 12px; }
.channel-card { border: 1px solid var(--line); border-radius: 11px; padding: 14px 16px; margin-bottom: 10px; background: #fcfcfd; }
.channel-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.channel-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.channel-title b { font-size: 13px; }
.channel-ops { display: flex; align-items: center; gap: 10px; }
.push-actions { border-top: 1px dashed var(--line); padding-top: 16px; margin-top: 18px; }
.push-channels { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }

.history { display: flex; flex-direction: column; }
.history-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--line); }
.history-row:last-child { border-bottom: 0; }
.history-main { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; font-size: 12px; }
.history-main b { font-size: 12.5px; }
.history-time { font-size: 11px; color: var(--dim); flex: none; }

@media (max-width: 640px) {
  .page-head { flex-direction: column; align-items: flex-start; }
  .section-head { flex-direction: column; }
  .form-grid .span-2 { grid-column: auto; }
  .probe-row { flex-direction: column; }
  .channel-head { align-items: flex-start; }
  .channel-ops { flex-direction: column; align-items: flex-end; }
  .history-row { flex-direction: column; align-items: flex-start; gap: 4px; }
  .add-channel { width: 100%; }
  .add-channel select { flex: 1; }
  .sub-head { align-items: flex-start; }
}
</style>
