# SocradarBot 接口清单

服务默认地址 `http://127.0.0.1:8100`，CORS 全开放，无鉴权（内网工具定位，对外请置于反向代理并加认证）。
错误约定：业务错误返回 `{"detail": "<可读原因>"}`；参数校验失败返回 400（旧版为 422，详见兼容性说明）。

**总计 31 个接口**：旧版 22 个全部保留，新增 9 个。

## 兼容性总览

| # | 方法 | 路径 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | GET | `/api/vulns` | 兼容 + 扩展 | 新增 `high_value` / `min_score` / `q` / `unpushed` 过滤 |
| 2 | GET | `/api/vulns/{vid}` | 兼容 + 扩展 | 返回新增富化字段 |
| 3 | POST | `/api/vulns/{vid}/poc` | 兼容 | |
| 4 | POST | `/api/vulns/{vid}/translate` | 兼容 | |
| 5 | POST | `/api/vulns/{vid}/nuclei` | 兼容 | |
| 6 | POST | `/api/vulns/purge` | 兼容 | |
| 7 | POST | `/api/translate/backfill` | 兼容 | |
| 8 | POST | `/api/collect` | 兼容 + 扩展 | 返回值新增 `enriched` / `high_value` / `push` |
| 9 | GET | `/api/collect/status` | 兼容 | |
| 10 | GET | `/api/nuclei/sync` | 兼容 | |
| 11 | POST | `/api/nuclei/sync` | 兼容 | |
| 12 | GET | `/api/nuclei/templates` | 兼容 | |
| 13 | GET | `/api/nuclei/remote` | 兼容 | 支持 `enrich.github_token` |
| 14 | POST | `/api/nuclei/pull` | 兼容 | |
| 15 | GET | `/api/settings` | 兼容 + 扩展 | 新增 `enrich` / `push` 节 |
| 16 | POST | `/api/settings` | 兼容 | 未知配置项返回 400 |
| 17 | POST | `/api/settings/test` | 兼容 | |
| 18 | GET | `/api/sources` | 兼容 | |
| 19 | POST | `/api/sources/discover` | 兼容 | |
| 20 | POST | `/api/sources` | 兼容 | |
| 21 | DELETE | `/api/sources/{name}` | 兼容 | |
| 22 | GET | `/api/llm/status` | 兼容 | |
| 23 | GET | `/api/health` | 新增 | 健康检查 |
| 24 | GET | `/api/stats` | 新增 | 总览统计 |
| 25 | POST | `/api/enrich/rebuild` | 新增 | 存量重新富化与评分 |
| 26 | GET | `/api/push` | 新增 | 推送配置（脱敏） |
| 27 | POST | `/api/push` | 新增 | 推送配置局部更新 |
| 28 | POST | `/api/push/test` | 新增 | 测试消息 |
| 29 | POST | `/api/push/run` | 新增 | 手动推送待推队列 |
| 30 | GET | `/api/push/history` | 新增 | 推送历史 |
| 31 | POST | `/api/vulns/{vid}/push` | 新增 | 单条手动推送 |

---

## 一、系统

### GET `/api/health`

返回：`{"ok":true,"name":"SocradarBot","version":"1.2.0","time":"2026-10-20T16:21:07+08:00"}`

### GET `/api/stats`

返回：
```json
{
  "total": 44, "high_value": 18, "unpushed_high_value": 0, "today": 44, "kev": 7, "poc": 56,
  "translated": 19, "pending_translate": 25,
  "by_source": {"cisa-kev": 7, "nvd": 8, "seebug": 10},
  "templates": 22,
  "collect_running": false, "sync_running": false, "last_collect": "2026-10-20T16:24:05",
  "push_enabled": true, "push_channels": 1, "llm_available": false, "version": "1.0.0"
}
```

### POST `/api/enrich/rebuild`

无请求体。对全库重新提取 CVE、查询 EPSS/KEV、推断严重性并重算评分。
返回：`{"total":44,"updated":44,"high_value":18,"failed":0}`。用于旧数据迁移或调整推送规则后重算。

---

## 二、漏洞

### GET `/api/vulns`

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `page` | int | 1 | 页码，越界收敛 |
| `page_size` | int | 10 | 1–100 |
| `source` | str | `""` | 来源筛选；`全部` = 不过滤 |
| `high_value` | bool | false | `1`/`true` 只看高价值 |
| `min_score` | int | 0 | 最低风险分 |
| `q` | str | `""` | 关键词（名称/摘要/CVE） |
| `severity` | str | `""` | 精确等级：critical/high/medium/low/info |
| `vendor` | str | `""` | 厂商/产品/影响范围模糊匹配 |
| `kev` | bool | false | 只看 CISA KEV |
| `poc` | bool | false | 只看有利用代码或 PoC 已公开 |
| `sort` | str | `latest` | latest / score / cvss / published |
| `unpushed` | bool | false | 只看未推送 |

返回：`items[] / total / page / pages / page_size / all_total / counts{} / high_value_total`。
`items[]` 字段：`id,name,source,summary,published,cvss,severity,cves,translated,has_nuclei,entry_date,entry_iso,epss,kev,poc,score,high_value,pushed,tags,affected_products`。其中 `poc` 表示「有利用代码或 PoC 已公开」，不包含 nuclei 检测模板。
排序：`entry_iso` 倒序；`entry_date` 对仅有年份的 CVE 只显示 `YYYY`。

### GET `/api/vulns/{vid}`

返回完整 meta + `poc` 全文 + `nuclei_yaml` 全文。404 `{"detail":"漏洞不存在"}`。

字段说明：

| 字段 | 说明 |
| --- | --- |
| `severity` | `critical/high/medium/low/info/unknown` |
| `severity_inferred` | 严重性是否由 CVSS/关键词推断 |
| `cves[]` | 关联 CVE |
| `cvss` | 分值，可能为 null |
| `epss` / `epss_percentile` | 利用概率预测 |
| `kev` / `kev_date` / `known_ransomware` | CISA KEV 标记 |
| `affected_products[]` | 影响产品/包 |
| `cwe[]` | 弱点类型 |
| `score` / `high_value` / `score_reasons[]` | 风险分、高价值标记、判定依据 |
| `pushed` / `pushed_at` / `push_skip_reason` | 推送状态 |
| `poc_source` | `article`（原文提取）/`ai`（生成）/`nuclei`（模板库）/`none` |
| `poc_disclosed` | 情报源标注 PoC/EXP 已公开（TI `POC公开`、OSCS `is_poc`、长亭 `poc_id`） |
| `translated` | 是否已中文化 |

### POST `/api/vulns/purge`

按 `collect.keep_days` 清理。`keep_days<=0` 时 400。
返回：`{"removed":0,"ids":[],"failed":[]}`。

---

## 三、采集

### POST `/api/collect`

无请求体（body 可为空）。与定时任务互斥。
返回：
```json
{
  "fetched": 50, "kept": 15, "skipped": 30, "expired": 5,
  "enriched": 15, "translated": 0, "high_value": 14,
  "nuclei_ok": 0, "nuclei_skipped": 0,
  "by_source": {"cisa-kev": 7, "nvd": 8},
  "source_errors": {"github-advisory": "HTTP 403"},
  "push": {"selected": 5, "pushed": 5, "skipped": 0, "channels": [{"name":"mock","type":"webhook","ok":true}], "items": [...], "message": "已推送 5 条至 1 个渠道"}
}
```
并发触发时返回 `{"skipped":true,"reason":"已有抓取任务在运行"}`。

### GET `/api/collect/status`

返回：`{"running":false,"last_run":"","last_result":null,"interval_minutes":10,"next_run":""}`。

---

## 四、nuclei 双向通道

### GET `/api/nuclei/sync`

返回：`{"repo": "...","cloned": true,"last_commit":"...","last_commit_short":"...","last_sync":"...","last_imported":7,"local_templates":13868,"running":false,"last_run":"","last_result":null}`。

### POST `/api/nuclei/sync`

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `full` | bool | false | 忽略上次同步点全量重扫 |
| `limit` | int | 0 | 本次最多入库条数，0 = 不限 |

返回：`{"changed":15,"from_commit":"...","to_commit":"...","imported":12,"skipped":2,"failed":0,"expired":0,"translated":10,"files":["nuclei-xxx"]}`。
git 不可用/网络异常时返回 `{"error":"...","imported":0,"files":[]}`（HTTP 200，便于前端提示）。
首次同步只建立基线、不导入 1.3w 存量。

### GET `/api/nuclei/templates`

返回：`{"dir":"...","items":[{"id","vid","name","severity","tags","file","requests"}]}`，critical/high 优先。

### GET `/api/nuclei/remote`

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `limit` | 10 | 条数 |
| `severity` | `""` | 精确过滤 |
| `tag` | `""` | 路径子串过滤 |

返回：`{"repo":"...","ref":"main","items":[{"id","name","severity","description","tags","path","refs"}]}`。
失败 502；GitHub 匿名限流时提示配置 `enrich.github_token`。索引缓存 6 小时。

### POST `/api/nuclei/pull`

请求：`{"limit":20,"severity":"critical","tag":""}`。
返回：`{"fetched":20,"saved":["nuclei-..."],"skipped":[],"expired":1}`；失败 502。

### POST `/api/vulns/{vid}/nuclei`

请求：`{"allow_write": false}`。
返回：`{"ok":true,"origin":"llm|heuristic","yaml":"id: ..."}`；无法生成时 `{"ok":false,"reason":"...","origin":"..."}`（HTTP 200）。
404 漏洞不存在；400 条目本身来自模板库；写操作模板未授权时 `ok=false` 并说明原因。

---

## 五、AI 加工

| 接口 | 请求 | 成功返回 | 失败 |
| --- | --- | --- | --- |
| POST `/api/vulns/{vid}/poc` | 无 | `{"ok":true,"chars":1024}` | 502；404 |
| POST `/api/vulns/{vid}/translate` | 无 | `{"ok":true,"name":"…","summary":"…","principle":"…"}` 或 `{"ok":true,"skipped":true,"message":"已是中文"}` | 502；404 |
| POST `/api/translate/backfill` | `{"limit":20,"ids":["…"]}`（ids ≤20） | `{"ok":8,"skipped":2,"failed":[{"id":"…","reason":"…"}],"ids":[],"names":[]}` | — |
| GET `/api/llm/status` | 无 | `{"available":false,"model":"…","base":"…","key_set":false,"pending_translate":25}` | — |

LLM 未配置时：`poc`/`translate` 返回 502 并说明；`backfill` 逐条记录 `failed` 原因。

---

## 六、设置

### GET `/api/settings`

返回 `llm`（`key` 脱敏）、`collect`、`nuclei`、`enrich`（`github_token` 脱敏）、`sources`、`push`（`webhook`/`secret` 脱敏，附 `webhook_set`/`secret_set`）、`config_file`、`key_set`。

### POST `/api/settings`

请求体为任意子集：`{"llm":{...},"collect":{...},"nuclei":{...},"enrich":{...},"push":{...},"sources":{...}}`。
- 深度合并，未提交字段保持原值
- `llm.key` / `llm.base` 传空串 = 保持原值（避免前端空传清掉密钥）
- 未知配置节/键 → 400 `{"detail":"未知配置项：…"}`
- 推送渠道回传脱敏 webhook（含 `****`）时自动还原为已保存值

返回：`{"ok":true,"config_file":"...","llm":{...}}`。

### POST `/api/settings/test`

请求：`{"llm":{"base":"","key":"","model":""}}`（均可省略，空值为"用已存值"）。
返回：`{"ok":true,"reply":"pong","model":"...","base":"..."}`；失败 502 `{"detail":"连接失败：…"}`。

---

## 七、漏洞源

### GET `/api/sources`

返回内置源目录（`builtin:true`，共 9 个，含启停状态与来源类型）与自定义源（`builtin:false`）：
```json
{
  "builtin": [
    {"name":"长亭漏洞库","url":"https://stack.chaitin.com/vuldb/index","builtin":true,
     "id":"chaitin","kind":"json","description":"CT Stack 公开 API…","enabled":true}
  ],
  "custom": [{"name":"某社区","url":"https://example.com/feed","enabled":true,"builtin":false}]
}
```
启停内置源：在 `/api/settings` 提交 `sources.disabled=["oscs"]`（或控制台「配置 → 采集与源」开关）。

### POST `/api/sources/discover`

请求：`{"url":"https://xz.aliyun.com","llm_judge":true}`。
返回：
```json
{"ok":true,"best":"https://xz.aliyun.com/feed","message":"找到 2 个 feed",
 "candidates":[{"url":"...","entries":20,"titles":["..."],
   "verdict":{"is_vuln_source":true,"reason":"...","suggested_name":"先知","by_llm":true}}]}
```
未找到：`{"ok":false,"message":"...","tried":["/feed","/rss",...],"candidates":[]}`。不写配置。

### POST `/api/sources`

请求：`{"name":"先知","url":"https://xz.aliyun.com/feed","enabled":true}`；同名视为更新。
返回：`{"ok":true,"sources":[...],"message":"已接入 先知，下一轮抓取生效"}`；非法地址/空名称 400。

### DELETE `/api/sources/{name}`

返回：`{"ok":true,"sources":[...],"message":"已移除 先知"}`；不存在 404。

---

## 八、推送

### GET `/api/push`

返回推送配置（webhook/secret 脱敏）+ `pending`（待推条数）：
```json
{
  "enabled": true, "min_score": 60, "min_severity": "high",
  "require_cve": false, "require_poc": false,
  "keywords_include": [], "keywords_exclude": [],
  "max_per_batch": 10, "cooldown_minutes": 30,
  "channels": [{"name":"安全群","type":"wecom","enabled":true,
                "webhook":"https://qyapi****abcd","webhook_set":true,
                "secret":"","secret_set":false,"chat_ids":[],"channel":""}],
  "pending": 3
}
```

### POST `/api/push`

请求体为 `Push` 配置的任意子集，**局部更新**（与现有配置深度合并）。
渠道按 `name` 匹配，`webhook` 传空或含 `****` 时保留原值。
返回：脱敏后的完整配置 + `ok:true`。校验失败 400（如启用渠道缺 webhook、min_score 越界、类型非法）。

### POST `/api/push/test`

向所有启用渠道发送一条测试消息。返回：
`{"selected":1,"pushed":1,"skipped":0,"channels":[{"name":"mock","type":"webhook","ok":true}],"items":[...],"message":"测试消息已发送：成功 1 / 1 个渠道"}`。

### POST `/api/push/run`

立即执行一次待推队列（与定时采集后的推送逻辑一致）。
返回：`{"selected":5,"pushed":5,"skipped":0,"channels":[...],"items":[...],"message":"已推送 5 条至 1 个渠道"}`。
未启用 push 或未配置渠道时返回对应 `message`，不报错。

### GET `/api/push/history`

返回最近 100 条：`{"items":[{"at":"...","trigger":"collect|manual|test|single","selected":5,"pushed":5,"channels":[...],"items":[...],"message":"..."}]}`。

### POST `/api/vulns/{vid}/push`

单条推送（不受 `high_value` 限制，但受渠道配置限制）。返回结构同上；404 漏洞不存在。

---

## 九、静态资源

`GET /` 返回 `web/dist` 中的前端；未构建时返回 API 导航页。未匹配的 `/api/*` 返回 404 JSON，其余路径回退到 `index.html`（SPA 路由）。

---

## 十、迁移差异（旧版 → Go 版）

| 项 | 旧版 | Go 版 | 影响 |
| --- | --- | --- | --- |
| 校验错误码 | 422 + 数组 detail | 400 + 字符串 detail | 前端 `api.js` 读取 `detail` 字符串，兼容 |
| 列表响应 | 9 个字段 | 追加 9 个富化字段 | 旧前端忽略未知字段，无影响 |
| `/api/settings` | 4 节 | 增加 `enrich`、`push` | 旧前端只读提交已知节，无影响 |
| 采集返回 | 6 个字段 | 增加 `enriched`、`high_value`、`push`、`by_source`、`source_errors` | 兼容 |
| 同步返回 | 8 个字段 | 增加 `imported`、`skipped`、`translated` 等 | 兼容 |
| 错误响应 | FastAPI `detail` | 相同 | 兼容 |
| 数据文件 | `meta.json` | 同名同结构，新增字段可省略 | 双向兼容 |

完整迁移步骤见 [`MIGRATION.md`](MIGRATION.md)。
