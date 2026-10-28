# 从 ai_bobao（Python）迁移到 SocradarBot（Go）

本次重构保持**数据格式与接口契约**不变，迁移可以做到不停机切换、可随时回滚。以下按执行顺序说明。

## 1. 数据迁移

目录结构完全一致，直接复制即可：

```bash
# 旧版
ai_bobao/backend/data/
├── vulns/{ID}/meta.json
├── vulns/{ID}/poc.py
├── vulns/{ID}/nuclei.yaml
├── nuclei_tpl/*.yaml
├── nuclei_sync.json
└── nuclei_cache/
```

```bash
mkdir -p /opt/socradarbot
cp -a ai_bobao/backend/data /opt/socradarbot/data
```

Go 版读取 `meta.json` 时，缺失的新字段（`severity`、`cves`、`score`、`high_value`、`pushed` 等）自动取零值，不会报错。
启动后执行一次存量补全：

```bash
curl -X POST http://127.0.0.1:8100/api/enrich/rebuild
# {"total":44,"updated":44,"high_value":18,"failed":0}
```

该接口会重新提取 CVE、查询 EPSS/KEV、推断严重性并重算评分，同时按当前推送规则更新 `high_value`。实测 44 条耗时 < 1 秒（EPSS 批量查询另有网络耗时）。

> nuclei 仓库目录 `data/nuclei_templates` 可保留，Go 版会复用同一 git 工作区与 `nuclei_sync.json` 的 `last_commit`。

## 2. 配置迁移

`config.yaml` 的 `llm` / `collect` / `nuclei` / `sources` 四节**键名完全一致**，可直接沿用。
新增两节（不写则使用默认值）：

```yaml
enrich:
  enabled: true
  epss: true
  kev: true
  github_advisory: true
  nvd: true
  timeout_seconds: 20
  cache_hours: 24
  github_token: ""

push:
  enabled: false
  min_score: 60
  min_severity: ""
  require_cve: false
  require_poc: false
  keywords_include: []
  keywords_exclude: []
  max_per_batch: 10
  cooldown_minutes: 30
  channels: []
```

差异点：

| 旧配置 | 新配置 | 说明 |
| --- | --- | --- |
| `collect.*` | 不变 | 新增 `article_fetch`、`timeout_seconds`（有默认值）；`keep_days` 默认由 60 调整为 90 |
| `nuclei.*` | 不变 | 语义一致 |
| `sources.custom` | 不变 | 结构 `{name,url,enabled}` |
| — | `sources.disabled` | 新增：按 ID 停用内置源 |
| — | `enrich.*` | 新增：富化数据源开关 |
| — | `push.*` | 新增：高价值推送策略 |

环境变量：新前缀 `SOCRADARBOT_*`，并**同时读取旧前缀** `AI_BAOBAO_*`，容器编排里的旧变量无需立即修改：

| 旧变量 | 新变量（优先级更高） |
| --- | --- |
| `AI_BAOBAO_LLM_KEY` | `SOCRADARBOT_LLM_KEY` |
| `AI_BAOBAO_LLM_BASE` | `SOCRADARBOT_LLM_BASE` |
| `AI_BAOBAO_LLM_MODEL` | `SOCRADARBOT_LLM_MODEL` |
| `AI_BAOBAO_INTERVAL_MINUTES` | `SOCRADARBOT_INTERVAL_MINUTES` |
| `AI_BAOBAO_KEEP_DAYS` | `SOCRADARBOT_KEEP_DAYS` |
| `AI_BAOBAO_AUTO_TRANSLATE` | `SOCRADARBOT_AUTO_TRANSLATE` |
| `AI_BAOBAO_NUCLEI_SYNC` / `_GEN` | `SOCRADARBOT_NUCLEI_SYNC` / `_GEN` |
| — | `SOCRADARBOT_GITHUB_TOKEN`（也读 `GITHUB_TOKEN`） |
| — | `SOCRADARBOT_PUSH_ENABLED` / `_MIN_SCORE` |

## 3. 接口兼容性

22 个旧接口的路径、方法、请求参数与返回字段均保持不变，前端 `api.js` 无需修改即可工作。差异：

| 项 | 旧版 | Go 版 | 处理建议 |
| --- | --- | --- | --- |
| 参数校验失败 | HTTP 422，`detail` 为数组 | HTTP 400，`detail` 为字符串 | 前端已按字符串读取；若有自研客户端，请兼容 400 |
| 列表字段 | 9 个 | 追加 `severity/cves/epss/kev/score/high_value/pushed/tags` | 未知字段可忽略 |
| 列表过滤 | 3 个参数 | 追加 `high_value/min_score/q/unpushed` | 可选使用 |
| `/api/settings` | 4 节 | 追加 `enrich`、`push`；未知键报 400 | 旧前端提交的节不受影响 |
| `/api/collect` 返回 | 6 个字段 | 追加 `enriched/high_value/push/by_source/source_errors` | 兼容 |
| `/api/nuclei/sync` 返回 | 8 个字段 | 追加 `imported/skipped/translated` | 兼容 |
| 404/400 文案 | 中文 | 中文，措辞略有调整 | 仅展示差异 |

新增 9 个接口（健康检查、统计、存量富化、推送管理）见 [`API.md`](API.md)。

## 4. 行为差异（需知悉）

1. **严重性补齐**：旧版文章类条目的 `severity` 为空；Go 版会按 CVSS 或中英文关键词推断，并标记 `severity_inferred=true`。这是评分与推送的基础。
2. **新增数据源**：默认启用 `cisa-kev`、`nvd`、`github-advisory`。若不需要，设 `enrich.kev=false` 等。
3. **NVD 默认开启**：每轮仅 1 次请求、最多 10 条，无 token 时受 5 次/30s 限流；高频部署建议关闭或配 token。
4. **GHSA 匿名限流**：共享出口 IP 很容易 403，日志会记录在 `source_errors`；生产建议配置 `enrich.github_token`。
5. **KEV 403 回退**：CISA 官网在部分网络被 CDN 拒绝，自动切换官方 GitHub 镜像 `cisagov/kev-data`，无需配置。
6. **推送**：默认关闭；开启后每轮采集结束自动推送，失败条目下一轮重试。
7. **调度**：首轮仍在启动 10s 后；单轮顺序为「模板同步 → 采集 → 过期清理」，与旧版一致。
8. **模板生成**：无 LLM 时走启发式（从 PoC 提取路径与判定关键词），仍会拦截写操作模板。
9. **错误码统一**：所有业务错误优先返回可读中文；同步/远程类的上游异常在部分接口以 HTTP 200 + `error` 字段返回（与旧版一致）。

## 5. 切换步骤（建议）

```bash
# 1) 停旧服务（保留数据目录）
systemctl stop ai_bobao

# 2) 备份数据
tar czf data-backup-$(date +%F).tgz /opt/ai_bobao/backend/data

# 3) 部署 Go 版
mkdir -p /opt/socradarbot && cd /opt/socradarbot
# 放入 socradarbot、web/dist、config.example.yaml
cp config.example.yaml config.yaml
# 按旧 config.yaml 填写 llm / collect / nuclei / sources

# 4) 复制数据并启动
cp -a /opt/ai_bobao/backend/data /opt/socradarbot/data
./socradarbot -addr 0.0.0.0:8100 -web web/dist

# 5) 验证
curl localhost:8100/api/health
curl localhost:8100/api/stats
curl -X POST localhost:8100/api/enrich/rebuild
curl -X POST localhost:8100/api/push/test    # 配置推送渠道后
```

前端若仍用 Vite 开发模式，代理目标保持 `http://127.0.0.1:8100` 不变。

## 6. 回滚

Go 版只是**追加**了 meta 字段，旧 Python 版读取时会忽略未知键，因此可直接回滚：

```bash
systemctl stop socradarbot
systemctl start ai_bobao      # 旧服务指向同一 data 目录
```

注意：Go 版在 `data/cache/` 下新增 KEV/EPSS 缓存、在 `data/push_history.json` 记录推送历史，这些文件旧版不会读取，可保留。

## 7. 常见问题

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `source_errors.cisa-kev: HTTP 403` | 官网 CDN 拦截 | 已自动回退镜像；若仍失败检查出网策略 |
| `source_errors.github-advisory: HTTP 403` | 匿名 API 限流 | 配置 `enrich.github_token` |
| `source_errors.nvd: HTTP 403/429` | NVD 限流 | 降低频率或关闭 `enrich.nvd` |
| 推送无反应 | `push.enabled=false` 或无启用渠道 | `curl -X POST /api/push/test` 查看各渠道结果 |
| 模板同步报 git 未找到 | 容器内未安装 git | `apk add git` 或挂载宿主机 git |
| 页面空白 | `-web` 指向错误 | 确认 `web/dist/index.html` 存在 |
