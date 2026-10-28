# SocradarBot

**AI 赋能的漏洞情报聚合与高价值推送服务（Go 实现）**

由 `ai_bobao`（Python 3.11 + FastAPI）重构而来：保留原有漏洞采集、AI 补全、nuclei 双向通道与 Web 控制台，后端整体迁移到 Go 单二进制；并按 [watchvuln](https://github.com/zema1/watchvuln) 的设计思路增强两块能力 —— **原始数据富化** 与 **高价值情报识别/推送**。

- 单一静态二进制（约 7 MB），无数据库、无 Python 运行时依赖
- 文件式存储与旧版完全兼容，`data/` 可直接沿用
- 旧版 **22 个接口全部保留**，新增 9 个（统计 / 存量富化 / 推送管理），前端无需改动
- **9 个内置情报源**：3 个 RSS + 长亭 / OSCS / 奇安信 TI 三个结构化 API + KEV / NVD / GitHub Advisory
- 采集、富化、评分、推送全链路可配置，推送规则可解释（每条情报都带 `score_reasons`）
- Web 控制台支持推送渠道与规则的可视化配置，桌面与移动端自适应

[![在线预览](https://img.shields.io/badge/Online%20Preview-socradarbot.million.cc.cd-7A1B3D)](https://socradarbot.million.cc.cd)
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/secjoker/socradarbot)

![情报流](https://socradarbot.million.cc.cd/screenshots/feed.png)

## 在线预览（只读）

- **演示地址**：<https://socradarbot.million.cc.cd>
- **实现方式**：Cloudflare Workers 绑定静态资源（`web/dist`），`deploy/cloudflare/worker.js` 提供脱敏演示 API
- **只读限制**：抓取、保存设置、推送、生成 PoC/模板等写操作统一返回 403；样本数据不含 PoC 代码与模板正文
- **一键部署**：点击上方 Deploy to Cloudflare 按钮，或执行 `npx wrangler deploy`（详见 [`docs/DEPLOY_CLOUDFLARE.md`](docs/DEPLOY_CLOUDFLARE.md)）

---

## 一、架构

```
                    ┌──────────────────────────── 数据源 ────────────────────────────┐
                    │ RSS: seebug / 先知 / exploit-db / 自定义社区                    │
                    │ CISA KEV（已知在野利用，官方 GitHub 镜像回退）                   │
                    │ NVD CVE 2.0（CVSS / CPE 影响范围 / CWE）                       │
                    │ GitHub Security Advisory（CVSS / 受影响包，建议配 token）        │
                    └───────────────────────────┬──────────────────────────────────┘
                                                │ 并发抓取（单源失败不影响整体）
                                                ▼
   ┌─────────────┐   归一化/去重    ┌──────────────────┐   CVE/EPSS/KEV/severity   ┌────────────┐
   │  crawler    │ ───────────────► │  source registry │ ────────────────────────► │  enrich    │
   │ 正文+PoC    │                  │  统一 Item        │                           │  风险评分   │
   └─────────────┘                  └──────────────────┘                           └─────┬──────┘
                                                                                        │
        ┌───────────────────────────────────────────────────────────────────────────────┘
        ▼
   ┌──────────┐   LLM 可用时补全情报/PoC/中文化    ┌──────────────┐
   │ pipeline │ ─────────────────────────────────► │ nuclei 通道   │  生成模板 / git 增量同步 / 远程抽样
   └────┬─────┘                                   └──────┬───────┘
        │                                                │
        ▼                                                ▼
   ┌─────────────────────────┐                  ┌──────────────────────┐
   │ store（文件库）          │                  │ data/nuclei_tpl/     │ 可直接 nuclei -l 执行
   │ data/vulns/{id}/meta... │                  └──────────────────────┘
   └────┬────────────────────┘
        │ high_value && !pushed
        ▼
   ┌─────────────────────────┐   wecom / dingtalk / feishu / slack / telegram / webhook
   │ push manager（多通道）   │ ────────────────────────────────────────────────────────►
   └─────────────────────────┘   规则判定 · CVE 去重 · 冷却窗口 · 分片发送 · 历史留痕
```

**定时调度**：启动 10s 后首轮，之后每 `collect.interval_minutes` 分钟执行「模板增量同步 → 采集（含推送）→ 过期清理」。手动触发与定时任务通过互斥锁防止并发撞车。

---

## 二、目录结构

```
socradarbot/
├── cmd/socradarbot/main.go       入口：参数、HTTP 服务、优雅退出
├── internal/
│   ├── api/                      31 个 HTTP 接口 + 静态资源托管
│   ├── config/                   默认值 < config.yaml < 环境变量；原子写回
│   ├── model/                    Vuln / Item / ListItem 数据结构
│   ├── store/                    文件存储（与旧版 data/ 兼容）
│   ├── source/                   多源采集：RSS / KEV / NVD / GHSA
│   ├── crawler/                  RSS 解析、正文抓取、PoC 提取、feed 探测
│   ├── enrich/                   CVE/EPSS/KEV/严重性/评分
│   ├── llm/                      OpenAI 兼容客户端与 5 类提示词
│   ├── nuclei/                   模板解析/生成、git 增量同步、远程抽样
│   ├── pipeline/                 采集/同步/翻译/PoC/重富化编排
│   ├── push/                     高价值判定、去重、多渠道发送、历史
│   └── scheduler/                定时任务
├── web/                          Vue3 控制台（构建产物 web/dist 由二进制托管）
├── docs/API.md                   接口清单（含兼容性说明）
├── docs/MIGRATION.md             从 Python 版迁移的完整步骤
├── scripts/                      冒烟测试 / 端到端测试 / mock webhook
├── config.example.yaml
├── Dockerfile
└── go.mod
```

---

## 三、快速开始

前置：Go 1.22+；仅改前端时需要 Node 18+。

```bash
# 1. 构建后端（Windows 产物 socradarbot.exe）
go build -trimpath -ldflags "-s -w" -o bin/socradarbot ./cmd/socradarbot

# 2. 构建前端（仓库已含 web/dist 时跳过）
cd web && npm ci && npm run build && cd ..

# 3. 配置
cp config.example.yaml config.yaml     # 填 LLM 与推送渠道，可留空

# 4. 启动（Windows 产物为 bin/socradarbot.exe）
./bin/socradarbot -addr 127.0.0.1:8100 -web web/dist
```

打开 `http://127.0.0.1:8100` 即为控制台；API 健康检查 `GET /api/health`。

**不配 LLM 也能跑**：采集、富化、评分、推送、模板生成（启发式）全部可用，仅「AI 补全 / 翻译 / PoC 生成」不可用。

常用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8100` | 监听地址；容器内用 `0.0.0.0:8100` |
| `-web` | `web/dist` | 前端静态目录，不存在时返回 API 导航页 |
| `-no-scheduler` | false | 只提供 API，不跑定时任务（调试用） |
| `-version` | — | 打印版本 |

---

## 四、运行配置

优先级：**内置默认值 < `config.yaml` < 环境变量**。设置页保存后立即生效，无需重启。

| 配置节 | 键 | 默认 | 说明 |
| --- | --- | --- | --- |
| `llm` | `base` / `key` / `model` / `timeout` | openai.com / 空 / gpt-4o-mini / 60 | OpenAI 兼容端点，不含 `/v1` |
| `collect` | `interval_minutes` | 10 | 定时抓取间隔 |
| | `fetch_limit` | 10 | 单源每轮条数 |
| | `keep_days` | 90 | 保留天数，0 = 不清理（多源接入后默认 90 天） |
| | `auto_translate` | true | 英文情报自动译中 |
| | `article_fetch` | true | 抓取正文（PoC 提取与 AI 补全依赖） |
| | `timeout_seconds` | 25 | 单请求硬超时 |
| `nuclei` | `repo` / `ref` | projectdiscovery/nuclei-templates / main | 上游模板库 |
| | `remote_limit` / `fetch_remote` | 20 / false | 远程抽样条数 / 是否纳入定时采集 |
| | `gen_templates` | true | 为收录漏洞生成模板 |
| | `sync_enabled` / `sync_limit` | true / 0 | 定时增量同步 / 单次入库上限 |
| `enrich` | `enabled` | true | 富化总开关 |
| | `epss` / `kev` / `github_advisory` / `nvd` | true | 各富化数据源开关 |
| | `timeout_seconds` / `cache_hours` | 20 / 24 | 外部请求超时 / KEV、EPSS 缓存 |
| | `github_token` | 空 | 提升 GitHub API 限流（60/h → 5000/h） |
| `push` | `enabled` | false | 推送总开关 |
| | `min_score` | 60 | 风险分阈值 0-100 |
| | `min_severity` | 空 | 严重性下限 high/critical |
| | `require_cve` / `require_poc` | false | 硬性条件 |
| | `keywords_include` / `keywords_exclude` | [] | 白名单（标题+摘要）/ 黑名单（仅标题） |
| | `max_per_batch` | 10 | 单轮最多推送条数 |
| | `cooldown_minutes` | 30 | 同 CVE 冷却窗口 |
| | `channels[]` | 6 个禁用模板 | 渠道列表，见下 |
| `sources` | `custom[]` | [] | 自定义 RSS 源 `{name,url,enabled}` |

环境变量（兼容旧版前缀）：

| 新变量 | 旧变量（仍生效） | 示例 |
| --- | --- | --- |
| `SOCRADARBOT_LLM_KEY` | `AI_BAOBAO_LLM_KEY` | `sk-...` |
| `SOCRADARBOT_LLM_BASE` / `_MODEL` | `AI_BAOBAO_LLM_BASE` / `_MODEL` | |
| `SOCRADARBOT_INTERVAL_MINUTES` | `AI_BAOBAO_INTERVAL_MINUTES` | `30` |
| `SOCRADARBOT_KEEP_DAYS` | `AI_BAOBAO_KEEP_DAYS` | `90` |
| `SOCRADARBOT_AUTO_TRANSLATE` | `AI_BAOBAO_AUTO_TRANSLATE` | `false` |
| `SOCRADARBOT_NUCLEI_SYNC` / `_GEN` | `AI_BAOBAO_NUCLEI_SYNC` / `_GEN` | `false` |
| `SOCRADARBOT_ENRICH` / `_EPSS` / `_KEV` / `_NVD` | `AI_BAOBAO_ENRICH` | `true` |
| `SOCRADARBOT_GITHUB_TOKEN` | `GITHUB_TOKEN` | `ghp_...` |
| `SOCRADARBOT_PUSH_ENABLED` | `AI_BAOBAO_PUSH_ENABLED` | `true` |
| `SOCRADARBOT_CONFIG` / `SOCRADARBOT_DATA` | — | 配置文件 / 数据目录路径 |

---

## 五、数据富化（增强点一）

### 5.1 数据源

| 源 | 类型 | 提供的关键字段 | 说明 |
| --- | --- | --- | --- |
| seebug / 先知 / exploit-db | RSS | 标题、摘要、链接、发布时间 | 内置，可在设置页叠加自定义社区 |
| 自定义 RSS | RSS/Atom | 同上 | 新增源前可先 `POST /api/sources/discover` 探测 |
| **`chaitin` 长亭漏洞库** | JSON API | CT 编号、CVE、CVSS、等级、参考链接 | 结构化程度最高，含实时中文条目（详见 `docs/SOURCES.md`） |
| **`oscs` 开源安全情报** | JSON API | 中文标题、影响组件/版本、CVSS、PoC 标记 | 墨菲安全预警，更新频率较低，保留期建议 ≥90 天 |
| **`qianxin-ti` 奇安信 TI** | JSON API | 中文标题、等级、`POC公开`/`CERT验证` 标签 | 当日重点漏洞 + PoC/EXP 新增 |
| `cisa-kev` | JSON | CVE、厂商/产品、处置建议、勒索标记、收录日期 | CISA 官网 403 时自动切换官方 GitHub 镜像 |
| `nvd` | JSON | CVE、CVSS、CPE 影响范围、CWE | 无 token 限流 5 次/30s；每轮仅 1 次请求 |
| `github-advisory` | JSON | CVE、CVSS、受影响包（生态+包名）、CWE | 匿名限流严格，建议配 `enrich.github_token` |

### 5.2 字段补齐规则

| 字段 | 来源与规则 |
| --- | --- |
| `cves` | 标题/摘要/原理/影响范围/引用链接中正则提取，统一大写去重 |
| `cvss` | 数据源显式给出；否则从正文提取 `CVSS 9.8` / `CVSS:3.1 7.5` / `9.8 分` |
| `severity` | ① 数据源显式等级 → ② CVSS 区间（≥9 严重 / ≥7 高危 / ≥4 中危 / >0 低危）→ ③ 标题与摘要关键词（严重/高危/远程代码执行/RCE/未授权/信息泄露…），命中后 `severity_inferred=true` |
| `affected_products` | NVD CPE、GHSA 受影响包、KEV 厂商+产品合并去重 |
| `epss` / `epss_percentile` | FIRST.org EPSS，每批 ≤100 个 CVE，12 小时本地缓存 |
| `kev` / `kev_date` / `known_ransomware` | CISA KEV 命中标记，计入评分 |
| `score` / `high_value` / `score_reasons` | 见 5.3 |
| `cwe` | NVD / GHSA 弱点类型 |

### 5.3 风险评分（0-100）

```
score = min(100, 基础分 + EPSS×20 + KEV 25 + PoC 15 + CVE 5 + 新鲜度 5)

基础分：CVSS × 8（有 CVSS）
        无 CVSS 时按等级：critical 75 / high 60 / medium 40 / low 20 / info 5
新鲜度：published 或 created_at 在 7 天内 +5
```

示例（实际运行输出）：`CVE-2026-0322` → KEV + 高危 + CVE + 近 7 天 = **95 分**，判定依据完整写入 `score_reasons`，并原样出现在推送文案中。

存量数据迁移后可调用 `POST /api/enrich/rebuild` 一键重算（44 条实测耗时 < 1s）。

### 5.4 情报源筛选与统一接入

对 watchvuln 的 9 类源逐一实测后的取舍：**集成**长亭、OSCS、奇安信 TI（公开 JSON API 稳定可用），复用其 RSS/KEV 思路，**不集成** AVD（JS WAF 挑战）、启明星辰（403）、微步（需登录态）、Struts2（低频且 CVE 已被 NVD 覆盖）。完整评估矩阵、字段归一化规则、接入点与配置设计见 [`docs/SOURCES.md`](docs/SOURCES.md)。

所有源实现同一个 `source.Fetcher` 接口，新增源只需在 `internal/source/` 增加适配器并在 `catalog` 注册，流水线、评分、推送、接口自动生效。内置源可通过 `sources.disabled` 或控制台开关停用。

---

## 六、高价值情报识别与推送（增强点二）

### 6.1 判定规则

一条情报被判定为「高价值」需**同时满足**：

1. `score >= push.min_score`（默认 60）
2. `severity >= push.min_severity`（默认不限）
3. `require_cve=true` 时必须关联 CVE；`require_poc=true` 时必须存在 PoC 或模板
4. 若配置 `keywords_include`，标题或摘要需命中至少一个关键词
5. 标题不得命中 `keywords_exclude`（黑名单只查标题，避免误杀）

> 判定在**落库时**执行并写入 `high_value`，推送前会按当前规则再算一次，改配置立即影响下一轮。

### 6.2 去重策略（三层）

| 层级 | 时机 | 规则 | 落点 |
| --- | --- | --- | --- |
| 入库去重 | 采集 | 相同 `id` 跳过；相同 CVE 跨源合并（保留信息量更大的一条，合并引用/标签/影响范围） | `skipped` 计数 |
| 推送去重 | 推送 | 同批同一 CVE 只推评分最高的一条，其余标记 `push_skip_reason=cve-duplicate` | 避免重复刷屏 |
| 冷却窗口 | 推送 | 同一 CVE 在 `cooldown_minutes` 内已推送过则跳过（跨 ID 生效） | 防止换源重推 |

失败语义：**所有渠道都失败时条目不标记已推送**，下一轮自动重试；只要有一个渠道成功即标记 `pushed=true`。

### 6.3 推送渠道

| type | 目标 | 报文 | 签名 | 单条上限 |
| --- | --- | --- | --- | --- |
| `wecom` | 企业微信群机器人 | `msgtype=markdown` | 不支持 | 3800 字节分片 |
| `dingtalk` | 钉钉群机器人 | `msgtype=markdown` | 支持加签（HMAC-SHA256） | 18 KB 分片 |
| `feishu` | 飞书群机器人 | 交互式卡片（lark_md） | 支持签名 | 20 KB 分片 |
| `slack` | Slack Incoming Webhook | `{text}`，可指定 channel | — | 3800 字节分片 |
| `telegram` | Telegram Bot | `sendMessage`，支持多个 `chat_ids` | — | 3800 字节分片 |
| `webhook` | 内部 IM 网关 | `{source,title,markdown}` JSON | — | 不分片 |

多通道并行：配置几个启用的渠道就推几个，单个渠道失败不影响其他渠道。

### 6.4 推送格式

```
## SocradarBot 高价值漏洞情报（5）

**1. [高危] Palo Alto Networks PAN-OS Code Injection Vulnerability（CVE-2026-0322）**
- CVE：CVE-2026-0322 ｜ 评分：95
- CISA KEV ✅
- 来源：cisa-kev ｜ 披露：2026-10-14
- 影响：Palo Alto Networks PAN-OS
- 摘要：Palo Alto Networks PAN-OS contains a code injection vulnerability ...
- 判定：严重性 高危、CISA KEV 已知在野利用、已关联 CVE 编号、近 7 天披露
- 详情：https://nvd.nist.gov/vuln/detail/CVE-2026-0322
```

每条包含：等级徽标、CVE、评分、CVSS/EPSS/KEV/PoC 技术标记、来源与披露日期、影响范围、摘要、**判定依据**、原文链接。按整条情报分片，不会把一条记录截断。

### 6.5 推送管理接口

```bash
curl localhost:8100/api/push                    # 查看配置（webhook 脱敏）
curl -X POST localhost:8100/api/push -d @push.json   # 局部更新（未提交字段保持原值）
curl -X POST localhost:8100/api/push/test       # 发送测试消息到所有启用渠道
curl -X POST localhost:8100/api/push/run        # 立即推送待推队列
curl localhost:8100/api/push/history            # 最近 100 条推送记录
curl -X POST localhost:8100/api/vulns/<ID>/push # 单条手动推送
```

`push.json` 最小示例：

```json
{
  "enabled": true,
  "min_score": 60,
  "min_severity": "high",
  "channels": [
    {"name": "安全群", "type": "wecom", "webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx", "enabled": true}
  ]
}
```

### 6.6 控制台配置与界面

推送无需改文件，控制台「配置 → 情报推送」提供：

- 总开关、最低风险分、严重性下限、单批上限、冷却窗口
- 必须关联 CVE / 必须存在 PoC 两个硬性条件
- 关键词白名单 / 黑名单（逗号或换行分隔）
- 渠道可视化编辑：类型、名称、Webhook、签名密钥、Telegram chat_ids、Slack channel、独立启停
- 「发送测试消息」「立即推送待推队列」与最近推送记录（含各渠道成功/失败原因）

界面参考 CVE 漏洞库的信息架构完成改版：浅色数据台、深酒红顶栏；首页由「英雄区（收录/KEV/PoC/高价值）+ 六维筛选 + 桌面高密度表格 + 移动卡片」组成；详情页为「风险摘要 + 正文分区 + 风险画像侧栏」；配置页拆为 AI / 采集与源 / 情报推送 / 模板库四个分区。响应式断点 900px 与 640px，已在 1440px 与 500px 视口实测无横向溢出。设计对比、令牌与差距分析见 [`docs/DESIGN.md`](docs/DESIGN.md)。

![推送配置](https://socradarbot.million.cc.cd/screenshots/push-settings.png)

> 上图为配置示例：可添加企业微信、钉钉、飞书、Slack、Telegram 或通用 Webhook，并单独启停。

---

## 七、部署

### 7.1 二进制（推荐）

```bash
# Linux 交叉编译（本机 Windows 亦可）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
  -o socradarbot ./cmd/socradarbot

# 服务器上
mkdir -p /opt/socradarbot && cd /opt/socradarbot
cp socradarbot config.example.yaml ./
cp -r web/dist ./web/
cp config.example.yaml config.yaml
./socradarbot -addr 0.0.0.0:8100 -web web/dist
```

### 7.2 systemd

```ini
[Unit]
Description=SocradarBot vulnerability intelligence
After=network-online.target

[Service]
WorkingDirectory=/opt/socradarbot
ExecStart=/opt/socradarbot/socradarbot -addr 127.0.0.1:8100 -web /opt/socradarbot/web/dist
Restart=always
RestartSec=5
Environment=SOCRADARBOT_CONFIG=/opt/socradarbot/config.yaml
Environment=SOCRADARBOT_DATA=/opt/socradarbot/data

[Install]
WantedBy=multi-user.target
```

### 7.3 Docker

```bash
docker build -t socradarbot .
docker run -d --name socradarbot -p 8100:8100 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  socradarbot
```

`config.yaml` 中的 `llm.base` 若为宿主机服务，容器内需用 `host.docker.internal` 或容器网络地址。

### 7.4 Cloudflare Workers 在线预览（一键部署）

仓库内置 `wrangler.toml` 与 `deploy/cloudflare/worker.js`：Worker 负责托管 `web/dist` 静态资源，并用内置脱敏数据提供只读 `/api/*`，因此无需公网后端即可完整浏览列表、筛选与详情。

```bash
# 本地预览
npx wrangler dev

# 部署到自己的 Cloudflare 账号（workers.dev 域名）
npx wrangler deploy

# 绑定自定义域名：在 wrangler.toml 增加 routes 后重新 deploy
# routes = [{ pattern = "your-subdomain.example.com", custom_domain = true }]
```

一键部署按钮见 README 顶部；自定义域名、数据更新与限制见 [`docs/DEPLOY_CLOUDFLARE.md`](docs/DEPLOY_CLOUDFLARE.md)。

### 7.5 反向代理与安全

- 服务默认只监听 `127.0.0.1`；对外暴露时置于 Nginx/Caddy 之后并加认证（接口无鉴权设计，属内网工具）。
- 采集接口是长任务（前端超时建议 ≥ 120s），Nginx 需相应放宽 `proxy_read_timeout`。
- 健康检查：`GET /api/health`；指标概览：`GET /api/stats`。

---

## 八、从 ai_bobao 迁移

完整步骤与差异清单见 [`docs/MIGRATION.md`](docs/MIGRATION.md)，要点：

1. **数据直接复用**：把旧 `backend/data/` 复制为 `socradarbot/data/`，目录结构（`vulns/{id}/meta.json + poc.py + nuclei.yaml`）完全一致；新字段自动补默认值。
2. **配置迁移**：`llm` / `collect` / `nuclei` / `sources` 四节键名不变，可直接复用；新增 `enrich` / `push` 两节。旧 `config.yaml` 可直接使用。
3. **环境变量**：新前缀 `SOCRADARBOT_*`，同时兼容 `AI_BAOBAO_*`。
4. **接口兼容**：旧版 22 个接口路径、方法、参数、返回字段不变；校验错误码由 422 改为 400（`detail` 仍为字符串，前端 `api.js` 兼容）。
5. **存量补字段**：启动后调用 `POST /api/enrich/rebuild`，为历史条目补齐 CVE/EPSS/KEV/评分。
6. **回滚**：Go 版写入的新字段对 Python 版是未知键，Python 读取 meta.json 不受影响；停止 Go 进程、启动旧服务即可回滚。

---

## 九、验证

```bash
go test ./...                                   # 17 个单元测试（富化/评分/模板/推送/数据源）
go vet ./...
node scripts/smoke_test.mjs                     # 40 项接口冒烟（需服务已启动）
node scripts/mock_webhook.mjs &                 # 本地 webhook 接收器
node scripts/e2e_test.mjs                       # 真实采集 + 推送端到端验证
```

实测结果（2026-10-20）：

- 接口冒烟 **40/40 通过**（含 404/400 分支、设置回读、源管理闭环）
- 新源采集：长亭 5 条、OSCS 3 条、奇安信 TI 5 条入库；OSCS 条目 CVSS 9.8 → 98 分，TI 条目 `POC公开` → 85 分
- 真实采集一轮：抓取 50 条，KEV 入库 7 条、NVD 入库 8 条，高价值 14 条，推送 5 条至 mock webhook
- 单元测试 17 项全部通过，`go vet` 无告警
- 前端在 1440px / 500px 视口截图核验，无横向溢出；推送配置页可保存、测试、查看历史

---

## 十、参考与致谢

- [watchvuln](https://github.com/zema1/watchvuln)：高价值漏洞采集与推送的先行实现。本项目参考了其情报源筛选思路、多源归一化方式与「评分 + 标签 + 去重」的推送判定，并在 Go 技术栈上重新实现。
- [ai_bobao](https://github.com/wr0x00/ai_bobao.git)：本项目的前身（Python / FastAPI）。接口契约、`data/vulns/{id}/` 文件结构与前端交互均以其为基础演进，Go 版保持旧接口兼容。

以上项目版权归各自作者所有；本仓库为独立重构实现，未包含其源码副本。

## 十一、安全与脱敏

- **仓库不含运行态数据**：`config.yaml`、`data/`、根目录 `dist/`（打包产物）、`bin/`、`*.zip`、`web/node_modules/` 均已写入 `.gitignore`，不会提交；`web/dist/` 作为一键部署所需的前端产物单独提交。
- **示例配置无凭据**：`config.example.yaml` 中 `llm.key`、`github_token`、各渠道 `webhook`/`secret` 均为空或占位符。
- **演示数据已脱敏**：Cloudflare 预览仅包含公开漏洞元数据（CVE、摘要、等级、评分等），剔除 PoC 代码、nuclei 模板正文、内部地址与本机路径，并禁用全部写操作。
- **凭据管理**：完整服务请将密钥写入本地 `config.yaml` 或环境变量（`SOCRADARBOT_LLM_KEY`、`SOCRADARBOT_GITHUB_TOKEN` 等），不要提交到仓库。
- 若曾将含真实密钥的 `config.yaml` 或打包目录分享给他人，请立即轮换 LLM Key、GitHub Token 与机器人 Webhook。

## 十二、安全声明

本项目仅用于防御性安全研究与授权测试。采集内容来自公开渠道，生成的 PoC 与 nuclei 模板依据公开披露的思路编写；使用前请确认已获得目标系统所有者授权。模板生成默认拦截写操作（POST/PUT/DELETE、admin/import 等），确需生成时必须显式 `allow_write=true`。
