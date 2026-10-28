# 情报源分析与统一接入方案

本文记录对 [watchvuln](https://github.com/zema1/watchvuln) 采集源的评估、筛选结果，以及 SocradarBot 的统一接入设计。

## 一、watchvuln 数据源盘点与本项目决策

| watchvuln 源 | 采集方式 | 本环境实测（2026-10-20） | 决策 | 原因 |
| --- | --- | --- | --- | --- |
| **OSCS 开源安全情报** | JSON API：`POST /oscs/v1/intelligence/list` + `POST /oscs/v1/vdb/info` | 200，1 607 条，含中文标题 / 影响版本 / CVSS | ✅ **已集成**（`oscs`） | 接口稳定、中文质量高、含 PoC 标记；缺点是更新频率偏低 |
| **长亭漏洞库（CT Stack）** | JSON API：`GET /api/v2/vuln/list/?limit=15&offset=0&search=CT-` | 200，42 万条，实时（当日） | ✅ **已集成**（`chaitin`） | 结构化程度最高，含 CT 编号 / CVE / CVSS / 参考链接，无需解析 HTML |
| **奇安信威胁情报中心** | JSON API：`POST /alpha-api/v2/vuln/one-day` | 200，当日新增 76 条、PoC/EXP 43 条 | ✅ **已集成**（`qianxin-ti`） | 中文情报及时，`POC公开 / 奇安信CERT验证 / 技术细节公开` 标签是强价值信号 |
| 阿里云漏洞库 AVD | HTML + JS WAF 绕过（执行页面脚本生成 Cookie） | 列表页返回 JS 挑战，API 返回 `{"code":1000,"msg":"May the Force be with you"}` | ❌ 不集成 | 需要 JS 引擎与逆向 WAF 参数，维护成本高、随时失效；价值可由 NVD/KEV/TI 覆盖 |
| 启明星辰通告 | HTML 列表 | HTTP 403 | ❌ 不集成 | 网络侧直接拒绝，无法稳定采集 |
| 微步 ThreatBook | SPA / 登录态接口 | 200 但为前端壳，数据接口需鉴权 | ❌ 不集成 | 无公开 API，强行逆向不稳定 |
| Apache Struts2 公告 | Wiki HTML + 逐页详情 | 200，可解析 | ⏸ 暂不集成 | 更新频率低；CVE 已被 NVD 覆盖；逐页抓取收益低 |
| Seebug / 先知 | watchvuln 用 HTML（含 WAF） | RSS 正常 | ✅ 已集成（RSS） | 官方 RSS 比 HTML 抓取更稳定，且已被原项目采用 |
| CISA KEV | 官方 JSON | 官网 403，GitHub 镜像 200 | ✅ 已集成 | 官方镜像 `cisagov/kev-data` 自动回退 |
| NVD | REST API 2.0 | 200 | ✅ 已集成 | CVSS / CPE / CWE 的标准来源 |
| GitHub Advisory | REST API | 403（匿名限流） | ✅ 已集成（需 token） | 配 `enrich.github_token` 后可用 |
| GitHub PoC 搜索 | watchvuln 默认按 CVE 搜索仓库/PR | 匿名限流 | ⏸ 未启用 | 以 TI `POC公开` 标签、OSCS `is_poc`、Chaitin `poc_id` 作为替代信号 |

最终内置源共 **9 个**：`seebug`、`先知`、`exploit-db`、`chaitin`、`oscs`、`qianxin-ti`、`cisa-kev`、`nvd`、`github-advisory`（后三者随 `enrich` 开关启停）。

## 二、关键接入点

### 1. 统一采集契约：`source.Fetcher`

所有源（RSS、JSON API）实现同一接口，向上只输出 `model.Item`：

```go
type Fetcher interface {
    Name() string
    Fetch(ctx context.Context, limit int) ([]model.Item, error)
}
```

接入新源的改动面被限制在 `internal/source/`：新增一个文件 + 在 `catalog` 注册 + 在 `Build` 中装配，不改流水线、存储与接口。

### 2. 统一字段归一化

| 字段 | 规则 |
| --- | --- |
| `ID` | 源前缀 + 源内唯一键：`chaitin-{ct_id}` / `oscs-{mps}` / `ti-{qvd_code}`，保证跨轮去重 |
| `Title` | 优先中文标题；仅有 CVE 编号时拼接摘要首句，避免列表出现纯编号 |
| `Severity` | 各源中文等级统一映射到 `critical/high/medium/low`（严重/极危 → critical） |
| `CVSS` | 数据源显式字段；长亭 `cvss3` 兼容数字与 `{"score": x}` 两种形态 |
| `CVEs` | 统一正则提取、大写去重 |
| `Affected` | OSCS `effect[]`（组件+版本）、KEV 厂商产品、NVD CPE、GHSA 包名 |
| `Tags` | 源标签原样保留（`发布预警`、`POC公开`、`奇安信CERT验证`…） |
| `POCDisclosed` | OSCS `is_poc/is_exp`、TI `poc_flag/标签`、长亭 `poc_id`，用于评分与 `require_poc` |
| `Published` | 统一 `YYYY-MM-DD`；缺失时用 `created_at` 兜底 |

### 3. 源目录与启停

`internal/source/catalog` 维护元信息（ID / 名称 / 类型 / 地址 / 说明），`/api/sources` 直接输出，前端据此渲染启停开关。

配置层：

```yaml
sources:
  disabled: ["oscs"]   # 按 ID 停用内置源
  custom: []           # 自定义 RSS
```

富化类源（KEV/NVD/GHSA）同时受 `enrich.enabled` 与各自开关控制，避免"关了富化却还在抓"的歧义。

### 4. 容错与限流

- 所有源并发抓取，单源失败只记录到 `source_errors`，不阻断其他源
- 每个源遵守 `collect.fetch_limit`（上限 60–100），OSCS 详情补全并发 4
- OSCS 列表 → 详情失败时回退列表字段，单条失败不影响整批
- 长亭分页按 `limit` 计算，最多 4 页
- 统一浏览器 UA / Referer / Origin；HTTP 客户端 25s 超时

### 5. 下游自动衔接

新源进入流水线后无需额外适配：去重（ID + CVE）→ 正文抓取（仅 RSS）→ CVE/EPSS/KEV 富化 → 严重性推断 → 风险评分 → 高价值判定 → 推送。实测新源条目可直接命中高价值（OSCS CVSS 9.8 → 98 分，TI POC公开 → 85 分）。

## 三、配置项设计

| 配置 | 默认 | 作用 |
| --- | --- | --- |
| `sources.disabled` | `[]` | 停用内置源，ID 见 `/api/sources` |
| `sources.custom` | `[]` | 自定义 RSS `{name,url,enabled}` |
| `collect.fetch_limit` | 10 | 每源每轮条数（新源同样受限） |
| `collect.keep_days` | 90 | 保留天数；OSCS 更新较慢，60 天会过滤其最新条目，故默认调为 90 |
| `enrich.kev / nvd / github_advisory` | true | 结构化源与富化开关 |
| `enrich.github_token` | 空 | 提升 GitHub API 限流 |
| `push.*` | 关闭 | 规则与渠道，支持 Web 配置 |

## 四、前端信息架构调整

| 区域 | 调整 |
| --- | --- |
| 全局 | 设计令牌（颜色/圆角/间距/字体）、居中容器、粘性导航、移动端折叠 |
| 情报流 | 4 项统计卡、来源页签、关键词搜索、仅高价值筛选、风险分列、严重性色条、KEV/EPSS/PoC 标签 |
| 详情 | 顶部风险摘要 + 右侧风险画像/元数据、判定依据可解释、代码块折叠与复制 |
| 配置 | 四个分区：AI 接口 / 采集与源 / 情报推送 / 模板库；源启停开关；**推送渠道与规则可视化编辑** |
| 模板库 | 与情报流一致的卡片语言、远程筛选、响应式布局 |
| 响应式 | 900px 双列降级，640px 单列；实测 1440px 与 500px 视口无横向溢出 |

## 五、验证记录

```
源目录: seebug, 先知, exploit-db, chaitin, oscs, qianxin-ti, cisa-kev, nvd, github-advisory
采集一轮（fetch_limit=5）：kept 13，chaitin 5 / oscs 3 / qianxin-ti 5，GitHub 403 记入 source_errors
样例：
  chaitin  CVE-2026-97627  high  score 85
  oscs     Apache CXF 反序列化  critical  CVSS 9.8  score 98
  qianxin  Apache Camel SSRF  high  POC公开  score 85
单元测试：source 包 5 项（flexFloat / 长亭映射 / OSCS 映射 / TI 映射 / 目录开关）
接口冒烟：40/40
```
