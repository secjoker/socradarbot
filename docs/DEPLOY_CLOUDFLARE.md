# Cloudflare Workers 在线预览部署

本项目提供一个**只读在线预览**：前端为 `web/dist` 静态资源，`/api/*` 由 Cloudflare Worker 使用内置的脱敏演示数据响应，因此无需公网后端即可浏览漏洞库、筛选、详情与配置页。

- 线上地址：<https://socradarbot.million.cc.cd>
- 备用地址：`https://socradarbot-preview.<你的子域>.workers.dev`（部分地区可能被网络策略拦截）

## 1. 结构

```
wrangler.toml                  # Worker 配置（静态资源 + 入口）
deploy/cloudflare/worker.js    # 路由：/api/* 只读数据；其余交给静态资源
deploy/cloudflare/demo-data.json
web/dist/                      # 已构建前端（含 screenshots/）
scripts/build-demo-data.mjs    # 从本地 data/ 生成脱敏演示数据
```

Worker 的行为：

| 路径 | 行为 |
| --- | --- |
| `GET /api/health`、`/api/stats`、`/api/vulns`、`/api/vulns/:id` | 返回演示数据，支持筛选/排序/分页 |
| `GET /api/settings`、`/api/push`、`/api/sources` | 返回脱敏配置（密钥为空、渠道为空） |
| `POST /api/*` | 统一 403，提示"在线预览为只读演示" |
| 其他路径 | 静态资源；SPA 回退到 `index.html`，并注入只读横幅 |

## 2. 本地预览

```bash
# 1) 构建前端
cd web && npm ci && npm run build && cd ..

# 2)（可选）从本地 data/ 重新生成脱敏样本
node scripts/build-demo-data.mjs

# 3) 启动 Worker 本地服务
npx wrangler dev
```

`wrangler dev` 默认监听 `http://localhost:8787`。如果你本机注入了 HTTP 代理且访问本地端口失败，先 `unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy` 并设置 `NO_PROXY=127.0.0.1,localhost`。

## 3. 部署

### 3.1 CLI（推荐）

```bash
npx wrangler login      # 首次
npx wrangler deploy
```

成功后输出 `https://socradarbot-preview.<你的子域>.workers.dev`。

### 3.2 一键部署按钮

README 顶部按钮：

```
https://deploy.workers.cloudflare.com/?url=https://github.com/<owner>/socradarbot
```

前置条件：

1. 仓库公开；
2. 根目录存在 `wrangler.toml`；
3. `web/dist` 已提交（本项目已包含构建产物，无需在 Cloudflare 侧再构建）。

### 3.3 自定义域名

`workers.dev` 在部分网络不可达。若域名已托管在 Cloudflare：

```toml
# wrangler.toml
routes = [
  { pattern = "socradarbot.example.com", custom_domain = true }
]
```

再次 `npx wrangler deploy`，Wrangler 会自动创建 DNS 记录并签发证书。

> 本仓库的线上实例使用独立配置 `wrangler.million.toml`（不提交），默认 `wrangler.toml` 保持无域名绑定，便于他人一键部署到自己的账号。

## 4. 演示数据

`deploy/cloudflare/demo-data.json` 由 `scripts/build-demo-data.mjs` 生成：

- 从 `data/vulns/*/meta.json` 读取，仅保留公开字段；
- 过滤 nuclei 模板条目，保留 `critical/high/medium` 与有 CVE 的记录；
- 剔除 PoC 代码、nuclei YAML、内网地址、本机路径；
- 生成约 50–70 条样本，覆盖 5 个来源、9 条 KEV 与若干 PoC 标记。

更新数据：

```bash
node scripts/build-demo-data.mjs
npx wrangler deploy
```

## 5. 限制

- 预览为**只读**：抓取、保存配置、推送、生成 PoC/模板均不可用；
- 数据是脱敏子集，不代表完整情报库；
- 如需完整能力，请按 README 部署 Go 后端，并将前端反向代理到 `/api`；
- 预览 Worker 不包含任何真实密钥；请勿在 `demo-data.json` 中加入内部数据。

## 6. 常见问题

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `workers.dev` TLS 错误 | 网络侧拦截 | 绑定自定义域名 |
| 页面空白 | `web/dist` 未提交或路径错误 | 确认 `assets.directory` 指向 `./web/dist` |
| API 全部 403 | 预览只读设计 | 属预期行为 |
| 部署提示 zone 不存在 | `routes` 使用了他人域名 | 删除 `routes` 或换成自己账号下的 zone |
