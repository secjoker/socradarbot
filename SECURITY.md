# Security Policy

## 报告问题

如发现安全漏洞或敏感信息泄露，请通过 GitHub 仓库的 **Security → Report a vulnerability** 私下报告，不要在公开 Issue 中披露细节。

## 密钥与配置

- 仓库不包含任何真实密钥。`config.yaml`、`data/`、`dist/`、`bin/`、`*.zip` 均在 `.gitignore` 中。
- `config.example.yaml` 只包含占位符。
- 生产部署请通过本地 `config.yaml` 或环境变量注入：
  - `SOCRADARBOT_LLM_KEY`
  - `SOCRADARBOT_GITHUB_TOKEN`
  - `SOCRADARBOT_PUSH_ENABLED`
- 推送渠道的 Webhook/Secret 属于凭据，请勿提交或写入 issue。

## 在线预览

Cloudflare 预览使用脱敏样本，且所有写接口返回 403；不连接真实数据库、不调用 LLM、不发送任何推送。

## 使用边界

本项目仅用于防御性安全研究与授权测试。使用 PoC 或 nuclei 模板前，请确认已获得目标系统所有者的明确授权。
