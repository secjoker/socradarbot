// SocradarBot Go 后端接口冒烟测试（兼容 22 个旧接口 + 新增接口）
const BASE = "http://127.0.0.1:8100";
let pass = 0, fail = 0;

async function call(name, path, init, expect = 200) {
  const t0 = Date.now();
  try {
    const r = await fetch(BASE + path, init);
    const text = await r.text();
    let body; try { body = JSON.parse(text); } catch { body = text.slice(0, 100); }
    const ok = Array.isArray(expect) ? expect.includes(r.status) : r.status === expect;
    ok ? pass++ : fail++;
    console.log(`${ok ? "✓" : "✗"} [${r.status}] ${name} (${Date.now() - t0}ms) :: ${JSON.stringify(body).slice(0, 170)}`);
    return { status: r.status, body };
  } catch (e) {
    fail++;
    console.log(`✗ [ERR] ${name} :: ${e}`);
    return { status: 0, body: null };
  }
}
const post = (b) => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b ?? {}) });

for (let i = 0; i < 20; i++) {
  try { await fetch(BASE + "/api/health"); break; } catch { await new Promise(r => setTimeout(r, 500)); }
}

console.log("── 基础与兼容接口 ──");
await call("GET /api/health", "/api/health");
await call("GET /api/stats", "/api/stats");
await call("GET /api/vulns", "/api/vulns");
await call("GET /api/vulns?page_size=5", "/api/vulns?page_size=5");
await call("GET /api/vulns?high_value=1", "/api/vulns?high_value=1");
await call("GET /api/vulns/not-exist → 404", "/api/vulns/not-exist", undefined, 404);
await call("GET /api/collect/status", "/api/collect/status");
await call("GET /api/llm/status", "/api/llm/status");
await call("GET /api/nuclei/templates", "/api/nuclei/templates");
await call("GET /api/nuclei/sync", "/api/nuclei/sync");
await call("GET /api/settings", "/api/settings");
await call("GET /api/push", "/api/push");
await call("GET /api/push/history", "/api/push/history");
await call("GET /api/sources", "/api/sources");

console.log("── 设置读写与校验 ──");
await call("POST /api/settings 改 model", "/api/settings", post({ llm: { model: "test-model-x" } }));
const got = await call("GET /api/settings 回读", "/api/settings");
const mOk = got.body?.llm?.model === "test-model-x";
mOk ? pass++ : fail++;
console.log(`${mOk ? "✓" : "✗"} 校验: model 回读 = test-model-x（实际 ${got.body?.llm?.model}）`);
await call("POST /api/settings 恢复", "/api/settings", post({ llm: { model: "gpt-4o-mini" } }));
await call("POST /api/settings 未知节 → 400", "/api/settings", post({ evil: {} }), 400);
await call("POST /api/settings 非法 base → 400", "/api/settings", post({ llm: { base: "ftp://x" } }), 400);
await call("POST /api/settings/test 未配 key → 502", "/api/settings/test", post({ llm: {} }), 502);

console.log("── 源管理闭环 ──");
await call("POST /api/sources 无协议头 → 400", "/api/sources", post({ name: "t", url: "ftp://x" }), 400);
await call("POST /api/sources 缺名称 → 400", "/api/sources", post({ name: "", url: "https://x.com/feed" }), 400);
await call("POST /api/sources 接入", "/api/sources", post({ name: "smoke-test", url: "https://example.com/feed", enabled: false }));
const src = await call("GET /api/sources 含测试源", "/api/sources");
const has = (src.body?.custom || []).some(s => s.name === "smoke-test");
has ? pass++ : fail++;
console.log(`${has ? "✓" : "✗"} 校验: custom 源含 smoke-test`);
await call("DELETE /api/sources/smoke-test", "/api/sources/smoke-test", { method: "DELETE" });
await call("DELETE /api/sources/smoke-test 再删 → 404", "/api/sources/smoke-test", { method: "DELETE" }, 404);

console.log("── 推送配置校验 ──");
await call("POST /api/push 启用但无 webhook → 400", "/api/push", post({ enabled: true, min_score: 60, channels: [{ name: "x", type: "wecom", enabled: true }] }), 400);
await call("POST /api/push 恢复默认关闭", "/api/push", post({ enabled: false, min_score: 60, min_severity: "", require_cve: false, require_poc: false, keywords_include: [], keywords_exclude: [], max_per_batch: 10, cooldown_minutes: 30, channels: [] }));
await call("POST /api/push/run 未启用", "/api/push/run", post({}));
await call("POST /api/push/test 无渠道", "/api/push/test", post({}));

console.log("── 其他兼容接口 ──");
await call("GET /api/nuclei/remote (可能限流)", "/api/nuclei/remote?limit=2", undefined, [200, 502]);
await call("POST /api/vulns/purge", "/api/vulns/purge", post({}));
await call("POST /api/translate/backfill 空库/无LLM", "/api/translate/backfill", post({ limit: 2 }));
await call("POST /api/vulns/nope/poc → 404", "/api/vulns/nope/poc", post({}), 404);
await call("POST /api/vulns/nope/translate → 404", "/api/vulns/nope/translate", post({}), 404);
await call("POST /api/vulns/nope/nuclei → 404", "/api/vulns/nope/nuclei", post({ allow_write: false }), 404);
await call("GET / 前端静态页", "/");
await call("GET /api/unknown → 404", "/api/unknown", undefined, 404);

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
