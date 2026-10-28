// 端到端验证：推送配置 → 测试推送 → 真实采集 → 富化字段与推送历史断言
const BASE = "http://127.0.0.1:8100";
const post = (b) => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b ?? {}) });
const j = async (r) => { const t = await r.text(); try { return JSON.parse(t); } catch { return t; } };
let fail = 0;
const ok = (cond, msg, extra = "") => { cond ? console.log(`✓ ${msg}`) : (fail++, console.log(`✗ ${msg} ${extra}`)); };

// 1) 配置推送渠道（指向本地 mock）
const cfgRes = await fetch(BASE + "/api/push", post({
  enabled: true, min_score: 50, max_per_batch: 5, cooldown_minutes: 30,
  channels: [{ name: "mock", type: "webhook", webhook: "http://127.0.0.1:18080/hook", enabled: true }],
}));
const cfg = await j(cfgRes);
ok(cfgRes.ok && cfg.channels?.some(c => c.name === "mock" && c.webhook_set), "推送渠道配置成功（webhook 已保存并脱敏）");

// 2) 测试推送
const testRes = await fetch(BASE + "/api/push/test", post({}));
const t = await j(testRes);
ok(testRes.ok && t.channels?.[0]?.ok === true, "测试消息投递 mock webhook 成功", JSON.stringify(t).slice(0, 200));

// 3) 真实采集
console.log("… 正在执行真实采集（3 个 RSS + CISA KEV + GitHub Advisory），约需 30-60s");
const cRes = await fetch(BASE + "/api/collect", post({}));
const c = await j(cRes);
console.log("采集结果:", JSON.stringify(c).slice(0, 500));
ok(cRes.ok && typeof c.fetched === "number", "采集接口返回结果");
ok(c.kept >= 1, `成功入库 ${c.kept} 条`, JSON.stringify(c).slice(0, 300));

// 4) 富化字段断言
const list = await j(await fetch(BASE + "/api/vulns?page_size=10"));
ok(Array.isArray(list.items), "列表接口返回 items");
const enrichedItem = list.items?.find(v => v.cves?.length || v.kev || v.epss || v.severity);
if (enrichedItem) {
  const d = await j(await fetch(BASE + "/api/vulns/" + encodeURIComponent(enrichedItem.id)));
  const hasCve = d.cves?.length > 0;
  const hasSev = !!d.severity && d.severity !== "unknown";
  const hasScore = typeof d.score === "number" && d.score > 0;
  console.log("富化样例:", JSON.stringify({
    id: d.id, name: (d.name || "").slice(0, 50), severity: d.severity, cvss: d.cvss,
    cves: d.cves, epss: d.epss, kev: d.kev, score: d.score, high_value: d.high_value,
    reasons: d.score_reasons, affected: d.affected_products, source: d.source,
  }));
  ok(hasCve || d.kev, "CVE / KEV 字段已补齐");
  ok(hasSev, "severity 字段已补齐");
  ok(hasScore, "风险评分已写入");
} else {
  fail++; console.log("✗ 未找到可验证的富化条目");
}

// 5) 统计与推送历史
const stats = await j(await fetch(BASE + "/api/stats"));
console.log("统计:", JSON.stringify(stats).slice(0, 300));
ok(stats.total >= 1 && stats.by_source, "统计接口返回来源分布");
const hist = await j(await fetch(BASE + "/api/push/history"));
ok(Array.isArray(hist.items) && hist.items.length >= 1, `推送历史 ${hist.items?.length} 条`);
const lastPush = hist.items?.[0];
if (lastPush) console.log("最近推送:", JSON.stringify({ trigger: lastPush.trigger, selected: lastPush.selected, pushed: lastPush.pushed, channels: lastPush.channels, message: lastPush.message }).slice(0, 400));

// 6) mock 是否收到真实情报
import fs from 'node:fs';
const recv = JSON.parse(fs.readFileSync(new URL('./mock_received.json', import.meta.url), 'utf8'));
const vulnPush = recv.find(r => (r.body || "").includes("socradarbot") && (r.body || "").includes("漏洞"));
ok(!!vulnPush, `mock webhook 共收到 ${recv.length} 次推送，含真实情报`);
if (vulnPush) console.log("推送报文片段:", vulnPush.body.slice(0, 600));

console.log(`\nE2E RESULT: ${fail === 0 ? "PASS" : "FAIL (" + fail + ")"}`);
process.exit(fail ? 1 : 0);
