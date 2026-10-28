package enrich

import (
	"testing"
	"time"

	"socradarbot/internal/config"
	"socradarbot/internal/model"
)

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs("修复 CVE-2026-1234 与 cve-2025-99999，重复 CVE-2026-1234")
	if len(got) != 2 || got[0] != "CVE-2026-1234" || got[1] != "CVE-2025-99999" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestExtractCVSS(t *testing.T) {
	cases := map[string]float64{
		"该漏洞 CVSS 9.8，影响严重": 9.8,
		"CVSS:3.1 7.5 高危":   7.5,
		"综合评分 8.1 分":        8.1,
		"没有分数":              0,
	}
	for text, want := range cases {
		got, ok := ExtractCVSS(text)
		if want == 0 {
			if ok {
				t.Errorf("%q: 不应提取到分数，得到 %.1f", text, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("%q: want %.1f got %.1f ok=%v", text, want, got, ok)
		}
	}
}

func TestInferSeverity(t *testing.T) {
	cases := map[string]string{
		"某系统远程代码执行漏洞":   "high",
		"【严重】核心网关未授权访问": "critical",
		"某插件信息泄露漏洞":     "medium",
		"低危安全问题说明":      "low",
		"一次普通的产品更新":     "unknown",
	}
	for text, want := range cases {
		if got := InferSeverity(text); got != want {
			t.Errorf("%q: want %s got %s", text, want, got)
		}
	}
}

func TestScoreHighValue(t *testing.T) {
	cvss := 9.8
	v := &model.Vuln{
		ID: "nvd-cve-2026-1234", Name: "Apache RCE", Severity: "critical",
		CVSS: &cvss, EPSS: 0.8, KEV: true, POCSource: "ai",
		CVEs: []string{"CVE-2026-1234"}, Published: time.Now().Format("2006-01-02"),
	}
	score, hv, reasons := Score(v, config.Push{MinScore: 60})
	if score != 100 {
		t.Fatalf("score want 100 got %d", score)
	}
	if !hv {
		t.Fatal("应判定为高价值")
	}
	if len(reasons) < 4 {
		t.Fatalf("判定依据不足: %v", reasons)
	}
}

func TestScoreThresholdAndBlacklist(t *testing.T) {
	cvss := 5.5
	v := &model.Vuln{
		ID: "nvd-cve-2026-2", Name: "phpMyFAQ 信息泄露", Severity: "medium",
		CVSS: &cvss, CVEs: []string{"CVE-2026-2"}, Published: time.Now().Format("2006-01-02"),
	}
	if _, hv, _ := Score(v, config.Push{MinScore: 60}); hv {
		t.Fatal("低分条目不应判定为高价值")
	}
	high := 9.8
	v2 := &model.Vuln{Name: "WordPress 插件 RCE", Severity: "critical", CVSS: &high,
		CVEs: []string{"CVE-2026-3"}, POCSource: "ai", Published: time.Now().Format("2006-01-02")}
	if _, hv, _ := Score(v2, config.Push{MinScore: 60, KeywordsExclude: []string{"wordpress"}}); hv {
		t.Fatal("黑名单命中不应推送")
	}
	if _, hv, _ := Score(v2, config.Push{MinScore: 60, RequirePOC: true, RequireCVE: true}); !hv {
		t.Fatal("满足 require_cve/require_poc 时应为高价值")
	}
}
