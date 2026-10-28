package push

import (
	"strings"
	"testing"

	"socradarbot/internal/model"
)

func TestMessageFormat(t *testing.T) {
	cvss := 9.8
	v := &model.Vuln{
		ID: "nvd-cve-2026-1234", Name: "Apache HTTP Server 远程代码执行漏洞",
		Severity: "critical", CVSS: &cvss, Score: 95, Source: "nvd",
		Published: "2026-10-19", Affected: []string{"apache http_server"},
		Summary:   "未授权攻击者可构造恶意请求执行任意代码。",
		POCSource: "ai", KEV: true, CVEs: []string{"CVE-2026-1234"},
		ScoreReasons: []string{"CVSS 9.8（严重）", "CISA KEV 已知在野利用"},
	}
	blocks := messageBlocks([]*model.Vuln{v})
	if len(blocks) != 1 {
		t.Fatalf("want 1 block got %d", len(blocks))
	}
	s := blocks[0]
	for _, want := range []string{
		"[严重]", "CVE-2026-1234", "评分：95", "CVSS 9.8", "CISA KEV ✅",
		"影响：apache http_server", "判定：CVSS 9.8（严重）",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("推送文案缺少 %q:\n%s", want, s)
		}
	}
}

func TestChunkMarkdown(t *testing.T) {
	blocks := []string{
		strings.Repeat("A", 2000),
		strings.Repeat("B", 2000),
		strings.Repeat("C", 2000),
	}
	chunks := chunkMarkdown("SocradarBot 情报", blocks, 3800)
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c) > 3800 {
			t.Errorf("chunk %d 超出上限: %d bytes", i, len(c))
		}
		if !strings.HasPrefix(c, "## SocradarBot 情报") {
			t.Errorf("chunk %d 缺少标题头", i)
		}
	}
}

func TestMessageEscapesMissingFields(t *testing.T) {
	v := &model.Vuln{ID: "art-1", Name: "无 CVE 的情报", Severity: "unknown", Score: 30}
	s := messageBlocks([]*model.Vuln{v})[0]
	if strings.Contains(s, "CVE：") {
		t.Errorf("无 CVE 时不应输出 CVE 行:\n%s", s)
	}
	if !strings.Contains(s, "来源：-") {
		t.Errorf("缺字段时应使用占位:\n%s", s)
	}
}
