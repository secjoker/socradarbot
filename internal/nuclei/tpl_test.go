package nuclei

import (
	"context"
	"strings"
	"testing"

	"socradarbot/internal/model"
)

func TestSlug(t *testing.T) {
	if got := Slug("CVE-2026-1234 Apache RCE!!"); got != "cve-2026-1234-apache-rce" {
		t.Fatalf("unexpected slug: %s", got)
	}
	if got := Slug("中文"); got != "ai-bobao-vuln" {
		t.Fatalf("fallback expected, got %s", got)
	}
}

func TestGenerateHeuristic(t *testing.T) {
	cvss := 9.8
	v := &model.Vuln{
		ID: "art-deadbeef", Name: "测试系统远程代码执行漏洞",
		Summary: "攻击者可通过 users 接口注入命令。", Severity: "high", CVSS: &cvss,
		Refs: []string{"https://example.com/advisory"},
	}
	poc := "import requests\n\n" +
		"url = 'http://target/api/v1/users?id=1'\n" +
		"r = requests.get(url, timeout=5)\n" +
		"if 'root' in r.text:\n    print('vulnerable')\n"
	out, origin, err := Generate(context.Background(), v, poc, nil, false)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if origin != "heuristic" {
		t.Fatalf("origin want heuristic got %s", origin)
	}
	if !strings.Contains(out, "{{BaseURL}}/api/v1/users") {
		t.Fatalf("path 未正确提取:\n%s", out)
	}
	if err := Validate([]byte(out)); err != nil {
		t.Fatalf("生成的模板未通过自检: %v\n%s", err, out)
	}
}

func TestGenerateBlocksWriteRisk(t *testing.T) {
	v := &model.Vuln{ID: "art-1", Name: "后台命令执行", Summary: "exec", Severity: "critical"}
	poc := "POST /admin/exec HTTP/1.1\nHost: target\n"
	if _, _, err := Generate(context.Background(), v, poc, nil, false); err == nil {
		t.Fatal("写操作模板应被拦截")
	}
	if _, _, err := Generate(context.Background(), v, poc, nil, true); err != nil {
		t.Fatalf("allow_write=true 时应放行: %v", err)
	}
}

func TestValidateRejectsBadTemplate(t *testing.T) {
	if err := Validate([]byte("id: BAD-ID\ninfo:\n  severity: high\nhttp:\n  - path: ['/']\n    matchers: []\n")); err == nil {
		t.Fatal("非法模板应校验失败")
	}
}
