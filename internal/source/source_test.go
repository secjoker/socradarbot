package source

import (
	"encoding/json"
	"testing"

	"socradarbot/internal/config"
)

func TestChaitinFlexFloat(t *testing.T) {
	cases := map[string]float64{
		`{"cvss3": 9.8}`:            9.8,
		`{"cvss3": {"score": 8.1}}`: 8.1,
		`{"cvss3": "7.5"}`:          7.5,
		`{"cvss3": null}`:           0,
	}
	for doc, want := range cases {
		var v struct {
			CVSS3 flexFloat `json:"cvss3"`
		}
		if err := json.Unmarshal([]byte(doc), &v); err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		if float64(v.CVSS3) != want {
			t.Errorf("%s: want %.1f got %.1f", doc, want, float64(v.CVSS3))
		}
	}
}

func TestChaitinToItem(t *testing.T) {
	cve := "CVE-2026-1234"
	item, ok := chaitinToItem(chaitinItem{
		Title: "CVE-2026-1234", SummaryEN: "Remote code execution in Example Server.",
		Severity: "high", CTID: "CT-100", CVEID: &cve, CreatedAt: "2026-10-19T10:00:00+08:00",
	})
	if !ok {
		t.Fatal("应生成条目")
	}
	if item.ID != "chaitin-ct-100" || item.Severity != "high" {
		t.Fatalf("映射异常: %+v", item)
	}
	if item.Published != "2026-10-19" {
		t.Fatalf("published 异常: %s", item.Published)
	}
	if len(item.CVEs) != 1 || item.CVEs[0] != cve {
		t.Fatalf("CVE 异常: %v", item.CVEs)
	}
	if item.Title == "CVE-2026-1234" {
		t.Fatal("只有 CVE 编号时应拼接摘要作为可读标题")
	}
}

func TestOscsMapping(t *testing.T) {
	if oscsSeverity("严重") != "critical" || oscsSeverity("High") != "high" || oscsSeverity("中危") != "medium" {
		t.Fatal("OSCS 严重性映射异常")
	}
	tags := oscsTags(2, 1, 1, 0)
	for _, want := range []string{"oscs", "墨菲安全独家", "发布预警", "PoC公开"} {
		found := false
		for _, tg := range tags {
			if tg == want {
				found = true
			}
		}
		if !found {
			t.Errorf("缺少标签 %s: %v", want, tags)
		}
	}
}

func TestTiToItem(t *testing.T) {
	item := tiToItem(tiItem{
		ID: 523106, VulnName: "Drupal Field UI 远程代码执行漏洞(CVE-2026-108097)",
		QvdCode: "QVD-2026-88162", CveCode: "CVE-2026-108097",
		PublishTime: "2026-10-14", RatingLevel: "极危", PocFlag: 1,
		Tag: []struct {
			Name string `json:"name"`
		}{{Name: "POC公开"}, {Name: "奇安信CERT验证"}},
	})
	if item.ID != "ti-qvd-2026-88162" || item.Severity != "critical" || item.Published != "2026-10-14" {
		t.Fatalf("TI 映射异常: %+v", item)
	}
	if !item.POCDisclosed {
		t.Fatal("PoC 公开标记未生效")
	}
	if len(item.Refs) != 1 || item.Refs[0] != "https://ti.qianxin.com/vulnerability/detail/523106" {
		t.Fatalf("详情链接异常: %v", item.Refs)
	}
}

func TestCatalogRespectsToggles(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sources.Disabled = []string{"chaitin"}
	cfg.Enrich.NVD = false
	status := map[string]bool{}
	for _, info := range Catalog(cfg) {
		status[info.ID] = info.Enabled
	}
	if status["chaitin"] {
		t.Error("chaitin 应被 sources.disabled 停用")
	}
	if status["nvd"] {
		t.Error("nvd 应随 enrich.nvd=false 停用")
	}
	if !status["oscs"] || !status["qianxin-ti"] {
		t.Error("新源默认应启用")
	}
}
