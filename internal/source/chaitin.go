// 长亭漏洞库（CT Stack）公开 API 适配器。
//
// 接口契约来自 watchvuln 的 grab/chaitin.go：
//
//	GET https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=0&search=CT-
//	Referer/Origin 必须为 stack.chaitin.com，否则可能被拒。
//
// 返回结构化 JSON，无需解析 HTML，是 watchvuln 数据源中最稳定的一个。
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"socradarbot/internal/enrich"
	"socradarbot/internal/model"
)

const chaitinListURL = "https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=%d&search=CT-"

// flexFloat 兼容 API 中 cvss3 的两种形态：数字或 {"score": 9.8} 对象。
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexFloat(n)
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(str), 64); err == nil {
			*f = flexFloat(v)
		}
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err == nil {
		for _, k := range []string{"score", "base_score", "baseScore", "cvss"} {
			if v, ok := obj[k]; ok {
				if num, ok := v.(float64); ok {
					*f = flexFloat(num)
					break
				}
			}
		}
	}
	return nil // 无法识别时按 0 处理，不阻断整批解析
}

type chaitinFetcher struct{ client *http.Client }

func (f *chaitinFetcher) Name() string { return "chaitin" }

type chaitinItem struct {
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Summary        string    `json:"summary"`
	SummaryEN      string    `json:"summary_en"`
	Severity       string    `json:"severity"`
	CVSS3          flexFloat `json:"cvss3"`
	CTID           string    `json:"ct_id"`
	CVEID          *string   `json:"cve_id"`
	PocID          *string   `json:"poc_id"`
	References     *string   `json:"references"`
	DisclosureDate *string   `json:"disclosure_date"`
	CreatedAt      string    `json:"created_at"`
}

func (f *chaitinFetcher) Fetch(ctx context.Context, limit int) ([]model.Item, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 60 {
		limit = 60
	}
	out := []model.Item{}
	for offset := 0; len(out) < limit && offset < limit*2; offset += 15 {
		u := fmt.Sprintf(chaitinListURL, offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("User-Agent", browserUA)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Referer", "https://stack.chaitin.com/vuldb/index")
		req.Header.Set("Origin", "https://stack.chaitin.com")
		resp, err := f.client.Do(req)
		if err != nil {
			return out, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return out, fmt.Errorf("长亭接口 HTTP %d", resp.StatusCode)
		}
		if readErr != nil {
			return out, readErr
		}
		var doc struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
			Data struct {
				List []chaitinItem `json:"list"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return out, fmt.Errorf("长亭响应解析失败: %w", err)
		}
		if len(doc.Data.List) == 0 {
			break
		}
		for _, d := range doc.Data.List {
			if len(out) >= limit {
				break
			}
			if item, ok := chaitinToItem(d); ok {
				out = append(out, item)
			}
		}
		if len(doc.Data.List) < 15 {
			break
		}
	}
	return out, nil
}

func chaitinToItem(d chaitinItem) (model.Item, bool) {
	title := strings.TrimSpace(d.Title)
	summary := strings.TrimSpace(d.Summary)
	if summary == "" {
		summary = strings.TrimSpace(d.SummaryEN)
	}
	if title == "" {
		return model.Item{}, false
	}
	name := title
	// 长亭很多条目 title 只有 CVE 编号，用英文摘要补一段可读描述
	if !containsHan(name) && summary != "" {
		name = title + " " + truncateText(firstSentence(summary), 80)
	}
	published := ""
	if d.DisclosureDate != nil && strings.TrimSpace(*d.DisclosureDate) != "" {
		published = strings.TrimSpace(*d.DisclosureDate)[:minInt(10, len(strings.TrimSpace(*d.DisclosureDate)))]
	} else if len(d.CreatedAt) >= 10 {
		published = d.CreatedAt[:10]
	}
	cves := []string{}
	if d.CVEID != nil && strings.TrimSpace(*d.CVEID) != "" {
		cves = enrich.ExtractCVEs(*d.CVEID)
	}
	refs := []string{"https://stack.chaitin.com/vuldb/detail/" + d.ID}
	if d.References != nil {
		for _, r := range strings.Split(*d.References, "\n") {
			if r = strings.TrimSpace(r); r != "" && len(refs) < 8 {
				refs = append(refs, r)
			}
		}
	}
	sev := strings.ToLower(strings.TrimSpace(d.Severity))
	if sev == "" {
		sev = "unknown"
	}
	var cvss *float64
	if d.CVSS3 > 0 {
		v := float64(d.CVSS3)
		cvss = &v
	}
	pocDisclosed := d.PocID != nil && strings.TrimSpace(*d.PocID) != ""
	return model.Item{
		ID: "chaitin-" + strings.ToLower(d.CTID), Title: name, Source: "chaitin",
		Summary: truncateText(summary, 600), Published: published,
		Severity: sev, CVSS: cvss, CVEs: cves, Refs: refs,
		Tags: []string{"chaitin"}, POCDisclosed: pocDisclosed,
	}, true
}

func containsHan(s string) bool {
	for _, r := range s {
		if r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return false
}

func firstSentence(s string) string {
	if i := strings.IndexAny(s, "。.!?\n"); i > 0 {
		return s[:i+1]
	}
	return s
}

func truncateText(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
