// OSCS 开源安全情报预警（墨菲安全）适配器。
//
// 接口契约来自 watchvuln 的 grab/oscs.go：
//
//	POST https://www.oscs1024.com/oscs/v1/intelligence/list  {"page":1,"per_page":10}
//	POST https://www.oscs1024.com/oscs/v1/vdb/info          {"vuln_no":"MPS-xxxx"}
//
// 列表只给标题/等级，详情才有 CVSS、CVE、影响组件与参考链接，因此列表后按 MPS 编号
// 并发补详情（限流 4 并发），详情失败则回退列表字段，保证单条失败不影响整体。
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"socradarbot/internal/enrich"
	"socradarbot/internal/model"
)

const (
	oscsListURL   = "https://www.oscs1024.com/oscs/v1/intelligence/list"
	oscsDetailURL = "https://www.oscs1024.com/oscs/v1/vdb/info"
)

type oscsFetcher struct{ client *http.Client }

func (f *oscsFetcher) Name() string { return "oscs" }

type oscsListItem struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	URL              string `json:"url"`
	Mps              string `json:"mps"`
	IntelligenceType int    `json:"intelligence_type"`
	PublicTime       string `json:"public_time"`
	IsPush           int    `json:"is_push"`
	IsPoc            int    `json:"is_poc"`
	IsExp            int    `json:"is_exp"`
	Level            string `json:"level"`
}

type oscsDetail struct {
	VulnNo      string  `json:"vuln_no"`
	VulnTitle   string  `json:"vuln_title"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Level       string  `json:"level"`
	CvssScore   float64 `json:"cvss_score"`
	CveID       string  `json:"cve_id"`
	PublishTime int64   `json:"publish_time"`
	Poc         bool    `json:"poc"`
	Exp         bool    `json:"exp"`
	VulnType    string  `json:"vuln_type"`
	VulnSuggest string  `json:"vuln_suggest"`
	References  []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"references"`
	Effect []struct {
		Name               string `json:"name"`
		AffectedVersion    string `json:"affected_version"`
		AffectedAllVersion bool   `json:"affected_all_version"`
	} `json:"effect"`
}

func (f *oscsFetcher) Fetch(ctx context.Context, limit int) ([]model.Item, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 20 {
		limit = 20
	}
	listBody, _ := json.Marshal(map[string]any{"page": 1, "per_page": limit})
	raw, err := f.post(ctx, oscsListURL, listBody)
	if err != nil {
		return nil, err
	}
	var listResp struct {
		Data struct {
			Total int            `json:"total"`
			Data  []oscsListItem `json:"data"`
		} `json:"data"`
		Success bool   `json:"success"`
		Code    int    `json:"code"`
		Info    string `json:"info"`
	}
	if err := json.Unmarshal(raw, &listResp); err != nil {
		return nil, fmt.Errorf("OSCS 列表解析失败: %w", err)
	}
	if listResp.Code != 200 || !listResp.Success {
		return nil, fmt.Errorf("OSCS 接口返回 code=%d %s", listResp.Code, listResp.Info)
	}
	items := listResp.Data.Data
	if len(items) > limit {
		items = items[:limit]
	}

	out := make([]model.Item, len(items))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = f.buildItem(ctx, items[i])
		}(i)
	}
	wg.Wait()

	filtered := out[:0]
	for _, it := range out {
		if it.ID != "" && it.Title != "" {
			filtered = append(filtered, it)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Published > filtered[j].Published })
	return filtered, nil
}

func (f *oscsFetcher) buildItem(ctx context.Context, l oscsListItem) model.Item {
	item := model.Item{
		ID: "oscs-" + strings.ToLower(l.Mps), Title: strings.TrimSpace(l.Title),
		Source: "oscs", Published: datePart(l.PublicTime), Severity: oscsSeverity(l.Level),
		Refs:         []string{"https://www.oscs1024.com/hd/" + l.Mps},
		Tags:         oscsTags(l.IntelligenceType, l.IsPush, l.IsPoc, l.IsExp),
		POCDisclosed: l.IsPoc == 1 || l.IsExp == 1,
	}
	body, _ := json.Marshal(map[string]string{"vuln_no": l.Mps})
	raw, err := f.post(ctx, oscsDetailURL, body)
	if err != nil {
		return item
	}
	var doc struct {
		Data    []oscsDetail `json:"data"`
		Success bool         `json:"success"`
		Code    int          `json:"code"`
		Info    string       `json:"info"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Code != 200 || !doc.Success || len(doc.Data) == 0 {
		return item
	}
	d := doc.Data[0]
	item.Title = firstNonEmptyStr(d.VulnTitle, d.Title, item.Title)
	item.Summary = truncateText(stripHTML(d.Description), 600)
	item.Severity = oscsSeverity(firstNonEmptyStr(d.Level, l.Level))
	item.CVEs = enrich.ExtractCVEs(d.CveID)
	if d.CvssScore > 0 {
		v := d.CvssScore
		item.CVSS = &v
	}
	if d.PublishTime > 0 {
		item.Published = time.UnixMilli(d.PublishTime).Format("2006-01-02")
	}
	if d.Poc || d.Exp {
		item.Tags = appendUniqueStr(item.Tags, "PoC公开")
		item.POCDisclosed = true
	}
	if d.VulnType != "" {
		item.Tags = appendUniqueStr(item.Tags, d.VulnType)
	}
	for _, ref := range d.References {
		if ref.URL != "" && len(item.Refs) < 8 {
			item.Refs = appendUniqueStr(item.Refs, ref.URL)
		}
	}
	for _, e := range d.Effect {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			continue
		}
		ver := strings.TrimSpace(e.AffectedVersion)
		if e.AffectedAllVersion || ver == "" {
			name += "（全部版本）"
		} else {
			name += " " + truncateText(ver, 60)
		}
		if len(item.Affected) < 5 {
			item.Affected = appendUniqueStr(item.Affected, name)
		}
	}
	return item
}

func (f *oscsFetcher) post(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", "https://www.oscs1024.com/cm")
	req.Header.Set("Origin", "https://www.oscs1024.com")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSCS 接口 HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func oscsSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "严重", "超危":
		return "critical"
	case "high", "高危":
		return "high"
	case "medium", "中危":
		return "medium"
	case "low", "低危":
		return "low"
	}
	return "unknown"
}

func oscsTags(intelType, isPush, isPoc, isExp int) []string {
	tags := []string{"oscs"}
	switch intelType {
	case 1:
		tags = append(tags, "公开漏洞")
	case 2:
		tags = append(tags, "墨菲安全独家")
	case 3:
		tags = append(tags, "投毒情报")
	}
	if isPush == 1 {
		tags = append(tags, "发布预警")
	}
	if isPoc == 1 || isExp == 1 {
		tags = append(tags, "PoC公开")
	}
	return tags
}

func datePart(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func appendUniqueStr(list []string, v string) []string {
	for _, s := range list {
		if s == v {
			return list
		}
	}
	return append(list, v)
}

func stripHTML(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch r {
		case '<':
			inTag = true
		case '>':
			inTag = false
		default:
			if !inTag {
				b.WriteRune(r)
			}
		}
	}
	return strings.TrimSpace(strings.ReplaceAll(b.String(), "&nbsp;", " "))
}
