// 奇安信威胁情报中心（TI）公开接口适配器。
//
// 接口契约来自 watchvuln 的 grab/ti.go：
//
//	POST https://ti.qianxin.com/alpha-api/v2/vuln/one-day
//
// 响应同时包含「重点漏洞新增」与「PoC/EXP 新增」两组数据，后者数量更多。
// 标签（POC公开 / 奇安信CERT验证 / 技术细节公开）是极强的高价值信号，原样保留。
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

	"socradarbot/internal/enrich"
	"socradarbot/internal/model"
)

const tiOneDayURL = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day"

type tiFetcher struct{ client *http.Client }

func (f *tiFetcher) Name() string { return "qianxin-ti" }

type tiItem struct {
	ID          int    `json:"id"`
	VulnName    string `json:"vuln_name"`
	QvdCode     string `json:"qvd_code"`
	CveCode     string `json:"cve_code"`
	PublishTime string `json:"publish_time"`
	Description string `json:"description"`
	RatingLevel string `json:"rating_level"`
	PocFlag     int    `json:"poc_flag"`
	Tag         []struct {
		Name string `json:"name"`
	} `json:"tag"`
}

func (f *tiFetcher) Fetch(ctx context.Context, limit int) ([]model.Item, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tiOneDayURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", "https://ti.qianxin.com/")
	req.Header.Set("Origin", "https://ti.qianxin.com")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("奇安信 TI HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
		Data    struct {
			KeyVulnAdd []tiItem `json:"key_vuln_add"`
			PocExpAdd  []tiItem `json:"poc_exp_add"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("奇安信 TI 解析失败: %w", err)
	}
	if doc.Status != 10000 {
		return nil, fmt.Errorf("奇安信 TI 返回 status=%d %s", doc.Status, doc.Message)
	}

	seen := map[string]bool{}
	merged := make([]tiItem, 0, len(doc.Data.KeyVulnAdd)+len(doc.Data.PocExpAdd))
	for _, list := range [][]tiItem{doc.Data.KeyVulnAdd, doc.Data.PocExpAdd} {
		for _, it := range list {
			key := strings.ToUpper(strings.TrimSpace(it.QvdCode))
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, it)
		}
	}
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].PublishTime > merged[j].PublishTime })
	if len(merged) > limit {
		merged = merged[:limit]
	}

	out := make([]model.Item, 0, len(merged))
	for _, d := range merged {
		out = append(out, tiToItem(d))
	}
	return out, nil
}

func tiToItem(d tiItem) model.Item {
	tags := []string{"奇安信TI"}
	pocDisclosed := d.PocFlag == 1
	for _, t := range d.Tag {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			continue
		}
		if strings.Contains(name, "POC") || strings.Contains(name, "EXP") || strings.Contains(name, "PoC") {
			pocDisclosed = true
		}
		tags = appendUniqueStr(tags, name)
	}
	refs := []string{}
	if d.ID > 0 {
		refs = append(refs, fmt.Sprintf("https://ti.qianxin.com/vulnerability/detail/%d", d.ID))
	}
	item := model.Item{
		ID:           "ti-" + strings.ToLower(strings.TrimSpace(d.QvdCode)),
		Title:        strings.TrimSpace(d.VulnName),
		Source:       "qianxin-ti",
		Summary:      truncateText(stripHTML(d.Description), 600),
		Published:    datePart(d.PublishTime),
		Severity:     tiSeverity(d.RatingLevel),
		CVEs:         enrich.ExtractCVEs(d.CveCode, d.VulnName),
		Tags:         tags,
		Refs:         refs,
		POCDisclosed: pocDisclosed,
	}
	return item
}

func tiSeverity(level string) string {
	switch strings.TrimSpace(level) {
	case "极危", "严重", "critical":
		return "critical"
	case "高危", "high":
		return "high"
	case "中危", "medium":
		return "medium"
	case "低危", "low":
		return "low"
	}
	return "unknown"
}
