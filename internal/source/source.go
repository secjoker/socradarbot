// Package source 负责多源采集与归一化。
//
// 数据源分两类：
//  1. 文章源：通用 RSS/Atom（内置 seebug / 先知 / exploit-db + 用户自定义）
//  2. 结构化情报源（本次新增，用于富化字段）：
//     - cisa-kev        已知在野利用漏洞目录（自带厂商/产品/处置建议）
//     - github-advisory GitHub 安全公告（自带 CVSS、受影响包、CWE）
//     - nvd             NVD 近期 CVE（自带 CVSS、CPE 影响范围）
//
// 所有源统一输出 model.Item，字段缺失由 enrich 层补齐。
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"socradarbot/internal/config"
	"socradarbot/internal/crawler"
	"socradarbot/internal/enrich"
	"socradarbot/internal/model"
)

// Fetcher 是一个可采集的数据源。
type Fetcher interface {
	Name() string
	Fetch(ctx context.Context, limit int) ([]model.Item, error)
}

// Registry 管理所有启用的数据源。
type Registry struct {
	fetchers []Fetcher
}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

// Info 是数据源的元信息，供 /api/sources 与前端展示。
type Info struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // rss | json
	URL         string `json:"url"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// catalog 是内置源目录（筛选结果见 docs/SOURCES.md）。
var catalog = []Info{
	{"seebug", "Seebug Paper", "rss", "https://paper.seebug.org/rss/", "知道创宇 Seebug 漏洞文章 RSS", true},
	{"先知", "先知社区", "rss", "https://xz.aliyun.com/feed", "阿里云先知社区技术文章 RSS", true},
	{"exploit-db", "Exploit-DB", "rss", "https://www.exploit-db.com/rss.xml", "公开 Exploit 数据库 RSS", true},
	{"chaitin", "长亭漏洞库", "json", "https://stack.chaitin.com/vuldb/index", "CT Stack 公开 API，含 CT 编号 / CVSS / CVE", true},
	{"oscs", "OSCS 开源安全情报", "json", "https://www.oscs1024.com/cm", "墨菲安全开源组件漏洞预警，含影响版本与 PoC 标记", true},
	{"qianxin-ti", "奇安信威胁情报中心", "json", "https://ti.qianxin.com/", "一日重点漏洞与 PoC/EXP 新增，含 CERT 验证标签", true},
	{"cisa-kev", "CISA KEV", "json", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "已知在野利用漏洞目录（官方镜像回退）", true},
	{"nvd", "NVD", "json", "https://nvd.nist.gov/", "CVE / CVSS / CPE 官方数据", true},
	{"github-advisory", "GitHub Advisory", "json", "https://github.com/advisories", "GitHub 安全公告，含受影响包与 CWE", true},
}

func disabledSet(cfg config.Config) map[string]bool {
	m := make(map[string]bool, len(cfg.Sources.Disabled))
	for _, id := range cfg.Sources.Disabled {
		m[strings.TrimSpace(id)] = true
	}
	return m
}

func sourceEnabled(cfg config.Config, id string) bool {
	if disabledSet(cfg)[id] {
		return false
	}
	switch id {
	case "cisa-kev":
		return cfg.Enrich.Enabled && cfg.Enrich.KEV
	case "nvd":
		return cfg.Enrich.Enabled && cfg.Enrich.NVD
	case "github-advisory":
		return cfg.Enrich.Enabled && cfg.Enrich.GitHubAdvisory
	}
	return true
}

// Catalog 返回内置源目录及当前启用状态。
func Catalog(cfg config.Config) []Info {
	out := make([]Info, 0, len(catalog))
	for _, c := range catalog {
		c.Enabled = sourceEnabled(cfg, c.ID)
		out = append(out, c)
	}
	return out
}

// Build 按配置装配启用的数据源。
func Build(cfg config.Config, client *http.Client, en *enrich.Enricher) *Registry {
	r := &Registry{}
	add := func(id string, f Fetcher) {
		if sourceEnabled(cfg, id) {
			r.fetchers = append(r.fetchers, f)
		}
	}
	for _, feed := range crawler.BuiltinFeeds {
		add(feed.Name, &rssFetcher{name: feed.Name, url: feed.URL, client: client})
	}
	add("chaitin", &chaitinFetcher{client: client})
	add("oscs", &oscsFetcher{client: client})
	add("qianxin-ti", &tiFetcher{client: client})
	if en != nil {
		add("cisa-kev", &kevFetcher{en: en})
	}
	add("github-advisory", &ghsaFetcher{client: client, token: cfg.Enrich.GitHubToken})
	add("nvd", &nvdFetcher{client: client})
	for _, s := range cfg.Sources.Custom {
		if s.Enabled && s.URL != "" {
			r.fetchers = append(r.fetchers, &rssFetcher{name: s.Name, url: s.URL, client: client})
		}
	}
	return r
}

// Names 返回已启用的源名称，便于状态展示与排障。
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.fetchers))
	for _, f := range r.fetchers {
		out = append(out, f.Name())
	}
	return out
}

// FetchAll 并发拉取所有源；单源失败只记录错误，不影响其他源。
func (r *Registry) FetchAll(ctx context.Context, limit int) ([]model.Item, map[string]string) {
	type result struct {
		items []model.Item
		name  string
		err   error
	}
	ch := make(chan result, len(r.fetchers))
	var wg sync.WaitGroup
	for _, f := range r.fetchers {
		wg.Add(1)
		go func(f Fetcher) {
			defer wg.Done()
			items, err := f.Fetch(ctx, limit)
			ch <- result{items: items, name: f.Name(), err: err}
		}(f)
	}
	wg.Wait()
	close(ch)

	all := []model.Item{}
	errs := map[string]string{}
	for res := range ch {
		if res.err != nil {
			errs[res.name] = res.err.Error()
			continue
		}
		all = append(all, res.items...)
	}
	return all, errs
}

// ── RSS 文章源 ────────────────────────────────────────────

type rssFetcher struct {
	name   string
	url    string
	client *http.Client
}

func (f *rssFetcher) Name() string { return f.name }

func (f *rssFetcher) Fetch(ctx context.Context, limit int) ([]model.Item, error) {
	items, err := crawler.FetchFeed(ctx, f.client, f.name, f.url, limit)
	if err != nil {
		return nil, err
	}
	return items, nil
}

// ── CISA KEV 源 ──────────────────────────────────────────

type kevFetcher struct{ en *enrich.Enricher }

func (f *kevFetcher) Name() string { return "cisa-kev" }

func (f *kevFetcher) Fetch(ctx context.Context, limit int) ([]model.Item, error) {
	if err := f.en.LoadKEV(ctx); err != nil {
		return nil, err
	}
	entries := f.en.KEVAll()
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]model.Item, 0, len(entries))
	for _, e := range entries {
		if e.CVEID == "" {
			continue
		}
		summary := strings.TrimSpace(e.Description)
		if e.Action != "" {
			summary += " 处置建议：" + e.Action
		}
		affected := []string{}
		if e.Vendor != "" || e.Product != "" {
			affected = append(affected, strings.TrimSpace(e.Vendor+" "+e.Product))
		}
		tags := []string{"kev", "在野利用"}
		if strings.EqualFold(e.Ransomware, "known") {
			tags = append(tags, "勒索软件")
		}
		out = append(out, model.Item{
			ID:        "kev-" + strings.ToLower(e.CVEID),
			Title:     fmt.Sprintf("%s（%s）", e.Name, e.CVEID),
			Source:    "cisa-kev",
			Summary:   summary,
			Published: e.DateAdded,
			Severity:  "high", // KEV 代表已被在野利用，按高危处理
			CVEs:      []string{strings.ToUpper(e.CVEID)},
			Tags:      tags,
			Affected:  affected,
			Refs: []string{
				"https://nvd.nist.gov/vuln/detail/" + strings.ToUpper(e.CVEID),
				"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			},
			POCProvided: true, // KEV 已知被利用，视为具备可用利用方式
		})
	}
	return out, nil
}

// ── GitHub Security Advisory 源 ──────────────────────────

type ghsaFetcher struct {
	client *http.Client
	token  string
}

func (f *ghsaFetcher) Name() string { return "github-advisory" }

func (f *ghsaFetcher) Fetch(ctx context.Context, limit int) ([]model.Item, error) {
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	u := fmt.Sprintf("https://api.github.com/advisories?per_page=%d&sort=published&direction=desc", limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SocradarBot/1.0")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub Advisory HTTP %d", resp.StatusCode)
	}
	var raw []struct {
		GHSAID    string `json:"ghsa_id"`
		CVEID     string `json:"cve_id"`
		Summary   string `json:"summary"`
		Desc      string `json:"description"`
		Severity  string `json:"severity"`
		Published string `json:"published_at"`
		HTMLURL   string `json:"html_url"`
		CVSS      struct {
			Score float64 `json:"score"`
		} `json:"cvss"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
		Vulnerabilities []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
		} `json:"vulnerabilities"`
		CWEs []struct {
			CWEID string `json:"cwe_id"`
		} `json:"cwes"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("GitHub Advisory 解析失败: %w", err)
	}
	out := []model.Item{}
	for _, a := range raw {
		if a.GHSAID == "" || a.Summary == "" {
			continue
		}
		refs := []string{}
		if a.HTMLURL != "" {
			refs = append(refs, a.HTMLURL)
		}
		for _, r := range a.References {
			if r.URL != "" && len(refs) < 6 {
				refs = append(refs, r.URL)
			}
		}
		affected := []string{}
		seen := map[string]bool{}
		for _, v := range a.Vulnerabilities {
			name := strings.TrimSpace(v.Package.Name)
			if name == "" {
				continue
			}
			label := name
			if v.Package.Ecosystem != "" {
				label = v.Package.Ecosystem + ":" + name
			}
			if !seen[label] {
				seen[label] = true
				affected = append(affected, label)
			}
		}
		cwes := []string{}
		for _, c := range a.CWEs {
			if c.CWEID != "" {
				cwes = append(cwes, c.CWEID)
			}
		}
		pub := a.Published
		if len(pub) >= 10 {
			pub = pub[:10]
		}
		var cvss *float64
		if a.CVSS.Score > 0 {
			v := a.CVSS.Score
			cvss = &v
		}
		out = append(out, model.Item{
			ID: "ghsa-" + strings.ToLower(a.GHSAID), Title: a.Summary,
			Source: "github-advisory", Summary: truncate(a.Desc, 600),
			Published: pub, Severity: strings.ToLower(a.Severity), CVSS: cvss,
			CVEs:     enrich.ExtractCVEs(a.CVEID),
			Refs:     refs,
			Affected: affected, CWE: cwes,
			Tags: []string{"github-advisory"},
		})
	}
	return out, nil
}

// ── NVD 源 ───────────────────────────────────────────────

type nvdFetcher struct{ client *http.Client }

func (f *nvdFetcher) Name() string { return "nvd" }

func (f *nvdFetcher) Fetch(ctx context.Context, limit int) ([]model.Item, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -3)
	q := url.Values{}
	q.Set("resultsPerPage", fmt.Sprint(limit))
	q.Set("pubStartDate", start.Format("2006-01-02T15:04:05.000")+"+00:00")
	q.Set("pubEndDate", now.Format("2006-01-02T15:04:05.000")+"+00:00")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://services.nvd.nist.gov/rest/json/cves/2.0?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SocradarBot/1.0")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					V31 []struct {
						Data struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					V30 []struct {
						Data struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("NVD 解析失败: %w", err)
	}
	out := []model.Item{}
	for _, w := range doc.Vulnerabilities {
		c := w.CVE
		if c.ID == "" {
			continue
		}
		desc := ""
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		var cvss *float64
		sev := ""
		if len(c.Metrics.V31) > 0 {
			v := c.Metrics.V31[0].Data.BaseScore
			cvss = &v
			sev = strings.ToLower(c.Metrics.V31[0].Data.BaseSeverity)
		} else if len(c.Metrics.V30) > 0 {
			v := c.Metrics.V30[0].Data.BaseScore
			cvss = &v
			sev = strings.ToLower(c.Metrics.V30[0].Data.BaseSeverity)
		}
		cwes := []string{}
		for _, wk := range c.Weaknesses {
			for _, d := range wk.Description {
				if strings.HasPrefix(d.Value, "CWE-") {
					cwes = append(cwes, d.Value)
				}
			}
		}
		affected := []string{}
		seenCpe := map[string]bool{}
		for _, cfg := range c.Configurations {
			for _, n := range cfg.Nodes {
				for _, m := range n.CPEMatch {
					if label := cpeProduct(m.Criteria); label != "" && !seenCpe[label] {
						seenCpe[label] = true
						affected = append(affected, label)
					}
				}
			}
		}
		refs := []string{"https://nvd.nist.gov/vuln/detail/" + c.ID}
		for _, r := range c.References {
			if r.URL != "" && len(refs) < 6 {
				refs = append(refs, r.URL)
			}
		}
		pub := c.Published
		if len(pub) >= 10 {
			pub = pub[:10]
		}
		out = append(out, model.Item{
			ID:     "nvd-" + strings.ToLower(c.ID),
			Title:  fmt.Sprintf("%s %s", c.ID, truncate(desc, 70)),
			Source: "nvd", Summary: desc, Published: pub,
			Severity: sev, CVSS: cvss, CVEs: []string{c.ID},
			Refs: refs, Affected: affected, CWE: cwes,
			Tags: []string{"nvd"},
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Published > out[j].Published })
	return out, nil
}

// cpeProduct 把 cpe:2.3:a:vendor:product:version 转成 "vendor product"。
func cpeProduct(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	vendor, product := parts[3], parts[4]
	if vendor == "*" || product == "*" || vendor == "" || product == "" {
		return ""
	}
	return vendor + " " + product
}

func truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
