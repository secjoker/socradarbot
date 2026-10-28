// Package enrich 负责数据富化与风险评分。
//
// 富化来源：
//   - CVE 编号：从标题、摘要、正文、引用链接中提取并去重
//   - EPSS：FIRST.org 利用概率预测（免费 API，批量查询 + 本地缓存）
//   - CISA KEV：已知在野利用漏洞目录（每日缓存，作为最高优先级信号）
//   - 严重性：CVSS 缺失时按等级关键词/CVSS 区间补齐
//
// 评分模型（0-100）用于"高价值情报"判定：
//
//	CVSS 基础分（0-80）+ EPSS（0-20）+ KEV（25）+ PoC（15）+ CVE（5）+ 新鲜度（5），截断到 100
//
// 每个加分项都会写入 score_reasons，保证推送可解释、可审计。
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"socradarbot/internal/config"
	"socradarbot/internal/model"
)

const (
	// CISA 官网在部分网络下会被 CDN 拒绝（403），因此准备官方 GitHub 镜像做回退。
	kevURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevMirror1 = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	kevMirror2 = "https://cdn.jsdelivr.net/gh/cisagov/kev-data@main/known_exploited_vulnerabilities.json"
	epssURL    = "https://api.first.org/data/v1/epss"
	browserUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

var kevURLs = []string{kevURL, kevMirror1, kevMirror2}

var cveRE = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

var (
	cvssTextRE  = regexp.MustCompile(`(?i)CVSS(?:\s*[:：]?\s*v?[23]\.[01])?[^0-9]{0,15}(\d{1,2}(?:\.\d)?)`)
	scoreTextRE = regexp.MustCompile(`(\d{1,2}\.\d)\s*分`)
)

var severityKeywords = []struct {
	level string
	words []string
}{
	{"critical", []string{"严重", "超危", "紧急", "critical", "紧急漏洞"}},
	{"high", []string{"高危", "高风险", "high", "rce", "远程代码执行", "命令执行", "任意文件",
		"未授权", "权限提升", "sql注入", "反序列化", "0day", "在野利用", "exploit"}},
	{"medium", []string{"中危", "medium", "信息泄露", "越权", "csrf", "xss", "ssrf", "拒绝服务"}},
	{"low", []string{"低危", "low", "安全提示", "加固建议"}},
}

// ExtractCVSS 从文本中提取 CVSS 分值（支持 "CVSS 9.8"、"CVSS:3.1 9.8"、"9.8 分"）。
func ExtractCVSS(text string) (float64, bool) {
	for _, re := range []*regexp.Regexp{cvssTextRE, scoreTextRE} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) < 2 {
				continue
			}
			v, err := strconv.ParseFloat(m[1], 64)
			if err == nil && v > 0 && v <= 10 {
				return v, true
			}
		}
	}
	return 0, false
}

// InferSeverity 依据标题/摘要中的中文等级词与漏洞类型推断严重性。
// 无法判断时返回 "unknown"，由后续 CVSS 推导兜底。
func InferSeverity(text string) string {
	low := strings.ToLower(text)
	for _, rule := range severityKeywords {
		for _, w := range rule.words {
			if strings.Contains(low, strings.ToLower(w)) {
				return rule.level
			}
		}
	}
	return "unknown"
}

// KEVEntry 是 CISA KEV 目录中的一条记录。
type KEVEntry struct {
	CVEID       string `json:"cveID"`
	Vendor      string `json:"vendorProject"`
	Product     string `json:"product"`
	Name        string `json:"vulnerabilityName"`
	DateAdded   string `json:"dateAdded"`
	Description string `json:"shortDescription"`
	Action      string `json:"requiredAction"`
	Ransomware  string `json:"knownRansomwareCampaignUse"`
}

// EPSS 是一条 EPSS 预测。
type EPSS struct {
	Score      float64
	Percentile float64
	At         time.Time
}

// Enricher 持有外部情报缓存。
type Enricher struct {
	cfg      config.Enrich
	cacheDir string
	client   *http.Client

	mu        sync.Mutex
	kev       map[string]KEVEntry
	kevLoaded time.Time
	epss      map[string]EPSS
	epssDirty bool
}

func New(cfg config.Enrich, cacheDir string) *Enricher {
	to := time.Duration(cfg.TimeoutSeconds) * time.Second
	if to <= 0 {
		to = 20 * time.Second
	}
	return &Enricher{
		cfg:      cfg,
		cacheDir: cacheDir,
		client:   &http.Client{Timeout: to},
		kev:      map[string]KEVEntry{},
		epss:     map[string]EPSS{},
	}
}

// ExtractCVEs 从任意文本中提取 CVE 编号（大写、去重、保序）。
func ExtractCVEs(texts ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range texts {
		for _, m := range cveRE.FindAllString(t, -1) {
			c := strings.ToUpper(m)
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// Severity 返回条目的严重性：优先显式等级，其次由 CVSS 推导。
func Severity(v *model.Vuln) string {
	if r := model.SeverityRank(v.Severity); r > 0 {
		return strings.ToLower(v.Severity)
	}
	if v.CVSS != nil {
		return model.SeverityFromCVSS(*v.CVSS)
	}
	return "unknown"
}

// Apply 就地补齐单条记录的 CVE、CVSS、严重性与 KEV 标记（EPSS 需批量查询，见 EPSSBatch）。
func (e *Enricher) Apply(v *model.Vuln) {
	if len(v.CVEs) == 0 {
		v.CVEs = ExtractCVEs(v.ID, v.Name, v.Summary, v.Principle, v.AttackScope, strings.Join(v.Refs, " "))
	} else {
		v.CVEs = dedupeUpper(v.CVEs)
	}
	text := v.Name + " " + v.Summary + " " + v.Principle + " " + v.AttackScope + " " + strings.Join(v.Tags, " ")
	// CVSS 缺失时尝试从正文/摘要提取，作为严重性推导依据
	if v.CVSS == nil {
		if score, ok := ExtractCVSS(text); ok {
			s := score
			v.CVSS = &s
		}
	}
	if v.Severity == "" || v.Severity == "unknown" {
		if v.CVSS != nil {
			v.Severity = model.SeverityFromCVSS(*v.CVSS)
			v.SeverityInferred = true
		} else if s := InferSeverity(text); s != "unknown" {
			v.Severity = s
			v.SeverityInferred = true
		}
	}
	if e.cfg.KEV {
		for _, c := range v.CVEs {
			if entry, ok := e.KEVEntry(c); ok {
				v.KEV = true
				v.KEVDate = entry.DateAdded
				v.KnownRansomware = strings.EqualFold(entry.Ransomware, "known")
				if entry.Vendor != "" && entry.Product != "" {
					v.Affected = appendUnique(v.Affected, entry.Vendor+" "+entry.Product)
				}
				break
			}
		}
	}
	v.EnrichedAt = time.Now().UTC().Format(time.RFC3339)
}

func deref(f *float64) float64 {
	if f == nil {
		return -1
	}
	return *f
}

func dedupeUpper(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func appendUnique(list []string, items ...string) []string {
	seen := map[string]bool{}
	for _, s := range list {
		seen[s] = true
	}
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			list = append(list, s)
		}
	}
	return list
}

// LoadKEV 加载 CISA KEV 目录，优先使用本地缓存（TTL 由 enrich.cache_hours 控制）。
func (e *Enricher) LoadKEV(ctx context.Context) error {
	e.mu.Lock()
	if len(e.kev) > 0 && time.Since(e.kevLoaded) < time.Duration(e.cfg.CacheHours)*time.Hour {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()

	_ = os.MkdirAll(e.cacheDir, 0o755)
	cacheFile := filepath.Join(e.cacheDir, "kev.json")
	var body []byte
	if b, err := os.ReadFile(cacheFile); err == nil {
		if st, err2 := os.Stat(cacheFile); err2 == nil &&
			time.Since(st.ModTime()) < time.Duration(e.cfg.CacheHours)*time.Hour {
			body = b
		}
	}
	if body == nil {
		var lastErr error
		for _, u := range kevURLs {
			b, err := e.fetchKEV(ctx, u)
			if err == nil && len(b) > 1024 {
				body = b
				break
			}
			if err != nil {
				lastErr = err
			}
		}
		if body == nil {
			if lastErr == nil {
				lastErr = fmt.Errorf("所有 KEV 镜像均不可用")
			}
			return fmt.Errorf("KEV 目录拉取失败: %w", lastErr)
		}
		_ = os.WriteFile(cacheFile, body, 0o644)
	}

	var doc struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("KEV 目录解析失败: %w", err)
	}
	m := make(map[string]KEVEntry, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		m[strings.ToUpper(v.CVEID)] = v
	}
	e.mu.Lock()
	e.kev = m
	e.kevLoaded = time.Now()
	e.mu.Unlock()
	return nil
}

// fetchKEV 拉取 KEV 目录（单个镜像）。
func (e *Enricher) fetchKEV(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s 返回 HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// KEVEntry 查询单条 KEV 记录。
func (e *Enricher) KEVEntry(cve string) (KEVEntry, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.kev[strings.ToUpper(cve)]
	return v, ok
}

// KEVAll 返回 KEV 目录全部记录（按收录日期倒序），供 KEV 数据源入库。
func (e *Enricher) KEVAll() []KEVEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]KEVEntry, 0, len(e.kev))
	for _, v := range e.kev {
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DateAdded > out[j].DateAdded })
	return out
}

// EPSSBatch 批量查询 EPSS（每批 100 个 CVE），带本地缓存。
func (e *Enricher) EPSSBatch(ctx context.Context, cves []string) map[string]EPSS {
	out := map[string]EPSS{}
	if !e.cfg.EPSS || len(cves) == 0 {
		return out
	}
	e.loadEPSSDisk()
	now := time.Now()
	missing := []string{}
	e.mu.Lock()
	for _, c := range cves {
		c = strings.ToUpper(c)
		if v, ok := e.epss[c]; ok && now.Sub(v.At) < 12*time.Hour {
			out[c] = v
		} else {
			missing = append(missing, c)
		}
	}
	e.mu.Unlock()
	if len(missing) == 0 {
		return out
	}
	for start := 0; start < len(missing); start += 100 {
		end := start + 100
		if end > len(missing) {
			end = len(missing)
		}
		chunk := missing[start:end]
		got := e.fetchEPSS(ctx, chunk)
		for k, v := range got {
			out[k] = v
			e.mu.Lock()
			e.epss[k] = v
			e.epssDirty = true
			e.mu.Unlock()
		}
	}
	e.saveEPSSDisk()
	return out
}

func (e *Enricher) fetchEPSS(ctx context.Context, cves []string) map[string]EPSS {
	out := map[string]EPSS{}
	u := epssURL + "?cve=" + strings.Join(cves, ",")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", "SocradarBot/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	var doc struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return out
	}
	for _, d := range doc.Data {
		s, _ := strconv.ParseFloat(d.EPSS, 64)
		p, _ := strconv.ParseFloat(d.Percentile, 64)
		out[strings.ToUpper(d.CVE)] = EPSS{Score: s, Percentile: p, At: time.Now()}
	}
	return out
}

func (e *Enricher) loadEPSSDisk() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.epss) > 0 {
		return
	}
	b, err := os.ReadFile(filepath.Join(e.cacheDir, "epss.json"))
	if err != nil {
		return
	}
	var raw map[string]EPSS
	if json.Unmarshal(b, &raw) == nil {
		e.epss = raw
	}
}

func (e *Enricher) saveEPSSDisk() {
	e.mu.Lock()
	if !e.epssDirty {
		e.mu.Unlock()
		return
	}
	b, _ := json.Marshal(e.epss)
	e.epssDirty = false
	e.mu.Unlock()
	_ = os.MkdirAll(e.cacheDir, 0o755)
	_ = os.WriteFile(filepath.Join(e.cacheDir, "epss.json"), b, 0o644)
}

// Score 计算风险分并判定是否属于高价值情报。
// 规则完全由 push 配置驱动，返回的 reasons 用于推送文案与前端展示。
func Score(v *model.Vuln, p config.Push) (int, bool, []string) {
	score := 0
	reasons := []string{}

	sev := Severity(v)
	if v.CVSS != nil {
		score += int(*v.CVSS * 8)
		reasons = append(reasons, fmt.Sprintf("CVSS %.1f（%s）", *v.CVSS, sevLabel(sev)))
	} else {
		switch sev {
		case "critical":
			score += 75
		case "high":
			score += 60
		case "medium":
			score += 40
		case "low":
			score += 20
		case "info":
			score += 5
		}
		if sev != "unknown" {
			reasons = append(reasons, "严重性 "+sevLabel(sev))
		}
	}
	if v.EPSS > 0 {
		score += int(v.EPSS * 20)
		reasons = append(reasons, fmt.Sprintf("EPSS %.0f%%", v.EPSS*100))
	}
	if v.KEV {
		score += 25
		reasons = append(reasons, "CISA KEV 已知在野利用")
	}
	if v.HasPOC() {
		score += 15
		if v.POCDisclosed && (v.POCSource == "" || v.POCSource == "none") {
			reasons = append(reasons, "情报源标注 PoC/EXP 已公开")
		} else {
			reasons = append(reasons, "存在可用 PoC")
		}
	}
	if len(v.CVEs) > 0 {
		score += 5
		reasons = append(reasons, "已关联 CVE 编号")
	}
	if fresh(v, 7) {
		score += 5
		reasons = append(reasons, "近 7 天披露")
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	ok := score >= p.MinScore
	if p.MinSeverity != "" && model.SeverityRank(sev) < model.SeverityRank(p.MinSeverity) {
		ok = false
	}
	if p.RequireCVE && len(v.CVEs) == 0 {
		ok = false
	}
	if p.RequirePOC && !v.HasPOC() {
		ok = false
	}
	blob := strings.ToLower(v.Name + " " + v.Summary)
	if len(p.KeywordsInclude) > 0 {
		hit := false
		for _, kw := range p.KeywordsInclude {
			if kw != "" && strings.Contains(blob, strings.ToLower(kw)) {
				hit = true
				break
			}
		}
		if !hit {
			ok = false
		}
	}
	for _, kw := range p.KeywordsExclude {
		if kw != "" && strings.Contains(strings.ToLower(v.Name), strings.ToLower(kw)) {
			ok = false
			break
		}
	}
	return score, ok, reasons
}

func sevLabel(s string) string {
	switch s {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	}
	return "未知"
}

func fresh(v *model.Vuln, days int) bool {
	ref := v.Published
	if ref == "" {
		ref = v.CreatedAt
	}
	if len(ref) < 10 {
		return false
	}
	t, err := time.Parse("2006-01-02", ref[:10])
	if err != nil {
		return false
	}
	return time.Since(t) < time.Duration(days)*24*time.Hour
}
