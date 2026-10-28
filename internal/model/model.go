// Package model 定义 SocradarBot 的核心数据结构。
//
// 字段与旧 Python 版 meta.json 保持向后兼容：新增字段全部为 omitempty 或带零值，
// 旧数据可直接被 Go 版读取，新写入的数据旧版前端也能忽略未知字段正常展示。
package model

import "strings"

// Vuln 是一条漏洞情报的完整记录，落盘为 data/vulns/{id}/meta.json。
type Vuln struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Source           string   `json:"source"`
	Summary          string   `json:"summary"`
	Principle        string   `json:"principle"`
	AttackScope      string   `json:"attack_scope"`
	Severity         string   `json:"severity,omitempty"`          // info|low|medium|high|critical|unknown
	SeverityInferred bool     `json:"severity_inferred,omitempty"` // 严重性是否由关键词/CVSS 推断而来
	CVSS             *float64 `json:"cvss"`
	CVEs             []string `json:"cves,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Refs             []string `json:"refs,omitempty"`

	// 富化字段
	EPSS            float64  `json:"epss,omitempty"`
	EPSSPercentile  float64  `json:"epss_percentile,omitempty"`
	KEV             bool     `json:"kev,omitempty"`
	KEVDate         string   `json:"kev_date,omitempty"`
	KnownRansomware bool     `json:"known_ransomware,omitempty"`
	Affected        []string `json:"affected_products,omitempty"`
	CWE             []string `json:"cwe,omitempty"`
	Score           int      `json:"score"`
	HighValue       bool     `json:"high_value"`
	ScoreReasons    []string `json:"score_reasons,omitempty"`
	EnrichedAt      string   `json:"enriched_at,omitempty"`

	Published string `json:"published,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`

	POCSource    string `json:"poc_source,omitempty"` // article|ai|nuclei|none
	POCFile      string `json:"poc_file,omitempty"`
	POCDisclosed bool   `json:"poc_disclosed,omitempty"` // 情报源标注 PoC/EXP 已公开（未必含代码）
	NucleiFile   string `json:"nuclei_file,omitempty"`
	Translated   bool   `json:"translated,omitempty"`
	Note         string `json:"note,omitempty"`
	TplPath      string `json:"tpl_path,omitempty"`
	SyncCommit   string `json:"sync_commit,omitempty"`

	// 推送状态
	Pushed         bool   `json:"pushed"`
	PushedAt       string `json:"pushed_at,omitempty"`
	PushSkipReason string `json:"push_skip_reason,omitempty"`

	// 仅详情接口返回，不落 meta.json
	POC        string `json:"poc"`
	NucleiYAML string `json:"nuclei_yaml"`

	// 运行期索引标记：构建列表缓存时写入，不持久化
	NucleiReady bool `json:"-"`
}

// HasPOC 判断是否具备可利用验证能力（含代码，或情报源标注 PoC 已公开）。
func (v *Vuln) HasPOC() bool {
	return (v.POCSource != "" && v.POCSource != "none") || v.POCDisclosed
}

// SeverityRank 把严重性等级映射为可比较的序号；未知等级返回 -1。
func SeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	case "unknown", "":
		return 0
	}
	return -1
}

// SeverityFromCVSS 按 CVSS 分值推导严重性等级（与旧版 nuclei 分级一致）。
func SeverityFromCVSS(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss > 0:
		return "low"
	case cvss == 0:
		return "info"
	}
	return "unknown"
}

// Item 是采集层的统一原始条目，各数据源归一化后进入流水线。
type Item struct {
	ID           string
	Title        string
	Source       string
	Summary      string
	Link         string
	Published    string
	Severity     string
	CVSS         *float64
	CVEs         []string
	Tags         []string
	Refs         []string
	Affected     []string
	CWE          []string
	Content      string // 正文纯文本（RSS 文章抓取后填充）
	POC          string // 从正文提取的现成 PoC
	POCProvided  bool   // 数据源直接给出 PoC/nuclei 模板
	POCDisclosed bool   // 情报源标注 PoC/EXP 已公开
	RawTemplate  string // nuclei 模板原文（来自模板库的条目）
}

// ListItem 是列表接口的单行结构，字段与旧版完全一致并追加富化字段。
type ListItem struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	Summary    string   `json:"summary"`
	Published  string   `json:"published"`
	CVSS       *float64 `json:"cvss"`
	Severity   string   `json:"severity,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	Translated bool     `json:"translated"`
	HasNuclei  bool     `json:"has_nuclei"`
	EntryDate  string   `json:"entry_date"`
	EntryISO   string   `json:"entry_iso"`
	EPSS       float64  `json:"epss,omitempty"`
	KEV        bool     `json:"kev,omitempty"`
	POC        bool     `json:"poc,omitempty"`
	Score      int      `json:"score"`
	HighValue  bool     `json:"high_value"`
	Pushed     bool     `json:"pushed"`
	Tags       []string `json:"tags,omitempty"`
	Affected   []string `json:"affected_products,omitempty"`
}

// ListResult 是 /api/vulns 的响应体，保持旧版字段不变。
type ListResult struct {
	Items     []ListItem     `json:"items"`
	Total     int            `json:"total"`
	Page      int            `json:"page"`
	Pages     int            `json:"pages"`
	PageSize  int            `json:"page_size"`
	AllTotal  int            `json:"all_total"`
	Counts    map[string]int `json:"counts"`
	HighValue int            `json:"high_value_total"`
}

// TemplateItem 是模板库列表项。
type TemplateItem struct {
	ID       string `json:"id"`
	VID      string `json:"vid"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Tags     string `json:"tags"`
	File     string `json:"file"`
	Requests int    `json:"requests"`
}
