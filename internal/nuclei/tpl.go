// Package nuclei 实现 nuclei 模板双向通道。
//
// 导出：漏洞情报 + PoC → nuclei v3 模板（LLM 抽结构化字段，启发式兜底，schema 校验后落盘）。
// 导入：git 增量同步上游模板库 / 远程抽样，原样入库不过 LLM 改写。
//
// 安全边界：生成的模板默认只做只读探测；带写操作（POST/PUT/DELETE 或 admin/import
// 等路径特征）的模板必须显式 allow_write=true 才放行。
package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"socradarbot/internal/llm"
	"socradarbot/internal/model"
)

// Tpl 是解析后的模板元信息。
type Tpl struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Tags        []string
	Refs        []string
	CVSS        float64
	Path        string
	Raw         string
	Source      string
	Protocols   []string
}

var (
	slugRE     = regexp.MustCompile(`[^A-Za-z0-9]+`)
	idRE       = regexp.MustCompile(`^[a-z0-9-]+$`)
	sevSet     = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	writeHint  = regexp.MustCompile(`(?i)(?:\bpost\b|\bput\b|\bpatch\b|\bdelete\b|\baction\b|/upload|/create|/add|/new\b|/insert|/register|/signup|/login\b|/logout\b|/invite|/reset|/admin|/import|/exec|/eval|/run\b|/generate|/send|/publish|/update|/drop)`)
	urlPathRE  = regexp.MustCompile(`["'](https?://[^"'/\s]+)((?:/[^"'\s]*)+)["']`)
	urlVarRE   = regexp.MustCompile(`(?i)url\s*=\s*[^"'\n]*["'](/[^"'\s]{2,})["']`)
	reqLineRE  = regexp.MustCompile(`(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+(/\S{2,})`)
	apiPathRE  = regexp.MustCompile(`/api/[A-Za-z0-9_./{}-]{2,}`)
	adminRE    = regexp.MustCompile(`/(?:admin|actuator|console|manager|phpmyadmin|wp-admin|debug|metrics|config)(?:/\S*)?`)
	evidenceRE = regexp.MustCompile(`(?:assert|if)\s*[^\n]*?["']([A-Za-z0-9_./{}\-: ]{4,60})["']|(?:status_code|status)\s*==\s*(\d{3})`)
	methodRE   = regexp.MustCompile(`(?i)method\s*=\s*["'](get|post|put|patch|delete|head)["']`)
	httpVerRE  = regexp.MustCompile(`(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD)\s+/`)

	skipDirs = []string{"helpers/", "workflows/", ".github/", "tests/", "testdata/", "internal/", "cmd/", "lib/", "pkg/", "static/", "helm/"}
)

// Slug 生成符合 nuclei 规范的 id。
func Slug(s string) string {
	out := strings.ToLower(strings.Trim(slugRE.ReplaceAllString(s, "-"), "-"))
	out = regexp.MustCompile(`-{2,}`).ReplaceAllString(out, "-")
	if len(out) > 80 {
		out = out[:80]
	}
	if out == "" {
		return "ai-bobao-vuln"
	}
	return out
}

// Parse 从 YAML 文本解析模板元信息。
func Parse(raw []byte, path string) (*Tpl, error) {
	var doc struct {
		ID   string `yaml:"id"`
		Info struct {
			Name           string `yaml:"name"`
			Severity       string `yaml:"severity"`
			Description    string `yaml:"description"`
			Tags           any    `yaml:"tags"`
			Reference      any    `yaml:"reference"`
			Classification struct {
				CVSSScore float64 `yaml:"cvss-score"`
			} `yaml:"classification"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.ID == "" {
		return nil, fmt.Errorf("模板缺少 id")
	}
	sev := strings.ToLower(doc.Info.Severity)
	if !sevSet[sev] {
		sev = "unknown"
	}
	protos := []string{}
	for _, p := range []string{"http", "dns", "tcp", "network", "file", "headless", "ssl", "websocket", "whois", "javascript", "code"} {
		if regexp.MustCompile(`(?m)^` + p + `:`).Match(raw) {
			protos = append(protos, p)
		}
	}
	return &Tpl{
		ID: doc.ID, Name: firstNonEmpty(doc.Info.Name, doc.ID), Severity: sev,
		Description: truncate(doc.Info.Description, 600),
		Tags:        asList(doc.Info.Tags), Refs: asList(doc.Info.Reference),
		CVSS: doc.Info.Classification.CVSSScore, Path: path,
		Raw: string(raw), Protocols: protos,
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n])
}

func asList(v any) []string {
	switch t := v.(type) {
	case string:
		out := []string{}
		for _, s := range strings.Split(t, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := []string{}
		for _, x := range t {
			if s := strings.TrimSpace(fmt.Sprint(x)); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}

// ── 生成 ─────────────────────────────────────────────────

type tplInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description,omitempty"`
	Tags        string   `yaml:"tags,omitempty"`
	Reference   []string `yaml:"reference,omitempty"`
}

type matcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	DSL       string   `yaml:"dsl,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Negative  bool     `yaml:"negative,omitempty"`
}

type httpReq struct {
	Method   string            `yaml:"method"`
	Path     []string          `yaml:"path"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Body     string            `yaml:"body,omitempty"`
	Matchers []matcher         `yaml:"matchers"`
	Attack   string            `yaml:"attack,omitempty"`
}

type spec struct {
	ID   string    `yaml:"id"`
	Info tplInfo   `yaml:"info"`
	HTTP []httpReq `yaml:"http"`
}

// Generate 把漏洞情报转成 nuclei 模板。
// 返回 (yaml 文本, 产出方式 llm|heuristic, 错误)。
func Generate(ctx context.Context, v *model.Vuln, poc string, client *llm.Client, allowWrite bool) (string, string, error) {
	fallback := heuristicSpec(v, poc)
	chosen := fallback
	origin := "heuristic"

	if client != nil && client.Available() {
		if raw, err := client.NucleiSpec(ctx, v, poc); err == nil {
			if s := cleanSpec(raw, v); len(s.HTTP) > 0 {
				chosen = s
				origin = "llm"
			}
		}
	}
	if len(chosen.HTTP) == 0 {
		return "", origin, fmt.Errorf("未能提取任何可用的 http 请求（PoC 里没有可识别的路径）")
	}
	if isWriteRisk(chosen) && !allowWrite {
		return "", origin, fmt.Errorf("模板含写操作（POST/PUT/DELETE 或 admin/import 等路径），" +
			"为避免被误用于破坏性测试已拦下；确认无害可加 allow_write=true 强制生成")
	}
	text, err := yaml.Marshal(chosen)
	if err != nil {
		return "", origin, err
	}
	if err := Validate(text); err != nil {
		return "", origin, fmt.Errorf("自检未通过: %w", err)
	}
	return string(text), origin, nil
}

// Validate 落盘前自检：能 load、id 合法、severity 合法、至少一条带 path+matcher 的请求。
func Validate(text []byte) error {
	var doc struct {
		ID   string `yaml:"id"`
		Info struct {
			Severity string `yaml:"severity"`
		} `yaml:"info"`
		HTTP []struct {
			Path     []string `yaml:"path"`
			Matchers []any    `yaml:"matchers"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal(text, &doc); err != nil {
		return fmt.Errorf("YAML 解析失败: %w", err)
	}
	if doc.ID == "" {
		return fmt.Errorf("缺少 id")
	}
	if !idRE.MatchString(doc.ID) {
		return fmt.Errorf("id 非法（只允许小写字母数字和连字符）: %s", doc.ID)
	}
	if !sevSet[strings.ToLower(doc.Info.Severity)] {
		return fmt.Errorf("severity 非法")
	}
	if len(doc.HTTP) == 0 {
		return fmt.Errorf("缺少 http 请求")
	}
	for _, r := range doc.HTTP {
		if len(r.Path) == 0 || len(r.Matchers) == 0 {
			return fmt.Errorf("存在缺少 path 或 matchers 的请求")
		}
	}
	return nil
}

func isWriteRisk(s spec) bool {
	for _, r := range s.HTTP {
		switch r.Method {
		case "GET", "HEAD", "OPTIONS":
		default:
			return true
		}
		for _, p := range r.Path {
			if writeHint.MatchString(p) {
				return true
			}
		}
	}
	return false
}

func heuristicSpec(v *model.Vuln, poc string) spec {
	sev := strings.ToLower(v.Severity)
	if !sevSet[sev] {
		sev = "medium"
		if v.CVSS != nil {
			sev = model.SeverityFromCVSS(*v.CVSS)
		}
	}
	paths := extractPaths(poc)
	words := extractEvidence(poc)
	method := extractMethod(poc)

	http := []httpReq{}
	ranked := paths
	if len(ranked) > 3 {
		ranked = ranked[:3]
	}
	if len(ranked) == 0 {
		ranked = []string{""}
	}
	for _, p := range ranked {
		full := "{{BaseURL}}"
		if p != "" {
			full = "{{BaseURL}}" + p
		}
		m := matcher{Type: "status", Status: []int{200}}
		if len(words) > 0 {
			m = matcher{Type: "word", Part: "body", Words: words, Condition: "or"}
		}
		http = append(http, httpReq{Method: method, Path: []string{full}, Matchers: []matcher{m}})
	}
	return spec{
		ID: Slug(v.ID),
		Info: tplInfo{
			Name: firstNonEmpty(v.Name, v.ID), Author: "socradarbot",
			Severity: sev, Description: truncate(v.Summary, 300),
			Reference: limitList(v.Refs, 8), Tags: "vuln",
		},
		HTTP: http,
	}
}

func limitList(in []string, n int) []string {
	out := []string{}
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
		if len(out) >= n {
			break
		}
	}
	return out
}

func extractPaths(poc string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(raw string) {
		p := normPath(raw)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, re := range []*regexp.Regexp{urlPathRE, urlVarRE, reqLineRE, apiPathRE, adminRE} {
		for _, m := range re.FindAllStringSubmatch(poc, -1) {
			if len(m) > 2 && m[2] != "" {
				add(m[2])
			} else if len(m) > 1 && m[1] != "" {
				add(m[1])
			} else {
				add(m[0])
			}
			if len(out) >= 8 {
				return out
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func normPath(raw string) string {
	p := strings.TrimSpace(raw)
	p = strings.Trim(p, "\"'`,;)]}")
	if i := strings.IndexAny(p, "#?"); i >= 0 {
		p = p[:i]
	}
	p = regexp.MustCompile(`^https?://[^/]+`).ReplaceAllString(p, "")
	p = regexp.MustCompile(`(?i)^\{\{?BaseURL\}?\}?`).ReplaceAllString(p, "")
	p = strings.TrimRight(p, "\"'`)]},; ")
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	seg := p[strings.LastIndex(p, "/")+1:]
	if !regexp.MustCompile(`[A-Za-z0-9]`).MatchString(seg) {
		return ""
	}
	if len(p) <= 1 {
		return ""
	}
	return p
}

func extractEvidence(poc string) []string {
	words := []string{}
	seen := map[string]bool{}
	for _, m := range evidenceRE.FindAllStringSubmatch(poc, -1) {
		w := ""
		for _, g := range m[1:] {
			if g != "" {
				w = strings.TrimSpace(g)
				break
			}
		}
		if w != "" && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
		if len(words) >= 6 {
			break
		}
	}
	return words
}

func extractMethod(poc string) string {
	if m := methodRE.FindStringSubmatch(poc); len(m) > 1 {
		method := strings.ToUpper(m[1])
		if method != "HEAD" {
			return method
		}
	}
	if m := httpVerRE.FindStringSubmatch(poc); len(m) > 1 {
		if method := strings.ToUpper(m[1]); method != "HEAD" {
			return method
		}
	}
	return "GET"
}

// cleanSpec 规整 LLM 输出：类型收敛、路径补全、matcher 合法性检查。
func cleanSpec(raw map[string]any, v *model.Vuln) spec {
	sev := strings.ToLower(strings.TrimSpace(asString(raw["severity"])))
	if !sevSet[sev] {
		sev = "medium"
		if v.CVSS != nil {
			sev = model.SeverityFromCVSS(*v.CVSS)
		}
	}
	out := spec{
		ID: Slug(firstNonEmpty(asString(raw["id"]), v.ID)),
		Info: tplInfo{
			Name: firstNonEmpty(asString(raw["name"]), v.Name, v.ID), Author: "socradarbot",
			Severity: sev, Description: truncate(firstNonEmpty(asString(raw["description"]), v.Summary), 600),
			Tags: strings.Join(asStringList(raw["tags"]), ","), Reference: limitList(asStringList(raw["references"]), 8),
		},
	}
	if out.Info.Tags == "" {
		out.Info.Tags = "vuln"
	}
	reqs, _ := raw["http"].([]any)
	for _, r := range reqs {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		paths := asStringList(rm["path"])
		if len(paths) == 0 {
			paths = asStringList(rm["paths"])
		}
		cleanPaths := []string{}
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "{{BaseURL}}") {
				if !strings.HasPrefix(p, "/") {
					p = "/" + p
				}
				p = "{{BaseURL}}" + p
			}
			cleanPaths = append(cleanPaths, p)
			if len(cleanPaths) >= 5 {
				break
			}
		}
		if len(cleanPaths) == 0 {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(asString(rm["method"])))
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		default:
			method = "GET"
		}
		matchers := []matcher{}
		rawMatchers, _ := rm["matchers"].([]any)
		for _, mm := range rawMatchers {
			mp, ok := mm.(map[string]any)
			if !ok {
				continue
			}
			m := matcher{
				Type:      strings.ToLower(asString(mp["type"])),
				Part:      strings.ToLower(asString(mp["part"])),
				Condition: "and",
				Negative:  asBool(mp["negative"]),
			}
			if strings.EqualFold(asString(mp["condition"]), "or") {
				m.Condition = "or"
			}
			switch m.Type {
			case "word", "regex":
				words := asStringList(mp["words"])
				if len(words) == 0 {
					continue
				}
				if len(words) > 10 {
					words = words[:10]
				}
				if m.Part == "" {
					m.Part = "body"
				}
				m.Words = words
			case "status":
				codes := []int{}
				switch t := mp["status"].(type) {
				case []any:
					for _, x := range t {
						if n, ok := toInt(x); ok {
							codes = append(codes, n)
						}
					}
				case any:
					if n, ok := toInt(t); ok {
						codes = append(codes, n)
					}
				}
				if len(codes) == 0 {
					continue
				}
				m.Status = codes
			case "dsl":
				dsl := asString(mp["dsl"])
				if dsl == "" {
					continue
				}
				m.DSL = truncate(dsl, 500)
			default:
				continue
			}
			matchers = append(matchers, m)
			if len(matchers) >= 4 {
				break
			}
		}
		if len(matchers) == 0 {
			continue
		}
		req := httpReq{Method: method, Path: cleanPaths, Matchers: matchers}
		if hm, ok := rm["headers"].(map[string]any); ok {
			h := map[string]string{}
			for k, val := range hm {
				if s := asString(val); s != "" {
					h[k] = s
				}
			}
			if len(h) > 0 {
				req.Headers = h
			}
		}
		if body := asString(rm["body"]); body != "" {
			req.Body = truncate(body, 2000)
		}
		if method != "GET" {
			req.Attack = "none"
		}
		out.HTTP = append(out.HTTP, req)
		if len(out.HTTP) >= 5 {
			break
		}
	}
	return out
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprint(int64(t))
		}
		return fmt.Sprint(t)
	default:
		return fmt.Sprint(t)
	}
}

func asStringList(v any) []string {
	out := []string{}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) != "" {
			out = append(out, t)
		}
	case []any:
		for _, x := range t {
			if s := strings.TrimSpace(asString(x)); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, t...)
	}
	return out
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case string:
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n, true
		}
	case json.Number:
		n, err := t.Int64()
		return int(n), err == nil
	}
	return 0, false
}

// FromTemplate 把模板条目转换成统一的漏洞记录字段（来源标记 nuclei）。
func FromTemplate(t *Tpl) *model.Vuln {
	sev := t.Severity
	if sev == "unknown" {
		sev = "medium"
	}
	var cvss *float64
	if t.CVSS > 0 {
		v := t.CVSS
		cvss = &v
	} else if sev == "critical" {
		v := 9.0
		cvss = &v
	} else if sev == "high" {
		v := 7.5
		cvss = &v
	}
	return &model.Vuln{
		ID:        "nuclei-" + Slug(t.ID),
		Name:      t.Name,
		Source:    t.Source,
		Summary:   firstNonEmpty(t.Description, t.Name),
		Principle: "见模板 description 与官方 reference。",
		AttackScope: func() string {
			if len(t.Protocols) > 0 {
				return "协议：" + strings.Join(t.Protocols, ", ") + "；严重性：" + sev
			}
			return "严重性：" + sev
		}(),
		Severity: sev, CVSS: cvss, Refs: limitList(t.Refs, 8),
		POCSource: "nuclei", TplPath: t.Path, Tags: t.Tags,
		Note: "来自 nuclei 模板库，原样收录",
	}
}
