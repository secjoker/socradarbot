// Package store 是文件存储层。
//
// 目录结构（与旧 Python 版完全一致，旧数据可直接迁移）：
//
//	data/vulns/{ID}/meta.json     元数据
//	data/vulns/{ID}/poc.py        PoC 文本
//	data/vulns/{ID}/nuclei.yaml   nuclei 模板（可选）
//	data/nuclei_tpl/*.yaml        模板汇总目录，可直接 nuclei -l 执行
package store

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"socradarbot/internal/config"
	"socradarbot/internal/model"
)

var (
	safeID  = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	cveYear = regexp.MustCompile(`(?i)CVE-(\d{4})`)
	dateRE  = regexp.MustCompile(`(\d{4})-(\d{2})-(\d{2})`)
	cveAny  = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	hasHan  = regexp.MustCompile(`[\x{4e00}-\x{9fff}]`)
)

// Store 提供并发安全的文件读写。
type Store struct {
	p  config.Paths
	mu sync.RWMutex

	// 全量元数据只读缓存：列表/统计共用，写入时失效，避免每次请求扫近万个 meta.json
	cache      []*model.Vuln
	cacheAt    time.Time
	cacheValid bool
}

func New(p config.Paths) *Store {
	return &Store{p: p}
}

func (s *Store) Paths() config.Paths { return s.p }

func SanitizeID(id string) string { return safeID.ReplaceAllString(id, "_") }

func nowUTC() string { return time.Now().UTC().Format("2006-01-02T15:04:05") }

// IsZhName 判断标题是否包含中文（用于翻译判定，剥离兜底标记）。
func IsZhName(name string) bool {
	return hasHan.MatchString(strings.ReplaceAll(name, "（兜底）", ""))
}

// EntryDate 返回条目真实披露日期与"是否只有年份"。
// CVE 编号年份优先于 published：模板库条目的 published 是入库时间，不代表漏洞年龄。
func EntryDate(v *model.Vuln) (string, bool) {
	blob := v.ID + " " + v.Name + " " + strings.Join(v.Refs, " ")
	if ys := cveYear.FindAllStringSubmatch(blob, -1); len(ys) > 0 {
		maxY := 0
		for _, m := range ys {
			var y int
			fmt.Sscanf(m[1], "%d", &y)
			if y > maxY {
				maxY = y
			}
		}
		if maxY > 0 {
			return fmt.Sprintf("%04d-12-31", maxY), true
		}
	}
	if m := dateRE.FindString(v.Published); m != "" {
		return m, false
	}
	if m := dateRE.FindString(v.CreatedAt); m != "" {
		return m, false
	}
	return "", false
}

// TooOld 判断条目是否超出保留期（keepDays<=0 表示不按日期清理）。
func TooOld(v *model.Vuln, keepDays int) bool {
	if keepDays <= 0 {
		return false
	}
	d, _ := EntryDate(v)
	if d == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", d)
	if err != nil {
		return false
	}
	return t.Before(time.Now().AddDate(0, 0, -keepDays))
}

func (s *Store) dir(id string) string { return filepath.Join(s.p.VulnDir, SanitizeID(id)) }

// Save 落盘一条漏洞（meta + poc + 可选 nuclei 模板）。
func (s *Store) Save(v *model.Vuln, poc, lang, nucleiYAML string) (string, error) {
	if v == nil {
		return "", fmt.Errorf("empty vuln")
	}
	id := SanitizeID(strings.TrimSpace(v.ID))
	if id == "" || id == "." || id == ".." {
		return "", fmt.Errorf("非法漏洞 ID")
	}
	if lang == "" {
		lang = "python"
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	v.ID = id
	dir := filepath.Join(s.p.VulnDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	v.POCFile = "poc." + lang
	if err := os.WriteFile(filepath.Join(dir, v.POCFile), []byte(poc), 0o644); err != nil {
		return "", err
	}
	if nucleiYAML != "" {
		v.NucleiFile = "nuclei.yaml"
		if err := os.WriteFile(filepath.Join(dir, "nuclei.yaml"), []byte(nucleiYAML), 0o644); err != nil {
			return "", err
		}
		if err := os.MkdirAll(s.p.TplDir, 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(s.p.TplDir, id+".yaml"), []byte(nucleiYAML), 0o644); err != nil {
			return "", err
		}
	}
	if v.CreatedAt == "" {
		v.CreatedAt = nowUTC()
	}
	return id, s.writeMeta(dir, v)
}

func (s *Store) writeMeta(dir string, v *model.Vuln) error {
	meta := *v
	meta.POC = ""
	meta.NucleiYAML = ""
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	s.cacheValid = false
	return os.Rename(tmp, filepath.Join(dir, "meta.json"))
}

// Get 读取漏洞详情（含 PoC 与模板全文）。
func (s *Store) Get(id string) (*model.Vuln, error) {
	dir := s.dir(id)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var v model.Vuln
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	if v.POCFile != "" {
		if pb, err := os.ReadFile(filepath.Join(dir, v.POCFile)); err == nil {
			v.POC = string(pb)
		}
	}
	if tb, err := os.ReadFile(filepath.Join(dir, "nuclei.yaml")); err == nil {
		v.NucleiYAML = string(tb)
	}
	v.POCSource = normalizePOCSource(&v)
	return &v, nil
}

func normalizePOCSource(v *model.Vuln) string {
	if v.POCSource != "" {
		return v.POCSource
	}
	if v.NucleiYAML != "" {
		return "nuclei"
	}
	if v.POC != "" {
		return "article"
	}
	return "none"
}

func (s *Store) readMeta(dir string) (*model.Vuln, error) {
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var v model.Vuln
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// ListOptions 列表筛选条件。
type ListOptions struct {
	Page      int
	PageSize  int
	Source    string
	HighValue bool
	MinScore  int
	Keyword   string
	Unpushed  bool
	Severity  string // 精确匹配 critical/high/medium/low/info
	KEV       bool
	POC       bool
	Vendor    string // 厂商 / 产品 / 影响范围模糊匹配
	Sort      string // latest(默认) | score | cvss | published
}

// List 分页列表，响应字段与旧版一致。
func (s *Store) List(o ListOptions) model.ListResult {
	all := s.All()

	rows := make([]model.ListItem, 0, len(all))
	counts := map[string]int{}
	hvTotal := 0
	for _, v := range all {
		date, yearOnly := EntryDate(v)
		display := date
		if yearOnly {
			// 只有 CVE 年份时优先展示真实披露日期，避免列表里全是「2026」
			if pub := dateRE.FindString(v.Published); pub != "" {
				display = pub
			} else {
				display = date[:4]
			}
		}
		if display == "" {
			display = strings.TrimSpace(v.CreatedAt)
			if len(display) > 10 {
				display = display[:10]
			}
		}
		iso := date
		if iso == "" {
			iso = strings.TrimSpace(v.CreatedAt)
			if len(iso) > 10 {
				iso = iso[:10]
			}
		}
		counts[v.Source]++
		if v.HighValue {
			hvTotal++
		}
		rows = append(rows, model.ListItem{
			ID: v.ID, Name: v.Name, Source: v.Source, Summary: v.Summary,
			Published: v.Published, CVSS: v.CVSS, Severity: v.Severity, CVEs: v.CVEs,
			Translated: v.Translated || IsZhName(v.Name),
			HasNuclei:  v.NucleiReady,
			EntryDate:  display, EntryISO: iso,
			EPSS: v.EPSS, KEV: v.KEV, POC: hasExploitPOC(v), Score: v.Score, HighValue: v.HighValue,
			Pushed: v.Pushed, Tags: v.Tags, Affected: v.Affected,
		})
	}

	allTotal := len(rows)
	filtered := rows[:0]
	for _, r := range rows {
		if o.Source != "" && o.Source != "全部" && r.Source != o.Source {
			continue
		}
		if o.HighValue && !r.HighValue {
			continue
		}
		if o.MinScore > 0 && r.Score < o.MinScore {
			continue
		}
		if o.Unpushed && r.Pushed {
			continue
		}
		if sev := strings.ToLower(strings.TrimSpace(o.Severity)); sev != "" && sev != "all" {
			if strings.ToLower(r.Severity) != sev {
				continue
			}
		}
		if o.KEV && !r.KEV {
			continue
		}
		if o.POC && !r.POC {
			continue
		}
		if vendor := strings.ToLower(strings.TrimSpace(o.Vendor)); vendor != "" {
			blob := strings.ToLower(r.Name + " " + strings.Join(r.Affected, " "))
			if !strings.Contains(blob, vendor) {
				continue
			}
		}
		if kw := strings.TrimSpace(o.Keyword); kw != "" {
			blob := strings.ToLower(r.Name + " " + r.Summary + " " + strings.Join(r.CVEs, " "))
			if !strings.Contains(blob, strings.ToLower(kw)) {
				continue
			}
		}
		filtered = append(filtered, r)
	}
	rows = filtered

	// 排序：默认按收录/披露时间倒序，可切换风险分、CVSS、披露时间
	switch strings.ToLower(o.Sort) {
	case "score":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Score != rows[j].Score {
				return rows[i].Score > rows[j].Score
			}
			return rows[i].EntryISO > rows[j].EntryISO
		})
	case "cvss":
		sort.SliceStable(rows, func(i, j int) bool {
			ci, cj := cvssValue(rows[i].CVSS), cvssValue(rows[j].CVSS)
			if ci != cj {
				return ci > cj
			}
			return rows[i].EntryISO > rows[j].EntryISO
		})
	case "published":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Published > rows[j].Published })
	default:
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].EntryISO != rows[j].EntryISO {
				return rows[i].EntryISO > rows[j].EntryISO
			}
			return rows[i].ID > rows[j].ID
		})
	}

	total := len(rows)
	pageSize := o.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}
	page := o.Page
	if page < 1 {
		page = 1
	}
	if page > pages {
		page = pages
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	items := rows[start:end]
	if items == nil {
		items = []model.ListItem{}
	}
	return model.ListResult{
		Items: items, Total: total, Page: page, Pages: pages,
		PageSize: pageSize, AllTotal: allTotal, Counts: counts, HighValue: hvTotal,
	}
}

func cvssValue(v *float64) float64 {
	if v == nil {
		return -1
	}
	return *v
}

// hasExploitPOC 区分「可利用代码」与「检测模板」：nuclei 模板不计入 PoC 筛选，
// 否则模板库会把 95% 以上的条目都标成有 PoC，筛选失去意义。
func hasExploitPOC(v *model.Vuln) bool {
	if v.POCDisclosed {
		return true
	}
	return v.POCSource == "article" || v.POCSource == "ai"
}

// scanLocked 全量扫描 meta.json（调用方负责加锁语义）。
func (s *Store) scanLocked() []*model.Vuln {
	out := []*model.Vuln{}
	entries, err := os.ReadDir(s.p.VulnDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.p.VulnDir, e.Name())
		v, err := s.readMeta(dir)
		if err != nil {
			continue
		}
		// 模板存在性在索引构建时算一次，避免列表每个请求做上万次 os.Stat
		v.NucleiReady = fileExists(filepath.Join(dir, "nuclei.yaml"))
		out = append(out, v)
	}
	return out
}

// All 返回全量元数据（带内存缓存，供列表/统计/去重索引共用）。
func (s *Store) All() []*model.Vuln {
	s.mu.RLock()
	if s.cacheValid && time.Since(s.cacheAt) < 30*time.Second {
		out := s.cache
		s.mu.RUnlock()
		return out
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cacheValid && time.Since(s.cacheAt) < 30*time.Second {
		return s.cache
	}
	start := time.Now()
	s.cache = s.scanLocked()
	s.cacheAt = time.Now()
	s.cacheValid = true
	log.Printf("[store] 元数据索引重建：%d 条，耗时 %s", len(s.cache), time.Since(start))
	return s.cache
}

// Index 返回已存在的 ID 与 CVE 索引。
func (s *Store) Index() (map[string]bool, map[string]string) {
	ids := map[string]bool{}
	cves := map[string]string{}
	for _, v := range s.All() {
		ids[v.ID] = true
		cs := v.CVEs
		if len(cs) == 0 {
			cs = cveAny.FindAllString(v.ID+" "+v.Name, -1)
		}
		for _, c := range cs {
			cves[strings.ToUpper(c)] = v.ID
		}
	}
	return ids, cves
}

// Purge 清理超出保留期的条目（漏洞目录 + 汇总模板一起清）。
func (s *Store) Purge(keepDays int) (int, []string, []string) {
	if keepDays <= 0 {
		return 0, []string{}, []string{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.p.VulnDir)
	if err != nil {
		return 0, []string{}, []string{}
	}
	ids, failed := []string{}, []string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.p.VulnDir, e.Name())
		v, err := s.readMeta(dir)
		if err != nil {
			continue
		}
		if !TooOld(v, keepDays) {
			continue
		}
		vid := v.ID
		if vid == "" {
			vid = e.Name()
		}
		if err := os.RemoveAll(dir); err != nil {
			failed = append(failed, vid)
			continue
		}
		_ = os.Remove(filepath.Join(s.p.TplDir, SanitizeID(vid)+".yaml"))
		ids = append(ids, vid)
	}
	if len(ids) > 0 {
		s.cacheValid = false
	}
	return len(ids), ids, failed
}

// Templates 返回本地模板库列表。
func (s *Store) Templates() []model.TemplateItem {
	out := []model.TemplateItem{}
	entries, err := os.ReadDir(s.p.TplDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.p.TplDir, e.Name()))
		if err != nil {
			continue
		}
		var doc struct {
			ID   string `yaml:"id"`
			Info struct {
				Name     string `yaml:"name"`
				Severity string `yaml:"severity"`
				Tags     any    `yaml:"tags"`
			} `yaml:"info"`
			HTTP []any `yaml:"http"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil || doc.ID == "" {
			continue
		}
		out = append(out, model.TemplateItem{
			ID: doc.ID, VID: strings.TrimSuffix(e.Name(), ".yaml"),
			Name: doc.Info.Name, Severity: strings.ToLower(doc.Info.Severity),
			Tags: joinAny(doc.Info.Tags), File: e.Name(), Requests: len(doc.HTTP),
		})
		if out[len(out)-1].Name == "" {
			out[len(out)-1].Name = doc.ID
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevOrder(out[i].Severity), sevOrder(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func sevOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	default:
		return 2
	}
}

func joinAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, fmt.Sprint(x))
		}
		return strings.Join(parts, ",")
	}
	return ""
}

// PendingHighValue 返回尚未推送的高价值条目（按评分倒序）。
func (s *Store) PendingHighValue(limit int) []*model.Vuln {
	all := s.All()
	out := []*model.Vuln{}
	for _, v := range all {
		if v.HighValue && !v.Pushed {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// MarkPushed 更新推送状态。
func (s *Store) MarkPushed(ids []string, at string) error {
	if len(ids) == 0 {
		return nil
	}
	if at == "" {
		at = nowUTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for _, id := range ids {
		dir := filepath.Join(s.p.VulnDir, SanitizeID(id))
		v, err := s.readMeta(dir)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		v.Pushed = true
		v.PushedAt = at
		v.PushSkipReason = ""
		if err := s.writeMeta(dir, v); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// MarkPushSkipped 标记"因去重/冷却被跳过"，避免反复进入待推队列。
func (s *Store) MarkPushSkipped(ids []string, reason string) {
	if len(ids) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		dir := filepath.Join(s.p.VulnDir, SanitizeID(id))
		v, err := s.readMeta(dir)
		if err != nil {
			continue
		}
		v.Pushed = true
		v.PushedAt = nowUTC()
		v.PushSkipReason = reason
		_ = s.writeMeta(dir, v)
	}
}

// PendingTranslateCount 全库未中文化条目数。
func (s *Store) PendingTranslateCount() int {
	n := 0
	for _, v := range s.All() {
		if !v.Translated && !IsZhName(v.Name) {
			n++
		}
	}
	return n
}

// Stats 汇总统计，供仪表盘与推送状态展示。
func (s *Store) Stats() map[string]any {
	all := s.All()
	bySource := map[string]int{}
	high, unpushed, today, translated, kev, poc := 0, 0, 0, 0, 0, 0
	todayStr := time.Now().Format("2006-01-02")
	for _, v := range all {
		bySource[v.Source]++
		if v.HighValue {
			high++
			if !v.Pushed {
				unpushed++
			}
		}
		if v.KEV {
			kev++
		}
		if v.HasPOC() && hasExploitPOC(v) {
			poc++
		}
		if strings.HasPrefix(v.CreatedAt, todayStr) {
			today++
		}
		if v.Translated || IsZhName(v.Name) {
			translated++
		}
	}
	return map[string]any{
		"total": len(all), "high_value": high, "unpushed_high_value": unpushed,
		"today": today, "translated": translated, "kev": kev, "poc": poc,
		"pending_translate": len(all) - translated,
		"by_source":         bySource,
		"templates":         countTemplates(s.p.TplDir),
	}
}

// countTemplates 只统计模板文件数量，避免首页为了一行统计去解析近万份 YAML。
func countTemplates(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			n++
		}
	}
	return n
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
