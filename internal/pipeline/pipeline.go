// Package pipeline 串联采集、富化、AI 加工、模板生成、评分、落库与推送。
//
// 一轮采集的数据流：
//
//	source.FetchAll → 去重/过期过滤 → 正文抓取 → enrich（CVE/KEV/EPSS/severity）
//	→ LLM 情报补全（可选）→ nuclei 模板生成（可选）→ 风险评分 → store.Save
//	→ push.PushPending（高价值情报）
package pipeline

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"socradarbot/internal/config"
	"socradarbot/internal/crawler"
	"socradarbot/internal/enrich"
	"socradarbot/internal/llm"
	"socradarbot/internal/model"
	"socradarbot/internal/nuclei"
	"socradarbot/internal/push"
	"socradarbot/internal/source"
	"socradarbot/internal/store"
)

type Pipeline struct {
	st *store.Store
	pm *push.Manager
}

func New(st *store.Store, pm *push.Manager) *Pipeline {
	return &Pipeline{st: st, pm: pm}
}

// CollectResult 是一轮采集的结果（字段与旧版兼容并扩展）。
type CollectResult struct {
	Fetched       int               `json:"fetched"`
	Kept          int               `json:"kept"`
	Skipped       int               `json:"skipped"`
	Expired       int               `json:"expired"`
	Enriched      int               `json:"enriched"`
	Translated    int               `json:"translated"`
	HighValue     int               `json:"high_value"`
	NucleiOK      int               `json:"nuclei_ok"`
	NucleiSkipped int               `json:"nuclei_skipped"`
	BySource      map[string]int    `json:"by_source"`
	SourceErrors  map[string]string `json:"source_errors,omitempty"`
	Push          *push.BatchResult `json:"push,omitempty"`
}

// RunCollect 执行完整采集流水线。
func (p *Pipeline) RunCollect(ctx context.Context) (CollectResult, error) {
	cfg := config.Current()
	res := CollectResult{BySource: map[string]int{}}
	client := crawler.Client(time.Duration(cfg.Collect.TimeoutSeconds) * time.Second)
	en := enrich.New(cfg.Enrich, p.st.Paths().CacheDir)
	if cfg.Enrich.KEV {
		if err := en.LoadKEV(ctx); err != nil {
			res.SourceErrors = ensureErrMap(res.SourceErrors)
			res.SourceErrors["cisa-kev"] = err.Error()
		}
	}
	llmClient := llm.New(cfg.LLM)
	reg := source.Build(cfg, client, en)
	items, srcErrs := reg.FetchAll(ctx, cfg.Collect.FetchLimit)
	res.Fetched = len(items)
	res.SourceErrors = srcErrs

	existingIDs, existingCVEs := p.st.Index()
	keepDays := cfg.Collect.KeepDays

	// 1) 归一化 + 去重 + 过期过滤
	candidates := []*model.Item{}
	seenIDs := map[string]bool{}
	seenCVEs := map[string]int{}
	for i := range items {
		it := &items[i]
		if it.ID == "" || seenIDs[it.ID] || existingIDs[it.ID] {
			res.Skipped++
			continue
		}
		seenIDs[it.ID] = true
		if it.Published != "" {
			tmp := &model.Vuln{ID: it.ID, Name: it.Title, Published: it.Published}
			if store.TooOld(tmp, keepDays) {
				res.Expired++
				continue
			}
		}
		cves := enrich.ExtractCVEs(it.ID, it.Title, it.Summary, strings.Join(it.Refs, " "))
		it.CVEs = mergeUnique(it.CVEs, cves)
		// CVE 跨源去重：同一 CVE 只保留信息量最大的一条（有 CVSS/影响范围的优先）
		dup := false
		for _, c := range it.CVEs {
			if _, ok := existingCVEs[c]; ok {
				dup = true
				break
			}
			if idx, ok := seenCVEs[c]; ok {
				mergeItem(&items[idx], it)
				dup = true
				break
			}
		}
		if dup {
			res.Skipped++
			continue
		}
		for _, c := range it.CVEs {
			seenCVEs[c] = len(candidates)
		}
		candidates = append(candidates, it)
	}

	// 2) 正文抓取（并发 4，仅 RSS 文章源）
	if cfg.Collect.ArticleFetch {
		fetchContents(ctx, candidates, 4, time.Duration(cfg.Collect.TimeoutSeconds)*time.Second)
	}

	// 3) EPSS 批量富化（一次请求最多 100 个 CVE）
	allCVEs := []string{}
	for _, it := range candidates {
		allCVEs = append(allCVEs, it.CVEs...)
	}
	epssMap := en.EPSSBatch(ctx, allCVEs)

	// 4) 逐条加工落库
	for _, it := range candidates {
		poc := it.POC
		content := it.Content
		pocSource := "none"
		if poc != "" {
			pocSource = "article"
		}

		v := &model.Vuln{
			ID: it.ID, Name: it.Title, Source: it.Source, Summary: it.Summary,
			Principle: "", AttackScope: "", Severity: it.Severity, CVSS: it.CVSS,
			CVEs: it.CVEs, Tags: it.Tags, Refs: it.Refs, Affected: it.Affected,
			CWE: it.CWE, Published: it.Published, POCDisclosed: it.POCDisclosed,
		}
		en.Apply(v)
		if e, ok := epssMap[firstCVE(v.CVEs)]; ok {
			v.EPSS = e.Score
			v.EPSSPercentile = e.Percentile
		}

		// 文章类条目走 AI 补全；结构化源保留原始字段
		isArticle := it.Source != "cisa-kev" && it.Source != "github-advisory" && it.Source != "nvd" &&
			!strings.HasPrefix(it.Source, "nuclei")
		if isArticle {
			gen := fallbackIntel(v, poc)
			if llmClient.Available() {
				if out, err := llmClient.GenerateIntel(ctx, *it, content, poc); err == nil {
					gen = out
				}
			}
			v.Name = gen.Name
			v.Summary = gen.Summary
			v.Principle = gen.Principle
			v.AttackScope = gen.AttackScope
			if gen.POC != "" {
				poc = gen.POC
				if pocSource == "none" {
					pocSource = "ai"
				}
			}
		} else {
			v.Principle = firstNonEmpty(v.Principle, "见原始公告与参考链接。")
			v.AttackScope = firstNonEmpty(v.AttackScope, scopeFromFields(v))
			if cfg.Collect.AutoTranslate && llmClient.Available() && !store.IsZhName(v.Name) {
				if tr, err := llmClient.Translate(ctx, v); err == nil {
					v.Name, v.Summary, v.Principle = tr.Name, tr.Summary, tr.Principle
					v.Translated = true
					res.Translated++
				}
			}
		}
		v.POCSource = pocSource
		// LLM 生成的中文情报可能包含等级/CVSS 线索，落库前再富化一次
		en.Apply(v)

		// nuclei 模板生成（仅当有 PoC 且开启）
		yamlText := ""
		if cfg.Nuclei.GenTemplates && strings.TrimSpace(poc) != "" {
			if y, _, err := nuclei.Generate(ctx, v, poc, llmClient, false); err == nil {
				yamlText = y
				res.NucleiOK++
			} else {
				res.NucleiSkipped++
			}
		}

		// 风险评分必须在落盘前完成，保证 meta.json 里的 score/high_value 是最新的
		score, hv, reasons := enrich.Score(v, cfg.Push)
		v.Score, v.HighValue, v.ScoreReasons = score, hv, reasons
		if _, err := p.st.Save(v, poc, "python", yamlText); err != nil {
			continue
		}
		res.Kept++
		res.BySource[v.Source]++
		if len(v.CVEs) > 0 || v.EPSS > 0 || v.KEV || (v.Severity != "" && v.Severity != "unknown") {
			res.Enriched++
		}
		if hv {
			res.HighValue++
		}
	}

	// 5) 高价值情报推送
	if cfg.Push.Enabled && res.Kept > 0 {
		pr := p.pm.PushPending(ctx, cfg.Push, "collect")
		res.Push = &pr
	}
	return res, nil
}

// bumpHighValue 保持评分与高价值标记最新，并返回当前条数。

func ensureErrMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func firstCVE(cves []string) string {
	if len(cves) > 0 {
		return cves[0]
	}
	return ""
}

func fallbackIntel(v *model.Vuln, poc string) *llm.Intel {
	out := &llm.Intel{
		Name:        v.Name,
		Summary:     truncate(v.Summary, 120),
		Principle:   "成因与利用思路见原文，建议阅读参考链接确认影响版本。",
		AttackScope: "以原文描述的影响范围为准。",
		POCLang:     "python",
		POC:         poc,
	}
	if out.Name == "" {
		out.Name = v.ID
	}
	if out.POC == "" {
		out.POC = fmt.Sprintf("# %s 概念验证模板（兜底生成，仅用于授权测试）\n"+
			"import requests\n\nTARGET = \"http://TARGET\"\n\n"+
			"def probe():\n"+
			"    \"\"\"思路：按文章分析构造触发请求，观察响应差异确认漏洞存在。\"\"\"\n"+
			"    r = requests.get(TARGET, timeout=10, verify=False)\n"+
			"    print(r.status_code, r.text[:200])\n\n"+
			"if __name__ == \"__main__\":\n"+
			"    probe()\n", v.ID)
	}
	return out
}

func scopeFromFields(v *model.Vuln) string {
	parts := []string{}
	if len(v.Affected) > 0 {
		parts = append(parts, "影响产品："+strings.Join(limit3(v.Affected), "、"))
	}
	if v.Severity != "" {
		parts = append(parts, "严重性："+v.Severity)
	}
	if len(parts) == 0 {
		return "以官方公告为准"
	}
	return strings.Join(parts, "；")
}

func limit3(in []string) []string {
	if len(in) > 3 {
		return in[:3]
	}
	return in
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func mergeUnique(dst, src []string) []string {
	seen := map[string]bool{}
	for _, s := range dst {
		seen[strings.ToUpper(s)] = true
	}
	for _, s := range src {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			dst = append(dst, s)
		}
	}
	return dst
}

// mergeExact 按原样去重（URL、产品名大小写敏感，不能统一转大写）。
func mergeExact(dst, src []string) []string {
	seen := map[string]bool{}
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range src {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			dst = append(dst, s)
		}
	}
	return dst
}

// mergeItem 把重复条目的有效信息并入保留条目（参考链接、标签、影响范围、CVSS）。
func mergeItem(dst, src *model.Item) {
	dst.Refs = mergeExact(dst.Refs, src.Refs)
	dst.Tags = mergeExact(dst.Tags, src.Tags)
	dst.Affected = mergeExact(dst.Affected, src.Affected)
	if dst.CVSS == nil && src.CVSS != nil {
		dst.CVSS = src.CVSS
	}
	if srcSeverityRank(src.Severity) > srcSeverityRank(dst.Severity) {
		dst.Severity = src.Severity
	}
	if dst.Summary == "" {
		dst.Summary = src.Summary
	}
}

func srcSeverityRank(s string) int {
	r := model.SeverityRank(s)
	if r < 0 {
		return 0
	}
	return r
}

// fetchContents 并发抓取 RSS 文章正文与现成 PoC。
func fetchContents(ctx context.Context, items []*model.Item, workers int, timeout time.Duration) {
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	client := crawler.Client(timeout)
	for _, it := range items {
		if it.Link == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it *model.Item) {
			defer wg.Done()
			defer func() { <-sem }()
			text, poc := crawler.FetchArticle(ctx, client, it.Link)
			it.Content = text
			if poc != "" {
				it.POC = poc
			}
		}(it)
	}
	wg.Wait()
}

// SyncSummary 是模板同步入库的完整结果。
type SyncSummary struct {
	nuclei.SyncResult
	Imported   int      `json:"imported"`
	Skipped    int      `json:"skipped"`
	Failed     int      `json:"failed"`
	Expired    int      `json:"expired"`
	Translated int      `json:"translated"`
	SavedIDs   []string `json:"files"`
}

// SyncTemplates 同步 nuclei 模板库增量并入库。
func (p *Pipeline) SyncTemplates(ctx context.Context, full bool, limit int) (SyncSummary, error) {
	cfg := config.Current()
	out := SyncSummary{SyncResult: nuclei.SyncResult{Files: []string{}}, SavedIDs: []string{}}
	tpls, res, err := nuclei.Sync(ctx, p.st.Paths(), cfg.Nuclei, full, limit)
	out.SyncResult = res
	if err != nil {
		return out, err
	}
	if len(tpls) == 0 {
		return out, nil
	}
	llmClient := llm.New(cfg.LLM)
	translated := 0
	for _, t := range tpls {
		v := nuclei.FromTemplate(t)
		if _, err := p.st.Get(v.ID); err == nil {
			out.Skipped++
			continue
		}
		if store.TooOld(v, cfg.Collect.KeepDays) {
			out.Expired++
			continue
		}
		if cfg.Collect.AutoTranslate && llmClient.Available() && !store.IsZhName(v.Name) && translated < 100 {
			if tr, err := llmClient.Translate(ctx, v); err == nil {
				v.Name, v.Summary, v.Principle = tr.Name, tr.Summary, tr.Principle
				v.Translated = true
				translated++
			}
		}
		score, hv, reasons := enrich.Score(v, cfg.Push)
		v.Score, v.HighValue, v.ScoreReasons = score, hv, reasons
		id, err := p.st.Save(v, "", "python", t.Raw)
		if err != nil {
			out.Failed++
			continue
		}
		out.Imported++
		out.SavedIDs = append(out.SavedIDs, id)
	}
	out.Translated = translated
	out.Files = out.SavedIDs
	nuclei.Commit(p.st.Paths(), res.To, out.Imported)
	return out, nil
}

// Rebuild 对全库存量数据重新富化与评分（从旧版迁移后补字段、调整推送规则后重算）。
func (p *Pipeline) Rebuild(ctx context.Context) map[string]any {
	cfg := config.Current()
	en := enrich.New(cfg.Enrich, p.st.Paths().CacheDir)
	if cfg.Enrich.KEV {
		_ = en.LoadKEV(ctx)
	}
	all := p.st.All()
	cves := []string{}
	for _, v := range all {
		cves = append(cves, v.CVEs...)
		if len(v.CVEs) == 0 {
			cves = append(cves, enrich.ExtractCVEs(v.ID, v.Name, v.Summary)...)
		}
	}
	epssMap := en.EPSSBatch(ctx, cves)
	updated, high, failed := 0, 0, 0
	for _, meta := range all {
		full, err := p.st.Get(meta.ID)
		if err != nil {
			failed++
			continue
		}
		en.Apply(full)
		if e, ok := epssMap[firstCVE(full.CVEs)]; ok {
			full.EPSS = e.Score
			full.EPSSPercentile = e.Percentile
		}
		score, hv, reasons := enrich.Score(full, cfg.Push)
		full.Score, full.HighValue, full.ScoreReasons = score, hv, reasons
		if _, err := p.saveExisting(full); err != nil {
			failed++
			continue
		}
		updated++
		if hv {
			high++
		}
	}
	return map[string]any{"total": len(all), "updated": updated, "high_value": high, "failed": failed}
}

// TranslateOne 翻译单条情报。
func (p *Pipeline) TranslateOne(ctx context.Context, vid string) (map[string]any, error) {
	v, err := p.st.Get(vid)
	if err != nil {
		return nil, fmt.Errorf("漏洞不存在")
	}
	if v.Translated || store.IsZhName(v.Name) {
		return map[string]any{"ok": true, "skipped": true, "message": "已是中文"}, nil
	}
	cfg := config.Current()
	client := llm.New(cfg.LLM)
	if !client.Available() {
		return nil, fmt.Errorf("LLM 未配置，无法翻译")
	}
	tr, err := client.Translate(ctx, v)
	if err != nil {
		return nil, err
	}
	v.Name, v.Summary, v.Principle = tr.Name, tr.Summary, tr.Principle
	v.Translated = true
	if _, err := p.saveExisting(v); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "name": tr.Name, "summary": tr.Summary, "principle": tr.Principle}, nil
}

// Backfill 批量翻译。
func (p *Pipeline) Backfill(ctx context.Context, limit int, ids []string) map[string]any {
	cfg := config.Current()
	client := llm.New(cfg.LLM)
	ok := 0
	skipped := 0
	failed := []map[string]string{}
	done := []string{}
	names := []string{}

	targets := []*model.Vuln{}
	if len(ids) > 0 {
		for _, id := range ids {
			if v, err := p.st.Get(id); err == nil {
				targets = append(targets, v)
			} else {
				failed = append(failed, map[string]string{"id": id, "reason": "漏洞不存在"})
			}
		}
	} else {
		for _, v := range p.st.All() {
			if len(targets) >= limit {
				break
			}
			if !v.Translated && !store.IsZhName(v.Name) {
				targets = append(targets, v)
			}
		}
	}
	for _, v := range targets {
		if v.Translated || store.IsZhName(v.Name) {
			skipped++
			continue
		}
		if !client.Available() {
			failed = append(failed, map[string]string{"id": v.ID, "reason": "LLM 未配置"})
			continue
		}
		tr, err := client.Translate(ctx, v)
		if err != nil {
			failed = append(failed, map[string]string{"id": v.ID, "reason": truncate(err.Error(), 120)})
			continue
		}
		v.Name, v.Summary, v.Principle = tr.Name, tr.Summary, tr.Principle
		v.Translated = true
		if _, err := p.saveExisting(v); err != nil {
			failed = append(failed, map[string]string{"id": v.ID, "reason": err.Error()})
			continue
		}
		ok++
		done = append(done, v.ID)
		names = append(names, v.Name)
	}
	if failed == nil {
		failed = []map[string]string{}
	}
	return map[string]any{"ok": ok, "skipped": skipped, "failed": failed, "ids": done, "names": names}
}

// GenPOC 生成/重生成 Python PoC。
func (p *Pipeline) GenPOC(ctx context.Context, vid string) (int, error) {
	v, err := p.st.Get(vid)
	if err != nil {
		return 0, fmt.Errorf("漏洞不存在")
	}
	cfg := config.Current()
	client := llm.New(cfg.LLM)
	if !client.Available() {
		return 0, fmt.Errorf("LLM 未配置，无法生成 PoC")
	}
	poc, err := client.GenPOC(ctx, v)
	if err != nil {
		return 0, err
	}
	v.POC = poc
	v.POCSource = "ai"
	if _, err := p.saveExisting(v); err != nil {
		return 0, err
	}
	return len([]rune(poc)), nil
}

// GenNuclei 为指定漏洞生成 nuclei 模板。
func (p *Pipeline) GenNuclei(ctx context.Context, vid string, allowWrite bool) (map[string]any, int, error) {
	v, err := p.st.Get(vid)
	if err != nil {
		return nil, 404, fmt.Errorf("漏洞不存在")
	}
	if v.POCSource == "nuclei" {
		return nil, 404, fmt.Errorf("该条目本身来自 nuclei 模板库，无需再生成")
	}
	cfg := config.Current()
	client := llm.New(cfg.LLM)
	yamlText, origin, err := nuclei.Generate(ctx, v, v.POC, client, allowWrite)
	if err != nil {
		return map[string]any{"ok": false, "reason": err.Error(), "origin": origin}, 400, nil
	}
	v.NucleiYAML = yamlText
	if _, err := p.saveExisting(v); err != nil {
		return nil, 500, err
	}
	return map[string]any{"ok": true, "origin": origin, "yaml": yamlText}, 200, nil
}

func (p *Pipeline) saveExisting(v *model.Vuln) (string, error) {
	lang := "python"
	if strings.HasPrefix(v.POCFile, "poc.") {
		lang = strings.TrimPrefix(v.POCFile, "poc.")
	}
	return p.st.Save(v, v.POC, lang, v.NucleiYAML)
}
