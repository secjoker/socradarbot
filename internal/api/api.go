// Package api 提供 HTTP 接口层。
//
// 兼容性：旧版 Python 的 22 个接口路径、方法、参数与返回字段全部保留，
// 前端无需改动；新增 /api/stats 与 /api/push* 系列接口用于富化展示与推送管理。
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"socradarbot/internal/config"
	"socradarbot/internal/crawler"
	"socradarbot/internal/enrich"
	"socradarbot/internal/llm"
	"socradarbot/internal/nuclei"
	"socradarbot/internal/pipeline"
	"socradarbot/internal/push"
	"socradarbot/internal/source"
	"socradarbot/internal/store"
)

const Version = "1.2.0"

type Server struct {
	st    *store.Store
	pl    *pipeline.Pipeline
	pm    *push.Manager
	paths config.Paths
	web   string

	collectMu sync.Mutex
	syncMu    sync.Mutex

	mu                sync.RWMutex
	collectRunning    bool
	collectLastRun    time.Time
	collectLastResult any
	syncRunning       bool
	syncLastRun       time.Time
	syncLastResult    any
}

func New(st *store.Store, pl *pipeline.Pipeline, pm *push.Manager, p config.Paths, webDir string) *Server {
	return &Server{st: st, pl: pl, pm: pm, paths: p, web: webDir}
}

// Handler 组装路由。静态前端挂在 "/" 兜底，/api/* 优先匹配。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "name": "SocradarBot", "version": Version,
			"time": time.Now().Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("POST /api/enrich/rebuild", s.handleRebuild)

	// 漏洞
	mux.HandleFunc("GET /api/vulns", s.handleList)
	mux.HandleFunc("GET /api/vulns/{vid}", s.handleDetail)
	mux.HandleFunc("POST /api/vulns/purge", s.handlePurge)

	// 抓取
	mux.HandleFunc("POST /api/collect", s.handleCollect)
	mux.HandleFunc("GET /api/collect/status", s.handleCollectStatus)

	// nuclei 双向通道
	mux.HandleFunc("GET /api/nuclei/sync", s.handleSyncStatus)
	mux.HandleFunc("POST /api/nuclei/sync", s.handleSyncRun)
	mux.HandleFunc("GET /api/nuclei/templates", s.handleTemplates)
	mux.HandleFunc("GET /api/nuclei/remote", s.handleRemote)
	mux.HandleFunc("POST /api/nuclei/pull", s.handlePull)
	mux.HandleFunc("POST /api/vulns/{vid}/nuclei", s.handleGenNuclei)

	// AI 加工
	mux.HandleFunc("POST /api/vulns/{vid}/poc", s.handleGenPOC)
	mux.HandleFunc("POST /api/vulns/{vid}/translate", s.handleTranslate)
	mux.HandleFunc("POST /api/translate/backfill", s.handleBackfill)
	mux.HandleFunc("GET /api/llm/status", s.handleLLMStatus)

	// 设置
	mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	mux.HandleFunc("POST /api/settings", s.handleSaveSettings)
	mux.HandleFunc("POST /api/settings/test", s.handleTestLLM)

	// 漏洞源
	mux.HandleFunc("GET /api/sources", s.handleSources)
	mux.HandleFunc("POST /api/sources", s.handleAddSource)
	mux.HandleFunc("DELETE /api/sources/{name}", s.handleDelSource)
	mux.HandleFunc("POST /api/sources/discover", s.handleDiscover)

	// 高价值推送
	mux.HandleFunc("GET /api/push", s.handleGetPush)
	mux.HandleFunc("POST /api/push", s.handleSavePush)
	mux.HandleFunc("POST /api/push/test", s.handlePushTest)
	mux.HandleFunc("POST /api/push/run", s.handlePushRun)
	mux.HandleFunc("GET /api/push/history", s.handlePushHistory)
	mux.HandleFunc("POST /api/vulns/{vid}/push", s.handlePushOne)

	mux.Handle("/", staticHandler(s.web))
	return withRecover(withCORS(mux))
}

// ── 漏洞 ─────────────────────────────────────────────────

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := store.ListOptions{
		Page:      queryInt(q.Get("page"), 1),
		PageSize:  queryInt(q.Get("page_size"), 10),
		Source:    q.Get("source"),
		HighValue: q.Get("high_value") == "1" || q.Get("high_value") == "true",
		MinScore:  queryInt(q.Get("min_score"), 0),
		Keyword:   q.Get("q"),
		Unpushed:  q.Get("unpushed") == "1" || q.Get("unpushed") == "true",
		Severity:  q.Get("severity"),
		KEV:       q.Get("kev") == "1" || q.Get("kev") == "true",
		POC:       q.Get("poc") == "1" || q.Get("poc") == "true",
		Vendor:    q.Get("vendor"),
		Sort:      q.Get("sort"),
	}
	writeJSON(w, 200, s.st.List(opts))
}

func (s *Server) handleDetail(w http.ResponseWriter, r *http.Request) {
	v, err := s.st.Get(r.PathValue("vid"))
	if err != nil {
		writeErr(w, 404, "漏洞不存在")
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handlePurge(w http.ResponseWriter, r *http.Request) {
	keep := config.Current().Collect.KeepDays
	if keep <= 0 {
		writeErr(w, 400, "保留天数为 0，未启用按日期清理")
		return
	}
	removed, ids, failed := s.st.Purge(keep)
	writeJSON(w, 200, map[string]any{"removed": removed, "ids": ids, "failed": failed})
}

// ── 采集 ─────────────────────────────────────────────────

func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	writeJSON(w, 200, s.TriggerCollect(ctx))
}

func (s *Server) handleCollectStatus(w http.ResponseWriter, r *http.Request) {
	interval := config.Current().Collect.IntervalMinutes
	s.mu.RLock()
	defer s.mu.RUnlock()
	lastRun, next := "", ""
	if !s.collectLastRun.IsZero() {
		lastRun = s.collectLastRun.Format("2006-01-02T15:04:05")
		next = s.collectLastRun.Add(time.Duration(interval) * time.Minute).Format("2006-01-02T15:04:05")
	}
	writeJSON(w, 200, map[string]any{
		"running": s.collectRunning, "last_run": lastRun,
		"last_result": s.collectLastResult, "interval_minutes": interval, "next_run": next,
	})
}

// TriggerCollect 是定时任务与手动接口共用的唯一入口（互斥防撞车）。
func (s *Server) TriggerCollect(ctx context.Context) map[string]any {
	if !s.collectMu.TryLock() {
		return map[string]any{"skipped": true, "reason": "已有抓取任务在运行"}
	}
	defer s.collectMu.Unlock()
	s.mu.Lock()
	s.collectRunning = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.collectRunning = false
		s.mu.Unlock()
	}()

	res, err := s.pl.RunCollect(ctx)
	s.mu.Lock()
	s.collectLastRun = time.Now()
	s.mu.Unlock()
	if err != nil {
		m := map[string]any{"error": err.Error()}
		s.mu.Lock()
		s.collectLastResult = m
		s.mu.Unlock()
		return m
	}
	m := toMap(res)
	s.mu.Lock()
	s.collectLastResult = m
	s.mu.Unlock()
	return m
}

// ── nuclei ───────────────────────────────────────────────

func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := nuclei.Status(s.paths)
	out["running"] = s.syncRunning
	out["last_run"] = ""
	if !s.syncLastRun.IsZero() {
		out["last_run"] = s.syncLastRun.Format("2006-01-02T15:04:05")
	}
	out["last_result"] = s.syncLastResult
	writeJSON(w, 200, out)
}

func (s *Server) handleSyncRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Full  bool `json:"full"`
		Limit int  `json:"limit"`
	}
	_ = decodeBody(r, &req)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	writeJSON(w, 200, s.TriggerSync(ctx, req.Full, req.Limit))
}

func (s *Server) TriggerSync(ctx context.Context, full bool, limit int) map[string]any {
	if !s.syncMu.TryLock() {
		return map[string]any{"skipped": true, "reason": "已有同步任务在运行"}
	}
	defer s.syncMu.Unlock()
	s.mu.Lock()
	s.syncRunning = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.syncRunning = false
		s.mu.Unlock()
	}()

	res, err := s.pl.SyncTemplates(ctx, full, limit)
	s.mu.Lock()
	s.syncLastRun = time.Now()
	s.mu.Unlock()
	if err != nil {
		m := map[string]any{"error": err.Error(), "imported": 0, "files": []string{}}
		s.mu.Lock()
		s.syncLastResult = m
		s.mu.Unlock()
		return m
	}
	m := toMap(res)
	s.mu.Lock()
	s.syncLastResult = m
	s.mu.Unlock()
	return m
}

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"dir": s.paths.TplDir, "items": s.st.Templates()})
}

func (s *Server) handleRemote(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	q := r.URL.Query()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	tpls, err := nuclei.FetchRemote(ctx, crawler.Client(30*time.Second),
		cfg.Nuclei.Repo, cfg.Nuclei.Ref, queryInt(q.Get("limit"), 10),
		q.Get("severity"), q.Get("tag"), s.paths.CacheDir, cfg.Enrich.GitHubToken)
	if err != nil {
		writeErr(w, 502, "远程模板库拉取失败: "+err.Error())
		return
	}
	items := []map[string]any{}
	for _, t := range tpls {
		items = append(items, map[string]any{
			"id": t.ID, "name": t.Name, "severity": t.Severity,
			"description": t.Description, "tags": t.Tags, "path": t.Path, "refs": t.Refs,
		})
	}
	writeJSON(w, 200, map[string]any{"repo": cfg.Nuclei.Repo, "ref": cfg.Nuclei.Ref, "items": items})
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Limit    int    `json:"limit"`
		Severity string `json:"severity"`
		Tag      string `json:"tag"`
	}
	_ = decodeBody(r, &req)
	if req.Limit <= 0 {
		req.Limit = 10
	}
	cfg := config.Current()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	tpls, err := nuclei.FetchRemote(ctx, crawler.Client(30*time.Second),
		cfg.Nuclei.Repo, cfg.Nuclei.Ref, req.Limit, req.Severity, req.Tag,
		s.paths.CacheDir, cfg.Enrich.GitHubToken)
	if err != nil {
		writeErr(w, 502, "拉取失败: "+err.Error())
		return
	}
	saved, skipped := []string{}, []string{}
	expired := 0
	for _, t := range tpls {
		v := nuclei.FromTemplate(t)
		if _, err := s.st.Get(v.ID); err == nil {
			skipped = append(skipped, v.ID)
			continue
		}
		if store.TooOld(v, cfg.Collect.KeepDays) {
			expired++
			continue
		}
		score, hv, reasons := enrich.Score(v, cfg.Push)
		v.Score, v.HighValue, v.ScoreReasons = score, hv, reasons
		if _, err := s.st.Save(v, "", "python", t.Raw); err == nil {
			saved = append(saved, v.ID)
		}
	}
	writeJSON(w, 200, map[string]any{"fetched": len(tpls), "saved": saved, "skipped": skipped, "expired": expired})
}

func (s *Server) handleGenNuclei(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AllowWrite bool `json:"allow_write"`
	}
	_ = decodeBody(r, &req)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, status, err := s.pl.GenNuclei(ctx, r.PathValue("vid"), req.AllowWrite)
	if err != nil {
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, status, res)
}

// ── AI 加工 ──────────────────────────────────────────────

func (s *Server) handleGenPOC(w http.ResponseWriter, r *http.Request) {
	vid := r.PathValue("vid")
	if _, err := s.st.Get(vid); err != nil {
		writeErr(w, 404, "漏洞不存在")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	chars, err := s.pl.GenPOC(ctx, vid)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "chars": chars})
}

func (s *Server) handleTranslate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := s.pl.TranslateOne(ctx, r.PathValue("vid"))
	if err != nil {
		if strings.Contains(err.Error(), "不存在") {
			writeErr(w, 404, err.Error())
		} else {
			writeErr(w, 502, err.Error())
		}
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleBackfill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Limit int      `json:"limit"`
		IDs   []string `json:"ids"`
	}
	_ = decodeBody(r, &req)
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Limit > 200 {
		req.Limit = 200
	}
	if len(req.IDs) > 20 {
		req.IDs = req.IDs[:20]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	writeJSON(w, 200, s.pl.Backfill(ctx, req.Limit, req.IDs))
}

func (s *Server) handleLLMStatus(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	client := llm.New(cfg.LLM)
	writeJSON(w, 200, map[string]any{
		"available": client.Available(), "model": cfg.LLM.Model, "base": cfg.LLM.Base,
		"key_set": cfg.LLM.Key != "", "pending_translate": s.st.PendingTranslateCount(),
	})
}

// ── 设置 ─────────────────────────────────────────────────

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	out := map[string]any{
		"llm":         maskedLLM(cfg.LLM),
		"collect":     cfg.Collect,
		"nuclei":      cfg.Nuclei,
		"enrich":      maskedEnrich(cfg.Enrich),
		"sources":     cfg.Sources,
		"push":        maskedPush(cfg.Push),
		"config_file": s.paths.ConfigFile,
		"key_set":     cfg.LLM.Key != "",
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if err := decodeBody(r, &patch); err != nil {
		writeErr(w, 400, "请求体格式错误："+err.Error())
		return
	}
	if pv, ok := patch["push"].(map[string]any); ok {
		mergeMaskedPush(pv, config.Current().Push)
	}
	cfg, err := config.Update(patch)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "config_file": s.paths.ConfigFile, "llm": maskedLLM(cfg.LLM),
	})
}

func (s *Server) handleTestLLM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LLM map[string]any `json:"llm"`
	}
	if err := decodeBody(r, &req); err != nil && err != io.EOF {
		writeErr(w, 400, "请求体格式错误："+err.Error())
		return
	}
	cur := config.Current().LLM
	if v, ok := req.LLM["base"].(string); ok && strings.TrimSpace(v) != "" {
		cur.Base = v
	}
	if v, ok := req.LLM["key"].(string); ok && strings.TrimSpace(v) != "" && !strings.Contains(v, "****") {
		cur.Key = v
	}
	if v, ok := req.LLM["model"].(string); ok && strings.TrimSpace(v) != "" {
		cur.Model = v
	}
	if v, ok := req.LLM["timeout"].(float64); ok && v > 0 {
		cur.Timeout = int(v)
	}
	client := llm.New(cur)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	reply, err := client.Ping(ctx)
	if err != nil {
		writeErr(w, 502, "连接失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "reply": reply, "model": cur.Model, "base": cur.Base})
}

// ── 漏洞源 ───────────────────────────────────────────────

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	builtin := []map[string]any{}
	for _, info := range source.Catalog(cfg) {
		builtin = append(builtin, map[string]any{
			"name": info.Name, "url": info.URL, "builtin": true,
			"id": info.ID, "kind": info.Kind, "description": info.Description, "enabled": info.Enabled,
		})
	}
	custom := []map[string]any{}
	for _, src := range cfg.Sources.Custom {
		custom = append(custom, map[string]any{
			"name": src.Name, "url": src.URL, "enabled": src.Enabled, "builtin": false,
		})
	}
	writeJSON(w, 200, map[string]any{"builtin": builtin, "custom": custom})
}

func (s *Server) handleAddSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, "请求体格式错误："+err.Error())
		return
	}
	url := strings.TrimSpace(req.URL)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		writeErr(w, 400, "源地址必须以 http:// 或 https:// 开头")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, 400, "请填写源名称")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	cfg := config.Current()
	list := append([]config.SourceCfg{}, cfg.Sources.Custom...)
	found := false
	for i := range list {
		if list[i].Name == name {
			list[i] = config.SourceCfg{Name: name, URL: url, Enabled: enabled}
			found = true
			break
		}
	}
	if !found {
		list = append(list, config.SourceCfg{Name: name, URL: url, Enabled: enabled})
	}
	if _, err := config.Update(map[string]any{"sources": map[string]any{"custom": list}}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "sources": list, "message": "已接入 " + name + "，下一轮抓取生效"})
}

func (s *Server) handleDelSource(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg := config.Current()
	rest := []config.SourceCfg{}
	found := false
	for _, src := range cfg.Sources.Custom {
		if src.Name == name {
			found = true
			continue
		}
		rest = append(rest, src)
	}
	if !found {
		writeErr(w, 404, "未找到源："+name)
		return
	}
	if _, err := config.Update(map[string]any{"sources": map[string]any{"custom": rest}}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "sources": rest, "message": "已移除 " + name})
}

type verdict struct {
	IsVulnSource  bool   `json:"is_vuln_source"`
	Reason        string `json:"reason"`
	SuggestedName string `json:"suggested_name"`
	ByLLM         bool   `json:"by_llm"`
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string `json:"url"`
		LLMJudge *bool  `json:"llm_judge"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, "请求体格式错误："+err.Error())
		return
	}
	url := strings.TrimSpace(req.URL)
	if url == "" {
		writeErr(w, 400, "请填写社区地址")
		return
	}
	judge := true
	if req.LLMJudge != nil {
		judge = *req.LLMJudge
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	results := crawler.Probe(ctx, crawler.Client(12*time.Second), url)
	if len(results) == 0 {
		writeJSON(w, 200, map[string]any{
			"ok": false, "message": "常见路径都没找到 feed；该站可能是 JS 渲染的列表页，可先在浏览器里找到它的 RSS 地址再填进来",
			"tried": crawler.FeedSuffixes(), "candidates": []any{},
		})
		return
	}
	// 条目最多的最可能是主源
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Entries > results[i].Entries {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	client := llm.New(config.Current().LLM)
	candidates := []map[string]any{}
	for _, cand := range results {
		v := verdict{IsVulnSource: true, Reason: "未启用 AI 判活", ByLLM: false}
		if judge {
			v = judgeFeed(ctx, client, cand.URL, cand.Titles)
		}
		candidates = append(candidates, map[string]any{
			"url": cand.URL, "entries": cand.Entries, "titles": cand.Titles, "verdict": v,
		})
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "best": results[0].URL, "candidates": candidates,
		"message": fmt.Sprintf("找到 %d 个 feed", len(results)),
	})
}

func judgeFeed(ctx context.Context, client *llm.Client, url string, titles []string) verdict {
	if len(titles) == 0 {
		return verdict{Reason: "未取到任何条目标题"}
	}
	if client.Available() {
		sys := "你是漏洞情报甄别助手。用户给一个网站 RSS/Atom 源解析出的最新文章标题，" +
			"你要判断这个站点是不是「漏洞技术社区」——即内容以漏洞分析、漏洞复现、安全研究、攻防技术为主。" +
			"只返回 JSON，不要解释。"
		user := fmt.Sprintf("网站：%s\n\n最新文章：\n- %s\n\n返回这个 JSON：\n"+
			`{"is_vuln_source":true/false,"reason":"一句话理由","suggested_name":"给这个源起个简短中文名"}`,
			url, strings.Join(titles, "\n- "))
		var out struct {
			IsVulnSource  bool   `json:"is_vuln_source"`
			Reason        string `json:"reason"`
			SuggestedName string `json:"suggested_name"`
		}
		if err := client.ChatJSON(ctx, sys, user, &out); err == nil {
			return verdict{IsVulnSource: out.IsVulnSource, Reason: truncate(out.Reason, 200),
				SuggestedName: truncate(out.SuggestedName, 30), ByLLM: true}
		}
	}
	// LLM 不可用：标题关键词兜底，宁可放过不误杀
	hints := []string{"漏洞", "CVE", "漏洞利用", "复现", "0day", "RCE", "任意文件", "权限提升",
		"vulnerability", "exploit", "injection"}
	hit := []string{}
	for _, h := range hints {
		for _, t := range titles {
			if strings.Contains(strings.ToLower(t), strings.ToLower(h)) {
				hit = append(hit, h)
				break
			}
		}
	}
	return verdict{IsVulnSource: len(hit) > 0,
		Reason: fmt.Sprintf("LLM 不可用，按标题关键词判断：命中 %v", hit), ByLLM: false}
}

// ── 推送 ─────────────────────────────────────────────────

func (s *Server) handleGetPush(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	out := maskedPush(cfg.Push)
	out["pending"] = len(s.st.PendingHighValue(0))
	writeJSON(w, 200, out)
}

func (s *Server) handleSavePush(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if err := decodeBody(r, &patch); err != nil {
		writeErr(w, 400, "请求体格式错误："+err.Error())
		return
	}
	// 与现有配置深度合并：局部更新不应把未提交的字段重置为零值
	base := toMap(config.Current().Push)
	deepMerge(base, patch)
	mergeMaskedPush(base, config.Current().Push)
	// 收敛为强类型再落盘：丢弃 webhook_set 之类的只读字段，同时统一类型
	var p config.Push
	raw, _ := json.Marshal(base)
	_ = json.Unmarshal(raw, &p)
	if _, err := config.Update(map[string]any{"push": toMap(p)}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg := config.Current()
	out := maskedPush(cfg.Push)
	out["ok"] = true
	writeJSON(w, 200, out)
}

// deepMerge 递归合并 map，数组整体替换。
func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if sv, ok := v.(map[string]any); ok {
			if dv, ok := dst[k].(map[string]any); ok {
				deepMerge(dv, sv)
				continue
			}
			dst[k] = sv
			continue
		}
		dst[k] = v
	}
}

func (s *Server) handlePushTest(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	writeJSON(w, 200, s.pm.Test(ctx, cfg.Push))
}

func (s *Server) handlePushRun(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	writeJSON(w, 200, s.pm.PushPending(ctx, cfg.Push, "manual"))
}

func (s *Server) handlePushHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.pm.History()})
}

func (s *Server) handlePushOne(w http.ResponseWriter, r *http.Request) {
	v, err := s.st.Get(r.PathValue("vid"))
	if err != nil {
		writeErr(w, 404, "漏洞不存在")
		return
	}
	cfg := config.Current()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	writeJSON(w, 200, s.pm.PushOne(ctx, cfg.Push, v))
}

// ── 统计 ─────────────────────────────────────────────────

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	stats := s.st.Stats()
	s.mu.RLock()
	stats["collect_running"] = s.collectRunning
	stats["sync_running"] = s.syncRunning
	lastRun := ""
	if !s.collectLastRun.IsZero() {
		lastRun = s.collectLastRun.Format("2006-01-02T15:04:05")
	}
	s.mu.RUnlock()
	stats["last_collect"] = lastRun
	stats["push_enabled"] = cfg.Push.Enabled
	stats["push_channels"] = len(cfg.Push.Channels)
	stats["llm_available"] = llm.New(cfg.LLM).Available()
	stats["version"] = Version
	writeJSON(w, 200, stats)
}

// handleRebuild 重新富化全库（迁移旧数据后补齐 CVE/EPSS/KEV/评分）。
func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	writeJSON(w, 200, s.pl.Rebuild(ctx))
}

// ── 辅助 ─────────────────────────────────────────────────

func maskedLLM(c config.LLM) map[string]any {
	return map[string]any{
		"base": c.Base, "key": maskSecret(c.Key), "model": c.Model, "timeout": c.Timeout,
	}
}

func maskedEnrich(c config.Enrich) map[string]any {
	return map[string]any{
		"enabled": c.Enabled, "epss": c.EPSS, "kev": c.KEV,
		"github_advisory": c.GitHubAdvisory, "nvd": c.NVD,
		"timeout_seconds": c.TimeoutSeconds, "cache_hours": c.CacheHours,
		"github_token": maskSecret(c.GitHubToken),
	}
}

func maskedPush(p config.Push) map[string]any {
	channels := []map[string]any{}
	for _, ch := range p.Channels {
		channels = append(channels, map[string]any{
			"name": ch.Name, "type": ch.Type, "enabled": ch.Enabled,
			"webhook": maskSecret(ch.Webhook), "webhook_set": ch.Webhook != "",
			"secret": maskSecret(ch.Secret), "secret_set": ch.Secret != "",
			"chat_ids": ch.ChatIDs, "channel": ch.Channel,
		})
	}
	return map[string]any{
		"enabled": p.Enabled, "min_score": p.MinScore, "min_severity": p.MinSeverity,
		"require_cve": p.RequireCVE, "require_poc": p.RequirePOC,
		"keywords_include": p.KeywordsInclude, "keywords_exclude": p.KeywordsExclude,
		"max_per_batch": p.MaxPerBatch, "cooldown_minutes": p.CooldownMinutes,
		"channels": channels,
	}
}

// mergeMaskedPush 把前端回传的脱敏 webhook 还原为已保存的真实值。
func mergeMaskedPush(patch map[string]any, old config.Push) {
	raw, ok := patch["channels"].([]any)
	if !ok {
		return
	}
	for _, item := range raw {
		ch, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := ch["name"].(string)
		hook, _ := ch["webhook"].(string)
		secret, _ := ch["secret"].(string)
		prev := old.FindChannel(name)
		if prev == nil {
			continue
		}
		if hook == "" || strings.Contains(hook, "****") {
			ch["webhook"] = prev.Webhook
		}
		if secret == "" || strings.Contains(secret, "****") {
			ch["secret"] = prev.Secret
		}
	}
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 12 {
		return "****"
	}
	return s[:6] + "****" + s[len(s)-4:]
}

func decodeBody(r *http.Request, dst any) error {
	if r.Body == nil {
		return io.EOF
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == io.EOF {
		return nil
	}
	return err
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def
	}
	return n
}

func toMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return map[string]any{}
	}
	return m
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"detail": msg})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[panic] %s %s → %v", r.Method, r.URL.Path, rec)
				writeErr(w, 500, "服务器内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

const landingHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>SocradarBot</title><style>body{background:#0f1115;color:#e6edf3;font-family:system-ui,sans-serif;
max-width:720px;margin:80px auto;padding:0 24px;line-height:1.7}code{background:#1c2128;padding:2px 6px;border-radius:4px}
h1{font-weight:600}a{color:#58a6ff}</style></head><body>
<h1>SocradarBot</h1><p>Go 后端已启动。前端静态资源未部署（<code>web/dist</code> 不存在）。</p>
<ul><li><a href="/api/health">/api/health</a> 健康检查</li>
<li><a href="/api/stats">/api/stats</a> 统计信息</li>
<li><a href="/api/vulns">/api/vulns</a> 漏洞列表</li>
<li><a href="/api/push">/api/push</a> 推送配置</li></ul>
<p>构建前端：<code>cd web &amp;&amp; npm install &amp;&amp; npm run build</code>，或直接使用 Vite 开发服务器（5173 端口，代理到 8100）。</p>
</body></html>`

func staticHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, 404, "接口不存在")
			return
		}
		if dir != "" {
			p := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/")))
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				fs.ServeHTTP(w, r)
				return
			}
			if _, err := os.Stat(filepath.Join(dir, "index.html")); err == nil {
				http.ServeFile(w, r, filepath.Join(dir, "index.html"))
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(landingHTML))
	})
}
