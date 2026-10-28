// Package push 实现高价值情报识别与多通道推送。
//
// 判定规则（全部可由配置调整，见 config.Push）：
//   - 评分阈值 min_score（默认 60，评分模型见 enrich.Score）
//   - 严重性下限 min_severity
//   - require_cve / require_poc 硬性条件
//   - 关键词白名单（标题+摘要命中任一）与黑名单（仅标题，避免误杀）
//
// 去重策略：
//  1. 入库前去重：同 ID / 同 CVE 不再新增（pipeline 负责）
//  2. 推送去重：pushed 标记 + 同批 CVE 只推评分最高的一条
//  3. 冷却窗口：cooldown_minutes 内不重复推送同一 CVE
//
// 推送渠道：企业微信、钉钉、飞书、Slack、Telegram、通用 Webhook。
package push

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"socradarbot/internal/config"
	"socradarbot/internal/enrich"
	"socradarbot/internal/model"
	"socradarbot/internal/store"
)

// ChannelResult 单个渠道的发送结果。
type ChannelResult struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ItemBrief 推送条目的精简信息（历史与响应体用）。
type ItemBrief struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	CVEs     []string `json:"cves,omitempty"`
	Score    int      `json:"score"`
	Severity string   `json:"severity"`
}

// BatchResult 一次推送的结果。
type BatchResult struct {
	Selected int             `json:"selected"`
	Pushed   int             `json:"pushed"`
	Skipped  int             `json:"skipped"`
	Channels []ChannelResult `json:"channels"`
	Items    []ItemBrief     `json:"items"`
	Message  string          `json:"message,omitempty"`
}

// HistoryEntry 推送历史。
type HistoryEntry struct {
	At       string          `json:"at"`
	Trigger  string          `json:"trigger"` // collect|manual|test|single
	Selected int             `json:"selected"`
	Pushed   int             `json:"pushed"`
	Channels []ChannelResult `json:"channels"`
	Items    []ItemBrief     `json:"items"`
	Message  string          `json:"message,omitempty"`
}

// Manager 负责选择、发送与状态回写。
type Manager struct {
	mu       sync.Mutex
	st       *store.Store
	histPath string
	client   *http.Client
}

func New(st *store.Store, histPath string) *Manager {
	return &Manager{st: st, histPath: histPath, client: &http.Client{Timeout: 15 * time.Second}}
}

// PushPending 推送当前所有待推送的高价值情报。
func (m *Manager) PushPending(ctx context.Context, cfg config.Push, trigger string) BatchResult {
	res := BatchResult{Items: []ItemBrief{}, Channels: []ChannelResult{}}
	if !cfg.Enabled {
		res.Message = "推送未启用（push.enabled=false）"
		return res
	}
	channels := enabledChannels(cfg)
	if len(channels) == 0 {
		res.Message = "未配置启用的推送渠道"
		return res
	}

	selected, dupIDs := m.selectVulns(cfg)
	res.Skipped = len(dupIDs)
	if len(selected) == 0 {
		res.Message = "无待推送的高价值情报"
		return res
	}
	res.Selected = len(selected)
	for _, v := range selected {
		res.Items = append(res.Items, ItemBrief{ID: v.ID, Name: v.Name, CVEs: v.CVEs, Score: v.Score, Severity: v.Severity})
	}

	blocks := messageBlocks(selected)
	res.Channels = m.sendBlocks(ctx, channels, buildTitle(selected), blocks)
	anyOK := countOK(res.Channels) > 0

	ids := make([]string, 0, len(selected))
	for _, v := range selected {
		ids = append(ids, v.ID)
	}
	if anyOK {
		_ = m.st.MarkPushed(ids, "")
		res.Pushed = len(ids)
		res.Message = fmt.Sprintf("已推送 %d 条至 %d 个渠道", len(ids), countOK(res.Channels))
	} else {
		res.Message = "所有渠道均发送失败，条目保留在待推送队列"
	}
	if len(dupIDs) > 0 {
		m.st.MarkPushSkipped(dupIDs, "cve-duplicate")
	}
	m.appendHistory(HistoryEntry{
		At: time.Now().UTC().Format(time.RFC3339), Trigger: trigger,
		Selected: res.Selected, Pushed: res.Pushed, Channels: res.Channels,
		Items: res.Items, Message: res.Message,
	})
	return res
}

// PushOne 推送指定单条漏洞（详情页手动推送）。
func (m *Manager) PushOne(ctx context.Context, cfg config.Push, v *model.Vuln) BatchResult {
	res := BatchResult{Items: []ItemBrief{}, Channels: []ChannelResult{}}
	channels := enabledChannels(cfg)
	if len(channels) == 0 {
		res.Message = "未配置启用的推送渠道"
		return res
	}
	score, _, _ := enrich.Score(v, cfg)
	v.Score = score
	res.Selected = 1
	res.Items = []ItemBrief{{ID: v.ID, Name: v.Name, CVEs: v.CVEs, Score: v.Score, Severity: v.Severity}}
	text := messageBlocks([]*model.Vuln{v})
	res.Channels = m.sendBlocks(ctx, channels, "SocradarBot 漏洞情报", text)
	anyOK := countOK(res.Channels) > 0
	if anyOK {
		_ = m.st.MarkPushed([]string{v.ID}, "")
		res.Pushed = 1
		res.Message = "已推送"
	} else {
		res.Message = "所有渠道均发送失败"
	}
	m.appendHistory(HistoryEntry{
		At: time.Now().UTC().Format(time.RFC3339), Trigger: "single",
		Selected: 1, Pushed: res.Pushed, Channels: res.Channels,
		Items: res.Items, Message: res.Message,
	})
	return res
}

// Test 发送一条测试消息到所有启用渠道。
func (m *Manager) Test(ctx context.Context, cfg config.Push) BatchResult {
	res := BatchResult{Items: []ItemBrief{}, Channels: []ChannelResult{}}
	channels := enabledChannels(cfg)
	if len(channels) == 0 {
		res.Message = "未配置启用的推送渠道"
		return res
	}
	sample := []*model.Vuln{{
		ID: "test-000000000000", Name: "【测试】SocradarBot 推送链路验证",
		Source: "system", Summary: "这是一条测试消息，用于验证 webhook、签名与报文格式是否正确。",
		Severity: "high", Score: 88, CVEs: []string{"CVE-2026-0000"},
		AttackScope: "测试记录，无实际影响", Published: time.Now().Format("2006-01-02"),
		POCSource: "ai", Refs: []string{"https://example.com/socradarbot"},
	}}
	text := messageBlocks(sample)
	for _, ch := range channels {
		cr := m.sendBlocks(ctx, []config.PushChannel{ch}, "SocradarBot 推送测试", text)
		res.Channels = append(res.Channels, cr...)
	}
	for _, cr := range res.Channels {
		if cr.OK {
			res.Pushed++
		}
	}
	res.Selected = 1
	res.Items = []ItemBrief{{ID: sample[0].ID, Name: sample[0].Name, Score: sample[0].Score, Severity: sample[0].Severity}}
	res.Message = fmt.Sprintf("测试消息已发送：成功 %d / %d 个渠道", countOK(res.Channels), len(channels))
	m.appendHistory(HistoryEntry{
		At: time.Now().UTC().Format(time.RFC3339), Trigger: "test",
		Selected: 1, Pushed: res.Pushed, Channels: res.Channels, Items: res.Items, Message: res.Message,
	})
	return res
}

// History 返回最近推送记录（倒序）。
func (m *Manager) History() []HistoryEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadHistory()
}

func (m *Manager) selectVulns(cfg config.Push) ([]*model.Vuln, []string) {
	pending := m.st.PendingHighValue(cfg.MaxPerBatch * 5)
	selected := []*model.Vuln{}
	dups := []string{}
	seen := map[string]bool{}

	// 冷却窗口：同一 CVE 在 cooldown_minutes 内已被推送过则跳过（跨 ID 去重）
	recent := map[string]time.Time{}
	if cfg.CooldownMinutes > 0 {
		for _, v := range m.st.All() {
			if !v.Pushed || v.PushedAt == "" {
				continue
			}
			at, err := time.Parse("2006-01-02T15:04:05", v.PushedAt)
			if err != nil {
				continue
			}
			for _, c := range v.CVEs {
				c = strings.ToUpper(c)
				if at.After(recent[c]) {
					recent[c] = at
				}
			}
		}
	}
	cutoff := time.Now().UTC().Add(-time.Duration(cfg.CooldownMinutes) * time.Minute)

	for _, v := range pending {
		score, hv, reasons := enrich.Score(v, cfg)
		if !hv {
			continue
		}
		v.Score = score
		v.ScoreReasons = reasons
		if len(v.CVEs) > 0 {
			key := strings.ToUpper(v.CVEs[0])
			if seen[key] {
				dups = append(dups, v.ID)
				continue
			}
			if cfg.CooldownMinutes > 0 {
				if at, ok := recent[key]; ok && at.After(cutoff) {
					dups = append(dups, v.ID)
					continue
				}
			}
			seen[key] = true
		}
		selected = append(selected, v)
		if len(selected) >= cfg.MaxPerBatch {
			break
		}
	}
	return selected, dups
}

func enabledChannels(cfg config.Push) []config.PushChannel {
	out := []config.PushChannel{}
	for _, ch := range cfg.Channels {
		if ch.Enabled && strings.TrimSpace(ch.Webhook) != "" {
			out = append(out, ch)
		}
	}
	return out
}

func countOK(list []ChannelResult) int {
	n := 0
	for _, c := range list {
		if c.OK {
			n++
		}
	}
	return n
}

func buildTitle(vulns []*model.Vuln) string {
	return fmt.Sprintf("SocradarBot 高价值漏洞情报（%d）", len(vulns))
}

func sevBadge(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	}
	return "未知"
}

// messageBlocks 生成每条漏洞的 Markdown 块，便于按条分片。
func messageBlocks(vulns []*model.Vuln) []string {
	blocks := []string{}
	for i, v := range vulns {
		sb := strings.Builder{}
		fmt.Fprintf(&sb, "**%d. [%s] %s**\n", i+1, sevBadge(v.Severity), v.Name)
		meta := []string{}
		if len(v.CVEs) > 0 {
			meta = append(meta, "CVE："+strings.Join(v.CVEs, ", "))
		}
		meta = append(meta, fmt.Sprintf("评分：%d", v.Score))
		sb.WriteString("- " + strings.Join(meta, " ｜ ") + "\n")
		tech := []string{}
		if v.CVSS != nil {
			tech = append(tech, fmt.Sprintf("CVSS %.1f", *v.CVSS))
		}
		if v.EPSS > 0 {
			tech = append(tech, fmt.Sprintf("EPSS %.0f%%", v.EPSS*100))
		}
		if v.KEV {
			tech = append(tech, "CISA KEV ✅")
		}
		if v.HasPOC() {
			tech = append(tech, "PoC 可用")
		}
		if len(tech) > 0 {
			sb.WriteString("- " + strings.Join(tech, " ｜ ") + "\n")
		}
		sb.WriteString(fmt.Sprintf("- 来源：%s ｜ 披露：%s\n", firstNonEmpty(v.Source), firstNonEmpty(v.Published, dateOnly(v.CreatedAt))))
		if len(v.Affected) > 0 {
			sb.WriteString("- 影响：" + strings.Join(limitStrings(v.Affected, 3), "、") + "\n")
		}
		if s := strings.TrimSpace(v.Summary); s != "" {
			sb.WriteString("- 摘要：" + truncate(s, 160) + "\n")
		}
		if len(v.ScoreReasons) > 0 {
			sb.WriteString("- 判定：" + strings.Join(v.ScoreReasons, "、") + "\n")
		}
		if link := firstLink(v.Refs); link != "" {
			sb.WriteString("- 详情：" + link + "\n")
		}
		blocks = append(blocks, strings.TrimSpace(sb.String()))
	}
	return blocks
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "-"
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func firstLink(refs []string) string {
	for _, r := range refs {
		if strings.HasPrefix(r, "http://") || strings.HasPrefix(r, "https://") {
			return r
		}
	}
	return ""
}

func limitStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// ── 渠道发送 ─────────────────────────────────────────────

// sendBlocks 按渠道单条消息上限分片发送，全部成功才视为该渠道成功。
func (m *Manager) sendBlocks(ctx context.Context, channels []config.PushChannel, title string, blocks []string) []ChannelResult {
	out := []ChannelResult{}
	for _, ch := range channels {
		chunks := chunkMarkdown(title, blocks, channelLimit(ch.Type))
		res := ChannelResult{Name: ch.Name, Type: ch.Type, OK: true}
		for _, chunk := range chunks {
			if err := m.dispatch(ctx, ch, title, chunk); err != nil {
				res.OK = false
				res.Error = err.Error()
				break
			}
		}
		out = append(out, res)
	}
	return out
}

// channelLimit 单条消息的字节预算（企业微信 markdown 上限 4096 字节，留出余量）。
func channelLimit(typ string) int {
	switch typ {
	case "wecom":
		return 3800
	case "telegram", "slack":
		return 3800
	case "dingtalk":
		return 18000
	case "feishu":
		return 20000
	default:
		return 100000
	}
}

// chunkMarkdown 以"整条漏洞"为单位分片，避免把一条情报从中间截断。
func chunkMarkdown(title string, blocks []string, maxBytes int) []string {
	header := "## " + title
	chunks := []string{}
	cur := header
	for _, b := range blocks {
		if len(cur)+len(b)+2 > maxBytes && cur != header {
			chunks = append(chunks, cur)
			cur = header
		}
		cur += "\n\n" + b
	}
	chunks = append(chunks, cur)
	return chunks
}

func (m *Manager) dispatch(ctx context.Context, ch config.PushChannel, title, markdown string) error {
	switch ch.Type {
	case "wecom":
		return m.sendWeCom(ctx, ch, markdown)
	case "dingtalk":
		return m.sendDingTalk(ctx, ch, title, markdown)
	case "feishu":
		return m.sendFeishu(ctx, ch, title, markdown)
	case "slack":
		return m.sendSlack(ctx, ch, markdown)
	case "telegram":
		return m.sendTelegram(ctx, ch, markdown)
	case "webhook":
		return m.sendWebhook(ctx, ch, title, markdown)
	default:
		return fmt.Errorf("未知渠道类型: %s", ch.Type)
	}
}

func (m *Manager) post(ctx context.Context, endpoint string, payload any, headers map[string]string) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SocradarBot/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return raw, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, nil
}

func (m *Manager) sendWeCom(ctx context.Context, ch config.PushChannel, markdown string) error {
	raw, err := m.post(ctx, ch.Webhook, map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"content": markdown},
	}, nil)
	if err != nil {
		return err
	}
	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(raw, &r) == nil && r.ErrCode != 0 {
		return fmt.Errorf("企业微信返回 errcode=%d %s", r.ErrCode, r.ErrMsg)
	}
	return nil
}

func (m *Manager) sendDingTalk(ctx context.Context, ch config.PushChannel, title, markdown string) error {
	endpoint := ch.Webhook
	if ch.Secret != "" {
		ts := time.Now().UnixMilli()
		secret := fmt.Sprintf("%d\n%s", ts, ch.Secret)
		h := hmac.New(sha256.New, []byte(ch.Secret))
		h.Write([]byte(secret))
		sign := url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))
		sep := "?"
		if strings.Contains(endpoint, "?") {
			sep = "&"
		}
		endpoint = fmt.Sprintf("%s%stimestamp=%d&sign=%s", endpoint, sep, ts, sign)
	}
	raw, err := m.post(ctx, endpoint, map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"title": title, "text": markdown + "\n"},
	}, nil)
	if err != nil {
		return err
	}
	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(raw, &r) == nil && r.ErrCode != 0 {
		return fmt.Errorf("钉钉返回 errcode=%d %s", r.ErrCode, r.ErrMsg)
	}
	return nil
}

func (m *Manager) sendFeishu(ctx context.Context, ch config.PushChannel, title, markdown string) error {
	endpoint := ch.Webhook
	payload := map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"config": map[string]any{"wide_screen_mode": true},
			"header": map[string]any{
				"template": "red",
				"title":    map[string]string{"tag": "plain_text", "content": title},
			},
			"elements": []map[string]any{
				{"tag": "div", "text": map[string]string{"tag": "lark_md", "content": markdown}},
			},
		},
	}
	if ch.Secret != "" {
		ts := time.Now().Unix()
		strToSign := fmt.Sprintf("%d\n%s", ts, ch.Secret)
		h := hmac.New(sha256.New, []byte(strToSign))
		h.Write(nil)
		payload["timestamp"] = fmt.Sprint(ts)
		payload["sign"] = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	raw, err := m.post(ctx, endpoint, payload, nil)
	if err != nil {
		return err
	}
	var r struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if json.Unmarshal(raw, &r) == nil && r.Code != 0 {
		return fmt.Errorf("飞书返回 code=%d %s", r.Code, r.Msg)
	}
	return nil
}

func (m *Manager) sendSlack(ctx context.Context, ch config.PushChannel, markdown string) error {
	payload := map[string]any{"text": markdown}
	if ch.Channel != "" {
		payload["channel"] = ch.Channel
	}
	_, err := m.post(ctx, ch.Webhook, payload, nil)
	return err
}

func (m *Manager) sendTelegram(ctx context.Context, ch config.PushChannel, markdown string) error {
	endpoint := ch.Webhook
	if !strings.HasPrefix(endpoint, "http") {
		endpoint = "https://api.telegram.org/bot" + endpoint + "/sendMessage"
	}
	if !strings.HasSuffix(endpoint, "/sendMessage") {
		endpoint = strings.TrimRight(endpoint, "/") + "/sendMessage"
	}
	chats := ch.ChatIDs
	if len(chats) == 0 {
		chats = []string{""}
	}
	text := strings.NewReplacer("**", "", "##", "", "`", "").Replace(markdown)
	for _, chat := range chats {
		if chat == "" {
			continue
		}
		raw, err := m.post(ctx, endpoint, map[string]any{
			"chat_id": chat, "text": text, "disable_web_page_preview": true,
		}, nil)
		if err != nil {
			return err
		}
		var r struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		if json.Unmarshal(raw, &r) == nil && !r.OK {
			return fmt.Errorf("Telegram 返回 %s", r.Description)
		}
	}
	return nil
}

func (m *Manager) sendWebhook(ctx context.Context, ch config.PushChannel, title, markdown string) error {
	_, err := m.post(ctx, ch.Webhook, map[string]any{
		"source": "socradarbot", "title": title, "markdown": markdown,
	}, nil)
	return err
}

func (m *Manager) appendHistory(e HistoryEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.loadHistory()
	list = append([]HistoryEntry{e}, list...)
	if len(list) > 100 {
		list = list[:100]
	}
	_ = os.MkdirAll(filepath.Dir(m.histPath), 0o755)
	if b, err := json.MarshalIndent(list, "", "  "); err == nil {
		_ = os.WriteFile(m.histPath, b, 0o644)
	}
}

func (m *Manager) loadHistory() []HistoryEntry {
	b, err := os.ReadFile(m.histPath)
	if err != nil {
		return []HistoryEntry{}
	}
	var list []HistoryEntry
	if json.Unmarshal(b, &list) != nil {
		return []HistoryEntry{}
	}
	return list
}
