// Package config 负责 SocradarBot 的配置加载、校验与原子写回。
//
// 优先级：内置默认值 < config.yaml < 环境变量。
// 设置页保存后立即生效，无需重启（每次取用都通过 Current() 读取最新缓存）。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type LLM struct {
	Base    string `yaml:"base" json:"base"`
	Key     string `yaml:"key" json:"key"`
	Model   string `yaml:"model" json:"model"`
	Timeout int    `yaml:"timeout" json:"timeout"`
}

type Collect struct {
	IntervalMinutes int  `yaml:"interval_minutes" json:"interval_minutes"`
	FetchLimit      int  `yaml:"fetch_limit" json:"fetch_limit"`
	KeepDays        int  `yaml:"keep_days" json:"keep_days"`
	AutoTranslate   bool `yaml:"auto_translate" json:"auto_translate"`
	ArticleFetch    bool `yaml:"article_fetch" json:"article_fetch"`
	TimeoutSeconds  int  `yaml:"timeout_seconds" json:"timeout_seconds"`
}

type Nuclei struct {
	Repo         string `yaml:"repo" json:"repo"`
	Ref          string `yaml:"ref" json:"ref"`
	RemoteLimit  int    `yaml:"remote_limit" json:"remote_limit"`
	FetchRemote  bool   `yaml:"fetch_remote" json:"fetch_remote"`
	GenTemplates bool   `yaml:"gen_templates" json:"gen_templates"`
	SyncEnabled  bool   `yaml:"sync_enabled" json:"sync_enabled"`
	SyncLimit    int    `yaml:"sync_limit" json:"sync_limit"`
}

// Enrich 控制富化数据源与外部情报补全。
type Enrich struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	EPSS           bool   `yaml:"epss" json:"epss"`
	KEV            bool   `yaml:"kev" json:"kev"`
	GitHubAdvisory bool   `yaml:"github_advisory" json:"github_advisory"`
	NVD            bool   `yaml:"nvd" json:"nvd"`
	TimeoutSeconds int    `yaml:"timeout_seconds" json:"timeout_seconds"`
	CacheHours     int    `yaml:"cache_hours" json:"cache_hours"`
	GitHubToken    string `yaml:"github_token" json:"github_token"`
}

type SourceCfg struct {
	Name    string `yaml:"name" json:"name"`
	URL     string `yaml:"url" json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

type Sources struct {
	Custom []SourceCfg `yaml:"custom" json:"custom"`
	// Disabled 按源 ID 停用内置源（seebug/先知/exploit-db/chaitin/oscs/...）
	Disabled []string `yaml:"disabled" json:"disabled"`
}

// PushChannel 一个推送渠道。Type 决定报文格式，Webhook 为机器人地址。
type PushChannel struct {
	Name    string   `yaml:"name" json:"name"`
	Type    string   `yaml:"type" json:"type"` // wecom|dingtalk|feishu|slack|telegram|webhook
	Webhook string   `yaml:"webhook" json:"webhook"`
	Secret  string   `yaml:"secret" json:"secret"`
	Enabled bool     `yaml:"enabled" json:"enabled"`
	ChatIDs []string `yaml:"chat_ids" json:"chat_ids"`
	Channel string   `yaml:"channel" json:"channel"` // Slack 频道覆盖
}

// Push 是高价值情报推送策略。
type Push struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	MinScore        int           `yaml:"min_score" json:"min_score"`
	MinSeverity     string        `yaml:"min_severity" json:"min_severity"`
	RequireCVE      bool          `yaml:"require_cve" json:"require_cve"`
	RequirePOC      bool          `yaml:"require_poc" json:"require_poc"`
	KeywordsInclude []string      `yaml:"keywords_include" json:"keywords_include"`
	KeywordsExclude []string      `yaml:"keywords_exclude" json:"keywords_exclude"`
	MaxPerBatch     int           `yaml:"max_per_batch" json:"max_per_batch"`
	CooldownMinutes int           `yaml:"cooldown_minutes" json:"cooldown_minutes"`
	Channels        []PushChannel `yaml:"channels" json:"channels"`
}

type Config struct {
	LLM     LLM     `yaml:"llm" json:"llm"`
	Collect Collect `yaml:"collect" json:"collect"`
	Nuclei  Nuclei  `yaml:"nuclei" json:"nuclei"`
	Enrich  Enrich  `yaml:"enrich" json:"enrich"`
	Sources Sources `yaml:"sources" json:"sources"`
	Push    Push    `yaml:"push" json:"push"`
}

// Paths 是运行期固定路径（不随设置页变化）。
type Paths struct {
	ConfigFile  string
	DataDir     string
	VulnDir     string
	TplDir      string
	CacheDir    string
	RepoDir     string
	SyncState   string
	PushHistory string
}

var (
	pathsOnce sync.Once
	paths     Paths
)

// ResolvePaths 解析运行路径。支持 SOCRADARBOT_CONFIG / SOCRADARBOT_DATA 覆盖。
func ResolvePaths() Paths {
	pathsOnce.Do(func() {
		cwd, err := os.Getwd()
		if err != nil {
			cwd = "."
		}
		cfgFile := os.Getenv("SOCRADARBOT_CONFIG")
		if cfgFile == "" {
			cfgFile = filepath.Join(cwd, "config.yaml")
		}
		data := os.Getenv("SOCRADARBOT_DATA")
		if data == "" {
			data = filepath.Join(cwd, "data")
		}
		paths = Paths{
			ConfigFile:  cfgFile,
			DataDir:     data,
			VulnDir:     filepath.Join(data, "vulns"),
			TplDir:      filepath.Join(data, "nuclei_tpl"),
			CacheDir:    filepath.Join(data, "cache"),
			RepoDir:     filepath.Join(data, "nuclei_templates"),
			SyncState:   filepath.Join(data, "nuclei_sync.json"),
			PushHistory: filepath.Join(data, "push_history.json"),
		}
	})
	return paths
}

// Defaults 返回内置默认配置。
func Defaults() Config {
	return Config{
		LLM: LLM{Base: "https://api.openai.com", Key: "", Model: "gpt-4o-mini", Timeout: 60},
		Collect: Collect{
			IntervalMinutes: 10, FetchLimit: 10, KeepDays: 90,
			AutoTranslate: true, ArticleFetch: true, TimeoutSeconds: 25,
		},
		Nuclei: Nuclei{
			Repo: "projectdiscovery/nuclei-templates", Ref: "main",
			RemoteLimit: 20, FetchRemote: false, GenTemplates: true,
			SyncEnabled: true, SyncLimit: 0,
		},
		Enrich: Enrich{
			Enabled: true, EPSS: true, KEV: true, GitHubAdvisory: true,
			NVD: true, TimeoutSeconds: 20, CacheHours: 24,
		},
		Sources: Sources{Custom: []SourceCfg{}, Disabled: []string{}},
		Push: Push{
			Enabled: false, MinScore: 60, MinSeverity: "",
			RequireCVE: false, RequirePOC: false,
			KeywordsInclude: []string{}, KeywordsExclude: []string{},
			MaxPerBatch: 10, CooldownMinutes: 30,
			Channels: []PushChannel{},
		},
	}
}

var (
	mu     sync.RWMutex
	cache  *Config
	loaded bool
)

// Current 返回当前生效配置的深拷贝，调用方可安全修改。
func Current() Config {
	mu.RLock()
	c := cache
	ok := loaded
	mu.RUnlock()
	if c != nil && ok {
		return *clone(c)
	}
	mu.Lock()
	defer mu.Unlock()
	if cache != nil && loaded {
		return *clone(cache)
	}
	c2 := loadFromDisk()
	cache = &c2
	loaded = true
	return *clone(&c2)
}

// Reload 强制重新读取配置（设置页保存、外部手改后可用）。
func Reload() Config {
	mu.Lock()
	defer mu.Unlock()
	c := loadFromDisk()
	cache = &c
	loaded = true
	return *clone(&c)
}

func clone(c *Config) *Config {
	b, _ := yaml.Marshal(c)
	var out Config
	_ = yaml.Unmarshal(b, &out)
	return &out
}

func loadFromDisk() Config {
	c := Defaults()
	p := ResolvePaths()
	if b, err := os.ReadFile(p.ConfigFile); err == nil {
		_ = yaml.Unmarshal(b, &c)
	}
	applyEnv(&c)
	return c
}

// applyEnv 支持 SOCRADARBOT_* 与旧版 AI_BAOBAO_* 两套变量，便于平滑迁移。
func applyEnv(c *Config) {
	type envItem struct {
		names []string
		apply func(string)
	}
	items := []envItem{
		{[]string{"SOCRADARBOT_LLM_BASE", "AI_BAOBAO_LLM_BASE"}, func(v string) { c.LLM.Base = v }},
		{[]string{"SOCRADARBOT_LLM_KEY", "AI_BAOBAO_LLM_KEY"}, func(v string) { c.LLM.Key = v }},
		{[]string{"SOCRADARBOT_LLM_MODEL", "AI_BAOBAO_LLM_MODEL"}, func(v string) { c.LLM.Model = v }},
		{[]string{"SOCRADARBOT_INTERVAL_MINUTES", "AI_BAOBAO_INTERVAL_MINUTES"}, func(v string) { c.Collect.IntervalMinutes = atoi(v, c.Collect.IntervalMinutes) }},
		{[]string{"SOCRADARBOT_KEEP_DAYS", "AI_BAOBAO_KEEP_DAYS"}, func(v string) { c.Collect.KeepDays = atoi(v, c.Collect.KeepDays) }},
		{[]string{"SOCRADARBOT_AUTO_TRANSLATE", "AI_BAOBAO_AUTO_TRANSLATE"}, func(v string) { c.Collect.AutoTranslate = atob(v, c.Collect.AutoTranslate) }},
		{[]string{"SOCRADARBOT_NUCLEI_SYNC", "AI_BAOBAO_NUCLEI_SYNC"}, func(v string) { c.Nuclei.SyncEnabled = atob(v, c.Nuclei.SyncEnabled) }},
		{[]string{"SOCRADARBOT_NUCLEI_GEN", "AI_BAOBAO_NUCLEI_GEN"}, func(v string) { c.Nuclei.GenTemplates = atob(v, c.Nuclei.GenTemplates) }},
		{[]string{"SOCRADARBOT_NUCLEI_REPO", "AI_BAOBAO_NUCLEI_REPO"}, func(v string) { c.Nuclei.Repo = v }},
		{[]string{"SOCRADARBOT_NUCLEI_REF", "AI_BAOBAO_NUCLEI_REF"}, func(v string) { c.Nuclei.Ref = v }},
		{[]string{"SOCRADARBOT_ENRICH", "AI_BAOBAO_ENRICH"}, func(v string) { c.Enrich.Enabled = atob(v, c.Enrich.Enabled) }},
		{[]string{"SOCRADARBOT_ENRICH_EPSS"}, func(v string) { c.Enrich.EPSS = atob(v, c.Enrich.EPSS) }},
		{[]string{"SOCRADARBOT_ENRICH_KEV"}, func(v string) { c.Enrich.KEV = atob(v, c.Enrich.KEV) }},
		{[]string{"SOCRADARBOT_ENRICH_NVD"}, func(v string) { c.Enrich.NVD = atob(v, c.Enrich.NVD) }},
		{[]string{"SOCRADARBOT_GITHUB_TOKEN", "GITHUB_TOKEN"}, func(v string) { c.Enrich.GitHubToken = v }},
		{[]string{"SOCRADARBOT_PUSH_ENABLED", "AI_BAOBAO_PUSH_ENABLED"}, func(v string) { c.Push.Enabled = atob(v, c.Push.Enabled) }},
		{[]string{"SOCRADARBOT_PUSH_MIN_SCORE"}, func(v string) { c.Push.MinScore = atoi(v, c.Push.MinScore) }},
	}
	for _, it := range items {
		for _, n := range it.names {
			if v := os.Getenv(n); v != "" {
				it.apply(v)
				break
			}
		}
	}
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func atob(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

const fileHeader = `# SocradarBot 运行配置 —— Web 控制台「设置」页保存到此文件，保存后立即生效。
# 也可手工编辑；优先级：内置默认值 < 本文件 < 环境变量（SOCRADARBOT_*，兼容旧版 AI_BAOBAO_*）。
# 注意：llm.key、push.channels[].webhook 是明文凭据，请勿提交到公开仓库。

`

// Update 深度合并补丁并落盘。空字符串的 llm.key / llm.base 表示"保持原值"。
func Update(patch map[string]any) (*Config, error) {
	if patch == nil {
		patch = map[string]any{}
	}
	if llmPatch, ok := patch["llm"].(map[string]any); ok {
		for _, k := range []string{"key", "base"} {
			if v, exists := llmPatch[k]; exists {
				if s, isStr := v.(string); isStr && strings.TrimSpace(s) == "" {
					delete(llmPatch, k)
				}
			}
		}
		if len(llmPatch) == 0 {
			delete(patch, "llm")
		}
	}
	// 富化凭据同样支持"留空保持原值"
	if ep, ok := patch["enrich"].(map[string]any); ok {
		if v, exists := ep["github_token"]; exists {
			if s, isStr := v.(string); isStr && strings.TrimSpace(s) == "" {
				delete(ep, "github_token")
			}
		}
	}
	normalizeNumbers(patch)

	mu.Lock()
	defer mu.Unlock()

	cur := loadFromDisk()
	base := map[string]any{}
	raw, _ := yaml.Marshal(cur)
	_ = yaml.Unmarshal(raw, &base)
	mergeMaps(base, patch)

	merged, _ := yaml.Marshal(base)
	c := Defaults()
	dec := yaml.NewDecoder(strings.NewReader(string(merged)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not found in type") {
			return nil, fmt.Errorf("未知配置项：%s", msg)
		}
		return nil, fmt.Errorf("配置格式错误：%s", msg)
	}
	applyEnv(&c)
	if err := validate(&c); err != nil {
		return nil, err
	}
	if err := writeFile(&c); err != nil {
		return nil, err
	}
	cache = &c
	loaded = true
	return clone(&c), nil
}

func mergeMaps(dst, src map[string]any) {
	for k, v := range src {
		if sv, ok := v.(map[string]any); ok {
			if dv, ok := dst[k].(map[string]any); ok {
				mergeMaps(dv, sv)
				continue
			}
			dst[k] = sv
			continue
		}
		dst[k] = v
	}
}

// normalizeNumbers 把 JSON 解出的 float64 整数转成 int，避免 yaml 反序列化到 int 失败。
func normalizeNumbers(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if f, ok := val.(float64); ok && f == float64(int64(f)) {
				t[k] = int(f)
			} else {
				normalizeNumbers(val)
			}
		}
	case []any:
		for i, val := range t {
			if f, ok := val.(float64); ok && f == float64(int64(f)) {
				t[i] = int(f)
			} else {
				normalizeNumbers(val)
			}
		}
	}
}

func writeFile(c *Config) error {
	p := ResolvePaths()
	if err := os.MkdirAll(filepath.Dir(p.ConfigFile), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := p.ConfigFile + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(fileHeader), b...), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p.ConfigFile)
}

var severityRank = map[string]int{
	"": 0, "unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

func validate(c *Config) error {
	if c.LLM.Timeout <= 0 {
		return fmt.Errorf("llm.timeout 必须是正整数")
	}
	if strings.TrimSpace(c.LLM.Model) == "" {
		return fmt.Errorf("llm.model 不能为空")
	}
	if b := strings.TrimSpace(c.LLM.Base); b != "" && !strings.HasPrefix(b, "http://") && !strings.HasPrefix(b, "https://") {
		return fmt.Errorf("llm.base 必须以 http:// 或 https:// 开头")
	}
	if c.Collect.IntervalMinutes < 1 {
		return fmt.Errorf("collect.interval_minutes 必须 ≥ 1")
	}
	if c.Collect.FetchLimit < 1 {
		return fmt.Errorf("collect.fetch_limit 必须 ≥ 1")
	}
	if c.Collect.KeepDays < 0 {
		return fmt.Errorf("collect.keep_days 不能为负数")
	}
	if c.Collect.TimeoutSeconds < 5 {
		return fmt.Errorf("collect.timeout_seconds 必须 ≥ 5")
	}
	if c.Nuclei.RemoteLimit < 0 || c.Nuclei.SyncLimit < 0 {
		return fmt.Errorf("nuclei.remote_limit / sync_limit 不能为负数")
	}
	if strings.TrimSpace(c.Nuclei.Repo) == "" || strings.TrimSpace(c.Nuclei.Ref) == "" {
		return fmt.Errorf("nuclei.repo 与 nuclei.ref 不能为空")
	}
	if c.Enrich.TimeoutSeconds < 5 {
		return fmt.Errorf("enrich.timeout_seconds 必须 ≥ 5")
	}
	if c.Enrich.CacheHours < 1 {
		return fmt.Errorf("enrich.cache_hours 必须 ≥ 1")
	}
	if c.Push.MinScore < 0 || c.Push.MinScore > 100 {
		return fmt.Errorf("push.min_score 必须在 0-100 之间")
	}
	if _, ok := severityRank[strings.ToLower(c.Push.MinSeverity)]; !ok {
		return fmt.Errorf("push.min_severity 只能是 info/low/medium/high/critical 或留空")
	}
	if c.Push.MaxPerBatch < 1 {
		return fmt.Errorf("push.max_per_batch 必须 ≥ 1")
	}
	if c.Push.CooldownMinutes < 0 {
		return fmt.Errorf("push.cooldown_minutes 不能为负数")
	}
	for i := range c.Push.Channels {
		ch := &c.Push.Channels[i]
		ch.Type = strings.ToLower(strings.TrimSpace(ch.Type))
		switch ch.Type {
		case "wecom", "dingtalk", "feishu", "slack", "telegram", "webhook":
		default:
			return fmt.Errorf("推送渠道 %q 的类型非法：%s（支持 wecom/dingtalk/feishu/slack/telegram/webhook）", ch.Name, ch.Type)
		}
		if ch.Name == "" {
			ch.Name = ch.Type
		}
		if ch.Enabled && strings.TrimSpace(ch.Webhook) == "" {
			return fmt.Errorf("推送渠道 %q 已启用但未填写 webhook", ch.Name)
		}
	}
	seen := map[string]bool{}
	for i := range c.Sources.Custom {
		s := &c.Sources.Custom[i]
		s.URL = strings.TrimSpace(s.URL)
		if s.Name == "" {
			s.Name = s.URL
		}
		if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("源地址必须以 http:// 或 https:// 开头：%s", s.URL)
		}
		if seen[s.Name] {
			return fmt.Errorf("源名重复：%s", s.Name)
		}
		seen[s.Name] = true
	}
	disabled := map[string]bool{}
	for _, id := range c.Sources.Disabled {
		id = strings.TrimSpace(id)
		if id == "" || disabled[id] {
			return fmt.Errorf("sources.disabled 存在空值或重复项")
		}
		disabled[id] = true
	}
	return nil
}

// FindChannel 按名称查找推送渠道（含未启用的）。
func (p *Push) FindChannel(name string) *PushChannel {
	for i := range p.Channels {
		if p.Channels[i].Name == name {
			return &p.Channels[i]
		}
	}
	return nil
}
