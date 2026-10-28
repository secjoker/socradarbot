// Package llm 是 OpenAI 兼容客户端（stdlib 实现）。
//
// 配置每次调用现读 config.Current()，设置页改完立即生效。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"socradarbot/internal/config"
	"socradarbot/internal/model"
)

var userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/122.0 Safari/537.36"

type Client struct {
	Base    string
	Key     string
	Model   string
	Timeout time.Duration
	http    *http.Client
}

func New(c config.LLM) *Client {
	to := time.Duration(c.Timeout) * time.Second
	if to <= 0 {
		to = 60 * time.Second
	}
	return &Client{
		Base:    strings.TrimRight(c.Base, "/"),
		Key:     c.Key,
		Model:   c.Model,
		Timeout: to,
		http:    &http.Client{Timeout: to},
	}
}

func (c *Client) Available() bool {
	return c != nil && c.Base != "" && c.Key != "" && c.Model != ""
}

// ChatJSON 发起一次强制 JSON 输出的对话，并把结果解析到 out。
func (c *Client) ChatJSON(ctx context.Context, system, user string, out any) error {
	if !c.Available() {
		return fmt.Errorf("LLM 未配置（缺少 base/key/model）")
	}
	payload := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]string{"type": "json_object"},
		"temperature":     0.2,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("LLM 返回 HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var envelope struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("LLM 响应解析失败: %w", err)
	}
	if len(envelope.Choices) == 0 {
		return fmt.Errorf("LLM 未返回内容")
	}
	content := stripFence(envelope.Choices[0].Message.Content)
	if err := json.Unmarshal([]byte(content), out); err != nil {
		return fmt.Errorf("LLM 返回非 JSON: %w（原文 %s）", err, truncate(content, 160))
	}
	return nil
}

func stripFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func runes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// Ping 连通性自检：让模型回一个固定 JSON 探针。
func (c *Client) Ping(ctx context.Context) (string, error) {
	var out struct {
		Reply string `json:"reply"`
	}
	if err := c.ChatJSON(ctx, "只返回 JSON，不要任何解释。", `{"task":"connectivity check","reply":"pong"}`, &out); err != nil {
		return "", err
	}
	if out.Reply == "" {
		return "ok", nil
	}
	return out.Reply, nil
}

// Intel 是 AI 补全后的结构化情报。
type Intel struct {
	Name        string `json:"name"`
	Summary     string `json:"summary"`
	Principle   string `json:"principle"`
	AttackScope string `json:"attack_scope"`
	POC         string `json:"poc"`
	POCLang     string `json:"poc_lang"`
}

const generateSys = "你是资深安全研究员，为漏洞播报系统生成结构化情报，内容仅用于防御研究与" +
	"授权测试教育目的。根据文章信息只返回 JSON：" +
	`{"name":"中文漏洞名称","summary":"一句话简介","principle":"漏洞原理，2-4句",` +
	`"attack_scope":"攻击范围/影响面（产品+版本）","poc":"python 概念验证代码，带注释","poc_lang":"python"}。` +
	"若用户消息里给了 article_poc，则 poc 字段必须原样使用它，不要改写。" +
	"若信息不足以确定影响版本，attack_scope 写'以官方公告为准'，不要编造。"

// GenerateIntel 基于文章内容生成结构化情报。
func (c *Client) GenerateIntel(ctx context.Context, it model.Item, content, poc string) (*Intel, error) {
	brief := map[string]any{
		"title": it.Title, "summary": it.Summary,
		"content": runes(content, 2500), "refs": it.Refs,
	}
	if poc != "" {
		brief["article_poc"] = runes(poc, 3000)
	}
	ub, _ := json.Marshal(brief)
	var out Intel
	if err := c.ChatJSON(ctx, generateSys, string(ub), &out); err != nil {
		return nil, err
	}
	if out.Name == "" || out.POC == "" {
		return nil, fmt.Errorf("LLM 返回字段不完整")
	}
	if out.POCLang == "" {
		out.POCLang = "python"
	}
	return &out, nil
}

const pocSys = "你是资深安全研究员，为漏洞播报系统写 Python 概念验证代码，仅用于防御研究与" +
	"授权测试教育目的。根据漏洞信息与 nuclei 模板只返回 JSON：" +
	`{"poc":"python 代码，带注释"}。要求：TARGET 留成占位符；请求构造要与模板的 payload 逻辑一致；` +
	"不得写入破坏性 payload，只做无害探测；代码要能直接运行。"

// GenPOC 为已收录漏洞补充/重写 Python PoC。
func (c *Client) GenPOC(ctx context.Context, v *model.Vuln) (string, error) {
	brief := map[string]any{
		"name": v.Name, "summary": v.Summary, "principle": v.Principle,
		"cvss": v.CVSS, "refs": v.Refs, "nuclei_template": runes(v.NucleiYAML, 4000),
	}
	ub, _ := json.Marshal(brief)
	var out struct {
		POC string `json:"poc"`
	}
	if err := c.ChatJSON(ctx, pocSys, string(ub), &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.POC) == "" {
		return "", fmt.Errorf("AI 未返回 PoC 代码")
	}
	return out.POC, nil
}

const translateSys = "你是漏洞情报翻译，负责把英文漏洞信息译成简体中文，用于内部漏洞播报。只返回 JSON：" +
	`{"name":"中文漏洞名称","summary":"中文简介","principle":"中文漏洞原理"}。` +
	"规则：CVE 编号、组件名、函数名、协议名、文件路径保留英文原文，其余译为简体中文；" +
	"不要添加原文没有的判断、影响面或利用结论。"

// Translate 翻译 name/summary/principle，任一字段为空则视为失败（不写半截译文）。
func (c *Client) Translate(ctx context.Context, v *model.Vuln) (Intel, error) {
	src := map[string]string{
		"name": runes(v.Name, 900), "summary": runes(v.Summary, 900), "principle": runes(v.Principle, 900),
	}
	ub, _ := json.Marshal(src)
	var out Intel
	if err := c.ChatJSON(ctx, translateSys, string(ub), &out); err != nil {
		return Intel{}, err
	}
	if out.Name == "" || out.Summary == "" || out.Principle == "" {
		return Intel{}, fmt.Errorf("AI 未返回完整译文")
	}
	return out, nil
}

const nucleiSys = "你是 nuclei 模板编写助手。把给定漏洞情报转成 nuclei v3 模板的结构化字段，" +
	"只返回 JSON，不要输出 YAML，不要写解释。字段：" +
	`{"id":"英文小写连字符id","name":"中文漏洞名","severity":"info|low|medium|high|critical",` +
	`"tags":["tag1"],"description":"中文描述","references":["https://..."],` +
	`"http":[{"method":"GET","path":["{{BaseURL}}/xxx"],"headers":{},"body":"",` +
	`"matchers":[{"type":"word|status|regex|dsl","part":"body|header|all","words":["..."],"condition":"and|or"}],` +
	`"attack":"none"}]}。` +
	"规则：1) path 必须以 {{BaseURL}} 开头，用真实接口路径；2) 优先只读方法（GET/HEAD），" +
	"POST 仅当漏洞本身无副作用时用；3) matchers 必须可判定漏洞是否命中，不要写恒真条件；" +
	"4) 没有把握的字段就给空，不要编造。内容仅用于防御研究与授权测试。"

// NucleiSpec 让模型抽取 nuclei 结构化字段；返回原始 map 交由 nuclei 包规整与校验。
func (c *Client) NucleiSpec(ctx context.Context, v *model.Vuln, poc string) (map[string]any, error) {
	brief := map[string]any{
		"name": v.Name, "summary": v.Summary, "principle": v.Principle,
		"attack_scope": v.AttackScope, "cvss": v.CVSS, "refs": v.Refs, "poc": runes(poc, 3000),
	}
	ub, _ := json.Marshal(brief)
	var out map[string]any
	if err := c.ChatJSON(ctx, nucleiSys, string(ub), &out); err != nil {
		return nil, err
	}
	return out, nil
}
