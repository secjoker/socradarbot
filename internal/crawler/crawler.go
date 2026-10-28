// Package crawler 提供 RSS/Atom 解析、文章正文抓取、PoC 提取与 feed 探测。
//
// 设计要点（沿用旧版并针对 Go 重写）：
//   - 每个请求都有硬超时，单源失败不影响其他源
//   - 正文抓取失败返回空字符串而非错误，流水线继续
//   - PoC 提取规则：<pre>/<code> 块长度 > 80 且包含代码特征
package crawler

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"socradarbot/internal/model"
)

// Feed 是一个文章源。
type Feed struct {
	Name string
	URL  string
}

// BuiltinFeeds 是内置文章源（与旧版一致）。
var BuiltinFeeds = []Feed{
	{"seebug", "https://paper.seebug.org/rss/"},
	{"先知", "https://xz.aliyun.com/feed"},
	{"exploit-db", "https://www.exploit-db.com/rss.xml"},
}

var (
	tagRE    = regexp.MustCompile(`<[^>]+>`)
	scriptRE = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	styleRE  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	preRE    = regexp.MustCompile(`(?is)<pre[^>]*>(.*?)</pre>`)
	codeRE   = regexp.MustCompile(`(?is)<code[^>]*>(.*?)</code>`)
	spaceRE  = regexp.MustCompile(`\s+`)
)

var pocHints = []string{"import ", "curl ", "requests.", "get /", "post /", "payload",
	"http://", "https://", "popen", "socket", "nuclei", "${jndi", "select "}

// Client 是带超时与宽松 TLS 的 HTTP 客户端（部分安全站点证书链在本地校验不过）。
func Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 采集用途，见 README 安全声明
			Proxy:           http.ProxyFromEnvironment,
		},
	}
}

func get(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0")
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml, */*")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if limit <= 0 {
		limit = 8 << 20
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

type rssDoc struct {
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
			PubDate     string `xml:"pubDate"`
		} `xml:"item"`
	} `xml:"channel"`
}

type atomDoc struct {
	Entries []struct {
		Title string `xml:"title"`
		Links []struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
		Summary   string `xml:"summary"`
		Content   string `xml:"content"`
		Updated   string `xml:"updated"`
		Published string `xml:"published"`
	} `xml:"entry"`
}

// FetchFeed 拉取并解析一个 RSS/Atom 源。
func FetchFeed(ctx context.Context, c *http.Client, name, url string, limit int) ([]model.Item, error) {
	raw, err := get(ctx, c, url, 8<<20)
	if err != nil {
		return nil, err
	}
	items := parseFeed(raw, name)
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func parseFeed(raw []byte, source string) []model.Item {
	out := []model.Item{}
	var rss rssDoc
	if xml.Unmarshal(raw, &rss) == nil {
		for _, it := range rss.Channel.Items {
			out = append(out, mkItem(source, it.Title, strings.TrimSpace(it.Link), it.Description, it.PubDate))
		}
	}
	if len(out) == 0 {
		var atom atomDoc
		if xml.Unmarshal(raw, &atom) == nil {
			for _, e := range atom.Entries {
				link := ""
				for _, l := range e.Links {
					if l.Href != "" {
						link = l.Href
						break
					}
				}
				desc := e.Summary
				if desc == "" {
					desc = e.Content
				}
				pub := e.Published
				if pub == "" {
					pub = e.Updated
				}
				out = append(out, mkItem(source, e.Title, link, desc, pub))
			}
		}
	}
	// 过滤空标题
	filtered := out[:0]
	for _, it := range out {
		if it.Title != "" {
			filtered = append(filtered, it)
		}
	}
	return filtered
}

func mkItem(source, title, link, desc, pub string) model.Item {
	title = strings.TrimSpace(tagRE.ReplaceAllString(html.UnescapeString(title), ""))
	desc = strings.TrimSpace(tagRE.ReplaceAllString(html.UnescapeString(desc), " "))
	desc = spaceRE.ReplaceAllString(desc, " ")
	if len([]rune(title)) > 120 {
		title = string([]rune(title)[:120])
	}
	if len([]rune(desc)) > 500 {
		desc = string([]rune(desc)[:500])
	}
	sum := md5.Sum([]byte(link + title))
	id := "art-" + hex.EncodeToString(sum[:])[:12]
	refs := []string{}
	if link != "" {
		refs = append(refs, link)
	}
	return model.Item{
		ID: id, Title: title, Source: source, Summary: desc,
		Link: link, Published: parseDate(pub), Refs: refs, Severity: "unknown",
	}
}

func parseDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range []string{
		time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822,
		"2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Format("2006-01-02")
		}
	}
	if len(s) >= 10 {
		if m := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`).FindString(s); m != "" {
			return m
		}
	}
	return ""
}

// FetchArticle 抓取正文并提取现成 PoC。
func FetchArticle(ctx context.Context, c *http.Client, url string) (string, string) {
	if url == "" {
		return "", ""
	}
	raw, err := get(ctx, c, url, 4<<20)
	if err != nil {
		return "", ""
	}
	page := string(raw)
	blocks := []string{}
	for _, re := range []*regexp.Regexp{preRE, codeRE} {
		for _, m := range re.FindAllStringSubmatch(page, -1) {
			text := strings.TrimSpace(tagRE.ReplaceAllString(html.UnescapeString(m[1]), ""))
			if len([]rune(text)) > 80 && looksLikePOC(text) {
				blocks = append(blocks, text)
			}
			if len(blocks) >= 2 {
				break
			}
		}
	}
	clean := scriptRE.ReplaceAllString(page, " ")
	clean = styleRE.ReplaceAllString(clean, " ")
	clean = tagRE.ReplaceAllString(html.UnescapeString(clean), " ")
	clean = spaceRE.ReplaceAllString(clean, " ")
	if len([]rune(clean)) > 4000 {
		clean = string([]rune(clean)[:4000])
	}
	return clean, strings.Join(blocks, "\n\n")
}

func looksLikePOC(s string) bool {
	low := strings.ToLower(s)
	for _, h := range pocHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// ProbeResult 是 feed 探测结果。
type ProbeResult struct {
	URL     string   `json:"url"`
	Entries int      `json:"entries"`
	Titles  []string `json:"titles"`
}

var feedSuffixes = []string{"/feed", "/rss", "/rss.xml", "/atom.xml", "/feed.xml",
	"/index.xml", "/feeds/posts/default", "/rss/index.xml"}

// FeedSuffixes 返回探测时尝试的常见 feed 路径（供接口回显）。
func FeedSuffixes() []string {
	out := make([]string, len(feedSuffixes))
	copy(out, feedSuffixes)
	return out
}

// Probe 按常见路径逐个探测 feed，返回能解析出条目的地址。
func Probe(ctx context.Context, c *http.Client, rawURL string) []ProbeResult {
	base := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	candidates := append([]string{base}, func() []string {
		out := make([]string, 0, len(feedSuffixes))
		for _, s := range feedSuffixes {
			out = append(out, base+s)
		}
		return out
	}()...)

	results := []ProbeResult{}
	for _, cand := range candidates {
		raw, err := get(ctx, c, cand, 4<<20)
		if err != nil {
			continue
		}
		n, titles := countEntries(raw)
		if n > 0 {
			results = append(results, ProbeResult{URL: cand, Entries: n, Titles: titles})
		}
	}
	return results
}

func countEntries(raw []byte) (int, []string) {
	var rss rssDoc
	if xml.Unmarshal(raw, &rss) == nil && len(rss.Channel.Items) > 0 {
		titles := []string{}
		for i, it := range rss.Channel.Items {
			if i >= 8 {
				break
			}
			titles = append(titles, truncate(spaceRE.ReplaceAllString(strings.TrimSpace(it.Title), " "), 80))
		}
		return len(rss.Channel.Items), titles
	}
	var atom atomDoc
	if xml.Unmarshal(raw, &atom) == nil && len(atom.Entries) > 0 {
		titles := []string{}
		for i, e := range atom.Entries {
			if i >= 8 {
				break
			}
			titles = append(titles, truncate(spaceRE.ReplaceAllString(strings.TrimSpace(e.Title), " "), 80))
		}
		return len(atom.Entries), titles
	}
	return 0, nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
