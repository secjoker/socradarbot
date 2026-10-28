// nuclei_remote：从 GitHub 远程模板库按需抽样（预览与手动拉取用）。
//
// 两条通道取模板原文：raw.githubusercontent.com 优先，被网关拦截时回落
// api.github.com/contents（base64）。索引与单模板均带磁盘缓存，避免重复限流。
package nuclei

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const indexTTL = 6 * time.Hour

type remoteIndex struct {
	Repo  string   `json:"repo"`
	Ref   string   `json:"ref"`
	Paths []string `json:"paths"`
	At    int64    `json:"at"`
}

// FetchRemote 拉取远程模板元信息（不落库）。
func FetchRemote(ctx context.Context, client *http.Client, repo, ref string, limit int,
	severity, tag, cacheDir, token string) ([]*Tpl, error) {
	if limit <= 0 {
		limit = 10
	}
	paths, err := remotePaths(ctx, client, repo, ref, cacheDir, token)
	if err != nil {
		return nil, err
	}
	filtered := []string{}
	for _, p := range paths {
		low := strings.ToLower(p)
		if strings.HasPrefix(low, "helpers/") || strings.HasPrefix(low, "workflows/") {
			continue
		}
		if tag != "" && !strings.Contains(low, strings.ToLower(tag)) {
			continue
		}
		filtered = append(filtered, p)
	}
	var pick []string
	if tag != "" {
		pick = filtered
		if len(pick) > limit {
			pick = pick[:limit]
		}
	} else {
		pool := limit
		if severity != "" {
			pool = limit * 5
		}
		pick = spread(filtered, pool)
	}
	out := []*Tpl{}
	for _, p := range pick {
		if len(out) >= limit {
			break
		}
		raw, err := remoteTemplate(ctx, client, repo, ref, p, cacheDir, token)
		if err != nil {
			continue
		}
		t, err := Parse([]byte(raw), p)
		if err != nil {
			continue
		}
		if severity != "" && !strings.EqualFold(t.Severity, severity) {
			continue
		}
		t.Source = "nuclei-remote:" + repo
		out = append(out, t)
	}
	return out, nil
}

func remotePaths(ctx context.Context, client *http.Client, repo, ref, cacheDir, token string) ([]string, error) {
	cacheFile := filepath.Join(cacheDir, "nuclei_index.json")
	if b, err := os.ReadFile(cacheFile); err == nil {
		var idx remoteIndex
		if json.Unmarshal(b, &idx) == nil && idx.Repo == repo && idx.Ref == ref &&
			time.Since(time.Unix(idx.At, 0)) < indexTTL && len(idx.Paths) > 0 {
			return idx.Paths, nil
		}
	}
	u := fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s?recursive=1", repo, ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SocradarBot/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("模板库索引 HTTP %d（GitHub 限流时请配置 enrich.github_token）", resp.StatusCode)
	}
	var doc struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	paths := []string{}
	for _, n := range doc.Tree {
		p := n.Path
		if n.Type == "blob" && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) &&
			!strings.HasPrefix(p, ".") {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("索引中未找到模板")
	}
	b, _ := json.Marshal(remoteIndex{Repo: repo, Ref: ref, Paths: paths, At: time.Now().Unix()})
	_ = os.MkdirAll(cacheDir, 0o755)
	_ = os.WriteFile(cacheFile, b, 0o644)
	return paths, nil
}

func spread(paths []string, limit int) []string {
	buckets := map[string][]string{}
	keys := []string{}
	for _, p := range paths {
		parts := strings.SplitN(strings.ToLower(p), "/", 3)
		key := strings.Join(parts[:min(2, len(parts))], "/")
		if _, ok := buckets[key]; !ok {
			keys = append(keys, key)
		}
		buckets[key] = append(buckets[key], p)
	}
	out := []string{}
	for len(out) < limit {
		progress := false
		for _, k := range keys {
			if len(out) >= limit {
				break
			}
			if len(buckets[k]) > 0 {
				out = append(out, buckets[k][0])
				buckets[k] = buckets[k][1:]
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	return out
}

func remoteTemplate(ctx context.Context, client *http.Client, repo, ref, path, cacheDir, token string) (string, error) {
	sum := sha1.Sum([]byte(repo + "/" + ref + "/" + path))
	cacheFile := filepath.Join(cacheDir, "tpl-"+hex.EncodeToString(sum[:])[:16]+".txt")
	if b, err := os.ReadFile(cacheFile); err == nil && len(b) > 0 {
		if st, err2 := os.Stat(cacheFile); err2 == nil && time.Since(st.ModTime()) < indexTTL {
			return string(b), nil
		}
	}
	raw, err := httpGet(ctx, client, fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repo, ref, path), token)
	if err != nil {
		api := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s?ref=%s", repo, path, ref)
		body, err2 := httpGet(ctx, client, api, token)
		if err2 != nil {
			return "", err
		}
		var doc struct {
			Content string `json:"content"`
		}
		if json.Unmarshal([]byte(body), &doc) != nil || doc.Content == "" {
			return "", fmt.Errorf("模板内容获取失败")
		}
		dec, err3 := base64.StdEncoding.DecodeString(strings.ReplaceAll(doc.Content, "\n", ""))
		if err3 != nil {
			return "", err3
		}
		raw = string(dec)
	}
	_ = os.MkdirAll(cacheDir, 0o755)
	_ = os.WriteFile(cacheFile, []byte(raw), 0o644)
	return raw, nil
}

func httpGet(ctx context.Context, client *http.Client, url, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "SocradarBot/1.0")
	req.Header.Set("Accept", "*/*")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), err
}
