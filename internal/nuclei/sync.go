// nuclei_sync：nuclei-templates git 增量同步。
//
// 用 git diff 而不是 GitHub API：模板库有 1.3w+ 文件，API 会限流且只能抽样，
// git 增量才能准确回答"今天更新了什么"。同步点用 tag + state 双保险。
package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"socradarbot/internal/config"
)

// SyncResult 是一次同步的结果。
type SyncResult struct {
	Changed int      `json:"changed"`
	From    string   `json:"from_commit"`
	To      string   `json:"to_commit"`
	Files   []string `json:"files"`
	Message string   `json:"message,omitempty"`
}

type syncState struct {
	LastCommit   string `json:"last_commit"`
	LastSync     string `json:"last_sync"`
	LastImported int    `json:"last_imported"`
}

const syncTag = "socradarbot-sync"

func findGit() string {
	if p, err := exec.LookPath("git"); err == nil {
		return p
	}
	for _, p := range []string{
		`C:\Program Files\Git\cmd\git.exe`,
		`C:\Program Files\Git\bin\git.exe`,
		`C:\Program Files (x86)\Git\cmd\git.exe`,
		`/usr/bin/git`,
		`/usr/local/bin/git`,
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func gitRun(ctx context.Context, dir string, args ...string) (string, error) {
	exe := findGit()
	if exe == "" {
		return "", fmt.Errorf("未找到 git，可执行文件未加入 PATH")
	}
	cmd := exec.CommandContext(ctx, exe, append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s 失败: %s", strings.Join(args[:min(2, len(args))], " "), truncate(string(out), 300))
	}
	return string(out), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func repoURL(repo string) string {
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "git@") {
		return repo
	}
	return "https://github.com/" + strings.TrimSuffix(repo, ".git") + ".git"
}

func ensureRepo(ctx context.Context, p config.Paths, cfg config.Nuclei) error {
	repo := p.RepoDir
	if st, err := os.Stat(filepath.Join(repo, ".git")); err == nil && st.IsDir() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(repo), 0o755); err != nil {
		return err
	}
	exe := findGit()
	if exe == "" {
		return fmt.Errorf("未找到 git，无法克隆 nuclei-templates")
	}
	_ = os.RemoveAll(repo)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, exe, "clone", "--depth", "1", "--branch", cfg.Ref, repoURL(cfg.Repo), repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(repo)
		return fmt.Errorf("克隆失败: %s", truncate(string(out), 300))
	}
	return nil
}

func readState(p config.Paths) syncState {
	var st syncState
	if b, err := os.ReadFile(p.SyncState); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func writeState(p config.Paths, st syncState) {
	if b, err := json.MarshalIndent(st, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(p.SyncState), 0o755)
		_ = os.WriteFile(p.SyncState, b, 0o644)
	}
}

// Sync 拉取增量并返回待入库模板清单（落盘由调用方完成）。
// 首次同步只建立基线、记录 commit，不把 1.3w 存量一股脑灌进库。
func Sync(ctx context.Context, p config.Paths, cfg config.Nuclei, full bool, limit int) ([]*Tpl, SyncResult, error) {
	res := SyncResult{Files: []string{}}
	if err := ensureRepo(ctx, p, cfg); err != nil {
		return nil, res, err
	}
	st := readState(p)
	old := st.LastCommit
	if old != "" {
		if tagCommit, err := gitRun(ctx, p.RepoDir, "rev-parse", syncTag+"^{commit}"); err == nil {
			old = strings.TrimSpace(tagCommit)
		}
		_, _ = gitRun(ctx, p.RepoDir, "tag", "-f", syncTag, old)
	}
	if _, err := gitRun(ctx, p.RepoDir, "fetch", "origin", cfg.Ref); err != nil {
		return nil, res, err
	}
	if _, err := gitRun(ctx, p.RepoDir, "reset", "--hard", "origin/"+cfg.Ref); err != nil {
		return nil, res, err
	}
	head, err := gitRun(ctx, p.RepoDir, "rev-parse", "HEAD")
	if err != nil {
		return nil, res, err
	}
	newCommit := strings.TrimSpace(head)
	res.From, res.To = short(old), short(newCommit)

	if !full && old == "" {
		writeState(p, syncState{LastCommit: newCommit, LastSync: time.Now().UTC().Format(time.RFC3339), LastImported: 0})
		total := len(allTemplateFiles(p.RepoDir))
		res.Message = fmt.Sprintf("首次同步完成，已建立基线（%d 个模板）。本轮不导入存量，之后只同步每日增量。", total)
		return nil, res, nil
	}
	if !full && old == newCommit {
		res.Message = fmt.Sprintf("模板库无更新（%s）", short(newCommit))
		return nil, res, nil
	}

	files := []string{}
	if full {
		files = allTemplateFiles(p.RepoDir)
	} else {
		out, err := gitRun(ctx, p.RepoDir, "diff", "--name-only", "--diff-filter=AM", old, newCommit)
		if err != nil {
			files = allTemplateFiles(p.RepoDir)
			res.Message = "上次同步点不可比，已回退全量扫描"
		} else {
			for _, ln := range strings.Split(out, "\n") {
				ln = strings.TrimSpace(ln)
				if ln != "" && isTemplatePath(ln) {
					files = append(files, ln)
				}
			}
		}
	}
	res.Changed = len(files)
	if limit > 0 && len(files) > limit {
		files = files[:limit]
		res.Message = strings.TrimSpace(res.Message + fmt.Sprintf("；本次仅处理前 %d 个（共 %d 个）", limit, res.Changed))
	}
	sort.Strings(files)

	tpls := make([]*Tpl, 0, len(files))
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(p.RepoDir, rel))
		if err != nil {
			continue
		}
		t, err := Parse(raw, rel)
		if err != nil {
			continue
		}
		t.Source = "nuclei-git:" + strings.SplitN(rel, "/", 2)[0]
		tpls = append(tpls, t)
	}
	return tpls, res, nil
}

// Commit 记录同步完成（入库之后调用）。
func Commit(p config.Paths, commit string, imported int) {
	writeState(p, syncState{LastCommit: commit, LastSync: time.Now().UTC().Format(time.RFC3339), LastImported: imported})
	if commit != "" {
		_, _ = gitRun(context.Background(), p.RepoDir, "tag", "-f", syncTag, commit)
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Status 返回同步状态，供前端展示。
func Status(p config.Paths) map[string]any {
	st := readState(p)
	cloned := false
	if s, err := os.Stat(filepath.Join(p.RepoDir, ".git")); err == nil && s.IsDir() {
		cloned = true
	}
	count := 0
	if cloned {
		count = len(allTemplateFiles(p.RepoDir))
	}
	commit := st.LastCommit
	if commit == "" {
		if c, err := gitRun(context.Background(), p.RepoDir, "rev-parse", "HEAD"); err == nil {
			commit = strings.TrimSpace(c)
		}
	}
	return map[string]any{
		"repo": p.RepoDir, "cloned": cloned,
		"last_commit": commit, "last_commit_short": short(commit),
		"last_sync": st.LastSync, "last_imported": st.LastImported,
		"local_templates": count,
	}
}

// allTemplateFiles 返回仓库中可独立运行的模板相对路径。
func allTemplateFiles(root string) []string {
	out := []string{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := strings.ToLower(info.Name())
			if base == ".git" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if isTemplatePath(rel) {
			out = append(out, rel)
		}
		return nil
	})
	return out
}

func isTemplatePath(rel string) bool {
	low := strings.ToLower(rel)
	if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
		return false
	}
	if strings.HasPrefix(low, ".") {
		return false
	}
	for _, d := range skipDirs {
		if strings.HasPrefix(low, d) || strings.Contains(low, "/"+d) {
			return false
		}
	}
	return true
}
