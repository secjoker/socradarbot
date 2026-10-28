// SocradarBot —— AI 赋能的漏洞情报聚合与高价值推送服务。
//
// 启动：
//
//	socradarbot -addr 127.0.0.1:8100 -web web/dist
//
// 配置：config.yaml（优先级：默认值 < config.yaml < 环境变量 SOCRADARBOT_*）。
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"socradarbot/internal/api"
	"socradarbot/internal/config"
	"socradarbot/internal/llm"
	"socradarbot/internal/pipeline"
	"socradarbot/internal/push"
	"socradarbot/internal/scheduler"
	"socradarbot/internal/store"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8100", "HTTP 监听地址（0.0.0.0:8100 可对外提供服务）")
	web := flag.String("web", "web/dist", "前端静态资源目录")
	noSched := flag.Bool("no-scheduler", false, "仅提供 API，不启动定时任务（调试/测试用）")
	showVer := flag.Bool("version", false, "打印版本号")
	flag.Parse()

	if *showVer {
		log.Printf("SocradarBot %s", api.Version)
		return
	}

	paths := config.ResolvePaths()
	for _, d := range []string{paths.DataDir, paths.VulnDir, paths.TplDir, paths.CacheDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			log.Fatalf("创建数据目录失败 %s: %v", d, err)
		}
	}

	cfg := config.Current()
	if _, err := os.Stat(paths.ConfigFile); err != nil {
		log.Printf("[init] 未找到 %s，使用内置默认值（可在 Web 设置页保存生成）", paths.ConfigFile)
	}

	st := store.New(paths)
	// 启动后预热元数据索引，避免首页首个请求承担近万次磁盘扫描
	go func() { _ = st.All() }()
	pm := push.New(st, paths.PushHistory)
	pl := pipeline.New(st, pm)
	srv := api.New(st, pl, pm, paths, *web)

	handler := srv.Handler()
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Minute, // 采集/同步接口是长任务
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !*noSched {
		go scheduler.Start(ctx, srv, st)
	}

	log.Printf("SocradarBot %s 启动", api.Version)
	log.Printf("  监听:      http://%s", *addr)
	log.Printf("  数据目录:  %s", paths.DataDir)
	log.Printf("  配置文件:  %s", paths.ConfigFile)
	webAbs, _ := filepath.Abs(*web)
	if _, err := os.Stat(filepath.Join(webAbs, "index.html")); err == nil {
		log.Printf("  前端:      %s", webAbs)
	} else {
		log.Printf("  前端:      未构建（仅 API 模式，可访问 /api/health）")
	}
	log.Printf("  LLM:       %s", map[bool]string{true: "已配置 " + cfg.LLM.Model, false: "未配置（AI 功能不可用）"}[llm.New(cfg.LLM).Available()])
	log.Printf("  富化:      KEV=%v EPSS=%v GHSA=%v NVD=%v", cfg.Enrich.KEV, cfg.Enrich.EPSS, cfg.Enrich.GitHubAdvisory, cfg.Enrich.NVD)
	log.Printf("  推送:      enabled=%v channels=%d min_score=%d", cfg.Push.Enabled, len(cfg.Push.Channels), cfg.Push.MinScore)
	log.Printf("  调度:      %v（间隔 %d 分钟）", !*noSched, cfg.Collect.IntervalMinutes)

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("收到退出信号，正在关闭 ...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	log.Printf("SocradarBot 已停止")
}
