// Package scheduler 是定时任务调度器：启动 10s 后先跑一轮，之后按配置间隔循环。
//
// 每轮顺序：nuclei 模板库增量同步（可关）→ 漏洞采集（含高价值推送）→ 过期清理。
// 抓取与同步各自带锁，手动触发与定时任务不会撞车。
package scheduler

import (
	"context"
	"log"
	"time"

	"socradarbot/internal/api"
	"socradarbot/internal/config"
	"socradarbot/internal/store"
)

// Start 启动调度循环（阻塞，应在独立 goroutine 中调用）。
func Start(ctx context.Context, srv *api.Server, st *store.Store) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}
	log.Printf("[scheduler] 首轮任务开始")
	for {
		cfg := config.Current()
		if cfg.Nuclei.SyncEnabled {
			r := srv.TriggerSync(ctx, false, 0)
			log.Printf("[scheduler] 模板同步 → %v/%v（%v）", r["imported"], r["changed"], r["message"])
		}
		r := srv.TriggerCollect(ctx)
		log.Printf("[scheduler] 采集完成 → %v 条入库 / %v 条抓取", r["kept"], r["fetched"])
		if keep := cfg.Collect.KeepDays; keep > 0 {
			removed, _, failed := st.Purge(keep)
			if removed > 0 || len(failed) > 0 {
				log.Printf("[scheduler] 过期清理 → 删除 %d 条，失败 %d 条", removed, len(failed))
			}
		}
		interval := time.Duration(cfg.Collect.IntervalMinutes) * time.Minute
		if interval < time.Minute {
			interval = time.Minute
		}
		log.Printf("[scheduler] 下一轮 %s 后（%s）", interval, time.Now().Add(interval).Format("15:04:05"))
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
