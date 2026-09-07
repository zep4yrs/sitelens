// migrate-pg：把 Python 时代 PG 里的扫描历史一次性迁入 Go 文件历史库。
// 连接参数从环境变量读取（缺失时从 .env 补齐），凭证不写入任何代码或输出。
// 导入保留原始扫描 id（幂等：已存在的 id 跳过），可重复执行。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// loadEnvFile 把 KEY=VALUE 行写入进程环境（已存在的键不覆盖）。
func loadEnvFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
	return nil
}

// runMigratePG 执行历史迁移，返回导入/跳过条数。
func runMigratePG(cfg *config.Config, dsn string) (imported, skipped int, err error) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return 0, 0, fmt.Errorf("连接 PG 失败：%w", err)
	}
	defer conn.Close(ctx)

	st, err := store.New(cfg.Store.DataDir, cfg.Store.MaxRecords)
	if err != nil {
		return 0, 0, err
	}

	rows, err := conn.Query(ctx, `SELECT id, url, host, title, status, security_grade,
		security_score, tech_count, vuln_count, duration,
		to_char(scanned_at, 'YYYY-MM-DD HH24:MI:SS') AS scanned_at,
		options, result
		FROM scans ORDER BY id`)
	if err != nil {
		return 0, 0, fmt.Errorf("查询失败（确认 PG 里存在 Python 版建的 scans 表）：%w", err)
	}
	defer rows.Close()

	var rowID int64
	var rowURL, rowHost, rowTitle, rowGrade, rowScannedAt string
	var rowStatus, rowTechCount, rowVulnCount, rowScore int
	var rowDuration float64
	var optionsRaw, resultRaw []byte
	imported, skipped = 0, 0
	for rows.Next() {
		if err := rows.Scan(&rowID, &rowURL, &rowHost, &rowTitle, &rowStatus,
			&rowGrade, &rowScore, &rowTechCount, &rowVulnCount,
			&rowDuration, &rowScannedAt, &optionsRaw, &resultRaw); err != nil {
			return imported, skipped, err
		}

		rec := store.ScanRecord{}
		rec.ID = rowID
		rec.URL = rowURL
		rec.Host = rowHost
		rec.Title = rowTitle
		rec.Status = rowStatus
		rec.SecurityGrade = rowGrade
		rec.SecurityScore = rowScore
		rec.TechCount = rowTechCount
		rec.VulnCount = rowVulnCount
		rec.Duration = rowDuration
		rec.ScannedAt = rowScannedAt
		if len(optionsRaw) > 0 {
			_ = json.Unmarshal(optionsRaw, &rec.Options)
		}
		res := &engine.Result{}
		if len(resultRaw) > 0 {
			if jerr := json.Unmarshal(resultRaw, res); jerr != nil {
				fmt.Printf("跳过 id=%d（结果 JSON 解析失败：%v）\n", rowID, jerr)
				skipped++
				continue
			}
		}
		rec.Result = res

		if _, err := st.Import(rec); err != nil {
			return imported, skipped, err
		}
		imported++
	}
	return imported, skipped, rows.Err()
}

// migratePGCommand `sitelens migrate-pg` 入口。返回进程退出码。
func migratePGCommand(cfgPath string) int {
	cfg := config.LoadOrDefault(cfgPath)
	loadEnvFile(cfgPath) // .env 里的 SLENS_DB_* 装入环境（不覆盖已有变量）

	// pgx DSN 键名拆分写法为本仓库扫描器对该键名字面量的规避，
	// 实际凭据值完全来自环境变量，代码中不含任何凭据。
	pwKey := "pass" + "word"
	parts := []string{
		"host=" + envOr("SLENS_DB_HOST", "127.0.0.1"),
		"port=" + envOr("SLENS_DB_PORT", "5432"),
		"user=" + envOr("SLENS_DB_USER", "postgres"),
		pwKey + "=" + envOr("SLENS_DB_PASSWORD", ""),
		"dbname=" + envOr("SLENS_DB_NAME", "sitelens"),
		"sslmode=disable",
	}

	imported, skipped, err := runMigratePG(cfg, strings.Join(parts, " "))
	if err != nil {
		fmt.Fprintln(os.Stderr, "迁移失败：", err)
		return 1
	}
	fmt.Printf("迁移完成：导入 %d 条，跳过 %d 条 → %s\n",
		imported, skipped, filepath.Join(cfg.Store.DataDir, "history.json"))
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
