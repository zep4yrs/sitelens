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

// pgConnParams PG 连接参数（全部来源：环境变量，凭证不写入代码/输出）。
type pgConnParams struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// pgParamsFromEnv 从环境变量收集连接参数（.env 由 main 的 -env 先行装入）。
func pgParamsFromEnv() pgConnParams {
	return pgConnParams{
		Host:     envOr("SLENS_DB_HOST", "127.0.0.1"),
		Port:     envOr("SLENS_DB_PORT", "5432"),
		User:     envOr("SLENS_DB_USER", "postgres"),
		Password: os.Getenv("SLENS_DB_PASSWORD"),
		DBName:   envOr("SLENS_DB_NAME", "sitelens"),
		SSLMode:  envOr("SLENS_DB_SSLMODE", "prefer"),
	}
}

// normalizeSSLMode 校验 sslmode 取值：合法值原样返回（小写），非法/空回退
// prefer。prefer = 优先 TLS、服务器不支持时回退明文，对本地无 TLS 的 PG
// 保持向后兼容；显式 disable 仍可用（由调用方告警），但不再是硬编码默认。
func normalizeSSLMode(mode string) string {
	switch m := strings.ToLower(strings.TrimSpace(mode)); m {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		return m
	default:
		return "prefer"
	}
}

// dsn 构造不含口令的 pgx DSN（BUG-030）。
//
// 口令**不进 DSN 字符串**：连接参数解析成 *pgx.ConnConfig 后直接写
// Password 字段，避免 DSN 被错误信息/调试输出带出到日志。
// sslmode 由配置（SLENS_DB_SSLMODE）决定，不再硬编码 disable。
// 含空格/引号的口令也不再需要转义（此前拼进 DSN 会直接解析失败）。
func (p pgConnParams) dsn() string {
	parts := []string{
		"host=" + p.Host,
		"port=" + p.Port,
		"user=" + p.User,
		"dbname=" + p.DBName,
		"sslmode=" + normalizeSSLMode(p.SSLMode),
	}
	return strings.Join(parts, " ")
}

// connConfig 解析 DSN 并把口令注入 ConnConfig（口令不经 DSN 字符串）。
func (p pgConnParams) connConfig() (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(p.dsn())
	if err != nil {
		// dsn 不含口令，可安全回显解析错误
		return nil, fmt.Errorf("PG 连接参数非法：%w", err)
	}
	cfg.Password = p.Password // 口令只存在于进程内存，不进 DSN
	return cfg, nil
}

// runMigratePG 执行历史迁移，返回导入/跳过条数。
func runMigratePG(cfg *config.Config, p pgConnParams) (imported, skipped int, err error) {
	ctx := context.Background()
	pcfg, err := p.connConfig()
	if err != nil {
		return 0, 0, err
	}
	conn, err := pgx.ConnectConfig(ctx, pcfg)
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
	// 连接参数只从环境变量读（.env 已由 main 的 -env 装入进程环境）。
	// 此前这里误把 cfgPath（yml 配置）当 .env 解析，属口径错误，已移除。
	p := pgParamsFromEnv()
	if normalizeSSLMode(p.SSLMode) == "disable" {
		fmt.Fprintln(os.Stderr, "警告：SLENS_DB_SSLMODE=disable，PG 连接为明文传输（仅限隔离/本机环境）")
	}

	imported, skipped, err := runMigratePG(cfg, p)
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
