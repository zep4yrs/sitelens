// 生产构建的数据库驱动注册（企业化 6.x，additive）。
//
// 之前 `store.driver=sqlite|postgres` 只是适配层就绪：默认二进制没有编入任何
// database/sql 驱动，`sql.Open` 会报 unknown driver 并回退 JSON。本文件把两种
// 驱动注册进默认构建：
//   - sqlite   → modernc.org/sqlite（纯 Go，无 CGO；driver name "sqlite"）
//   - postgres → github.com/jackc/pgx/v5/stdlib（driver name "pgx"；配置仍写
//     postgres，由 server 层映射为 pgx）
//
// 不启用企业存储时只是注册、不建连接；对默认 JSON 路径零行为变化。
package store

import (
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)
