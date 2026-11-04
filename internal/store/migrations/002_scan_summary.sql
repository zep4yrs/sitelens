-- =============================================================================
-- SiteLens 企业版 6.x SQL 后端 · 002 列表汇总冗余列（C-08，Wave-2）
-- =============================================================================
--
-- 目标：列表/统计不再解码 result_json（原来每次 /api/history 与 /api/stats
-- 都要 JSON 解码大量行；带 tech 过滤时甚至全表拉进 Go）。
-- 方案：把列表页需要的派生值冗余成列，SaveScan / MigrateFromJSON 写入，
-- 列表走纯 SQL 投影；tech 过滤走 tech_names 子串（LIKE，参数化 + 通配符转义）。
--
-- 方言：SQLite 与 PostgreSQL 均支持 `ALTER TABLE ... ADD COLUMN` 与本文件的
-- 类型（INTEGER/TEXT + 常量 DEFAULT）。两方言都**没有** ADD COLUMN IF NOT
-- EXISTS —— 幂等由 store.ApplyMigrationsDialect 对"列已存在"错误容忍实现。
--
-- 旧库升级：已有行这三列取默认值（0/空），列表对旧行展示 0；
-- 需要准确计数时调用一次 `store.BackfillScanSummary(db, dialect, 0)` 回填
-- （幂等，只处理 tech_names 仍为空的旧行；Get 单条不受影响，始终可从
-- result_json 补齐）。
-- =============================================================================

ALTER TABLE scans ADD COLUMN tech_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN vuln_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN tech_names TEXT NOT NULL DEFAULT '';

-- 列表按 id 倒序分页（已由主键覆盖）；tech_names 是子串匹配（LIKE '%x%'），
-- 普通 B-tree 索引对前导通配符号无效，因此不建索引，避免误导。
