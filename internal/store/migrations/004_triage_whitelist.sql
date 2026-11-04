-- =============================================================================
-- SiteLens 企业版 6.x SQL 后端 · 004 复核/白名单（C-09）
-- =============================================================================
--
-- 目标：把 triage（误报复核）与 whitelist（白名单）从 JSON 文件落到 SQL，
-- 使 `store.driver=sqlite|postgres` 后端也具备持久化复核能力（此前 SQL
-- 后端 triage/whitelist 接口直接 503「请使用 json 存储」）。
--
-- 语义对齐 JSON 后端（internal/store/triage.go）：
--   - scan_triage：scan_id + fingerprint 唯一；verdict ∈ false_positive/
--     confirmed/ignored；重复标记覆盖 verdict/note/updated_at；
--   - whitelist：host + rule_id 唯一；host 支持精确域名与 *.example.com
--     （规范化在应用层做，SQL 只存规范化后的值）；重复添加保留首次
--     created_at、只覆盖 reason（白名单是"永久生效"语义）。
--
-- 方言：两表均为纯 CREATE TABLE IF NOT EXISTS + 主键，SQLite/PostgreSQL 通用。
--
-- 与 001 的关系：001 预留了 `triage` 表（历史遗留、从未接线使用），本迁移按
-- BL-5/C-09 任务约定新建 `scan_triage` 作为实际存储（不改 001、不做破坏性
-- 迁移）；001 的 `triage` 表保持原样（无数据），后续可另行清理。
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_triage (
    scan_id     BIGINT NOT NULL,
    fingerprint TEXT   NOT NULL,
    verdict     TEXT   NOT NULL,
    note        TEXT   NOT NULL DEFAULT '',
    updated_at  TEXT   NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_scan_triage_scan ON scan_triage (scan_id);

CREATE TABLE IF NOT EXISTS whitelist (
    host       TEXT NOT NULL,
    rule_id    TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (host, rule_id)
);
