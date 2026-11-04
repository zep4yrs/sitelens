-- =============================================================================
-- SiteLens 企业版 6.x SQL 后端 · 003 多租户数据面隔离（BL-5 / A-04）
-- =============================================================================
--
-- 目标：`scans` 增加 `tenant` 列，SQL 后端按租户过滤列表/Get/Delete，
-- 修复按 `{id}` 直接读取的跨租户 IDOR（server 侧再统一做 404 归属校验）。
--
-- 语义：
--   - 旧数据 tenant='' = legacy（认证关闭/单机部署时全局可见）；
--   - 认证开启后新记录写入令牌租户；tenant 非空的查询只返回本租户记录，
--     不会返回 legacy 空租户记录（防止历史数据被任意租户读取）；
--   - tenant 为空的查询不过滤（保持既有调用方语义）。
--
-- 方言：SQLite 与 PostgreSQL 均支持 `ALTER TABLE ... ADD COLUMN` 与
-- `CREATE INDEX IF NOT EXISTS`；ADD COLUMN 的幂等由 ApplyMigrationsDialect
-- 对"列已存在"错误容忍实现（与 002 相同）。
-- =============================================================================

ALTER TABLE scans ADD COLUMN tenant TEXT NOT NULL DEFAULT '';

-- 租户 + id 倒序分页是主查询形态（WHERE tenant=? ORDER BY id DESC LIMIT ?）。
CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans (tenant);
