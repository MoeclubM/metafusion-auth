-- 全部服务实例升级到只读 permissions 的版本后执行。
-- 不在服务启动时删列，避免滚动发布期间旧实例读取 role 失败。
BEGIN;
ALTER TABLE auth.users DROP COLUMN IF EXISTS role;
COMMIT;
