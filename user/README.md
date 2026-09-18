# 账号自助应用（auth-user，骨架）

分支 `codex/auth-user-shell`。独立 Next 应用，无 basePath，由网关精确路径 `= /login`、`= /setup` 聚合（接线见主仓库契约 `docs-local/reports/frontend-split-contract-v0.1.md` §4，本轮尚未接线）。

本轮范围：应用外壳（layout 按 cookie 读语言 + `force-dynamic` + `noindex`）、探活 `GET /api/health`、i18n 三件套与四语最小字典（与 `admin/` 同规格，`bun run i18n:check` 断言）。

下轮：搬运 `login`/`setup` 页面与会话库（`lib/api.ts`、`endpoints.ts`、`session.tsx`，Cookie 唯一凭据口径），再做主仓库网关 + 编排接线。
