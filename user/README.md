# 账号自助应用（auth-user）

独立 Next.js 应用，提供登录、注册和首次初始化页面。网关将 `/login`、`/setup` 转发到本服务；Next 静态资源使用 `/auth-user-assets/_next/static/` 专属前缀，避免与主站共用 `/_next/static/` 时串到错误应用。

数据请求使用同源 `/api/*`，会话由账号服务管理。`bun run typecheck`、`bun run i18n:check` 和 `bun run build` 用于本地验证。
