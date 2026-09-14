# MetaFusion Auth

MetaFusion 统一账号与令牌服务：用户、会话、OAuth 2.0 / OIDC 与 RS256 令牌签发验签。

拆分基准见主仓库 [docs/architecture/service-split-migration.md](https://github.com/MoeclubM/MetaFusion/blob/main/docs/architecture/service-split-migration.md) 的 P3 阶段。

## 职责边界

- **拥有**：`auth.users`、`auth.sessions`、`auth.oauth_clients`、`auth.oauth_codes`、`auth.oauth_tokens`
  与 RSA 密钥（令牌签发/注销/JWKS）。
- **对外**：签发短期 RS256 访问令牌（15 分钟）+ 服务端会话轮转（refresh），并提供 JWKS 供其他服务本地验签。
- **不拥有**：实体元数据（目录服务）、文件（存储服务）、论坛与互动记录（互动服务）。
  其他服务只验签、不查本服务的库；本服务也不读它们的库。

## HTTP 契约

路径与请求/响应形状与主仓库 `catalog` 包逐字一致，切流时前端与第三方客户端都不需要改动。

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET/POST | `/api/setup` | 首次初始化 | 检查是否仍需初始化首管 / 创建首个管理员（已有用户则拒绝 `setup_complete`） |
| POST | `/api/auth/login` | 匿名 | 用户名+密码换取令牌，同时下发 HttpOnly Cookie `mf_session` |
| POST | `/api/auth/refresh` | 令牌 | 用当前 Bearer/Cookie 换发新令牌（服务端轮转会话行，无需独立 refresh_token） |
| GET | `/api/auth/me` | 令牌 | 当前账号 |
| POST | `/api/auth/logout` | 令牌 | 注销当前会话并清 Cookie |
| GET | `/api/auth/settings` | 匿名 | 实例准入能力（当前无注册/邀请/邮件验证实现，如实返回关闭） |
| PUT | `/api/auth/password`、POST `/api/auth/change-password` | 令牌 | 修改自己的密码（`old_password`/`new_password`） |
| POST | `/api/auth/logout-all` | 令牌 | 吊销该用户全部会话 |
| GET/POST | `/api/admin/users` | 管理员 | 账号列表 / 创建账号（默认角色 `editor`） |
| PUT | `/api/admin/users/{id}/role`、`/api/admin/users/{id}/password` | 管理员 | 改角色（`user/editor/admin`，不得降级最后一个管理员）/ 重置密码 |
| GET | `/api/oauth/clients` | 登录 | OAuth 客户端列表（不含密钥哈希） |
| GET | `/api/oauth/authorize` | 登录 | 授权码流程（PKCE `S256`/`plain`，redirect_uri 白名单校验） |
| POST | `/api/oauth/token` | 匿名 | 授权码换令牌，另签发 `id_token`（aud 指向客户端） |
| GET | `/api/oauth/userinfo` | 令牌 | OIDC 用户信息 |
| GET | `/api/.well-known/openid-configuration`、`/.well-known/openid-configuration` | 匿名 | OIDC 发现文档（两个入口同一份内容，地址取自 issuer） |
| GET | `/api/oidc/jwks`、`/.well-known/jwks.json` | 匿名 | 验签公钥（JWKS） |

限流：认证写入类接口按 IP 固定窗口 15 次/分钟，超限返回 429 与 `Retry-After`。

## 令牌与密钥

- 算法固定 RS256；验签只接受 RS256，拒绝 `none`/`HS*`，避免算法混淆攻击。
- 私钥来自 `AUTH_JWT_PRIVATE_KEY`（PEM 或 base64 后的 PEM，PKCS#1/PKCS#8）；
  未配置时生成进程内临时密钥并打印告警——服务仍可启动，但重启后已签发令牌失效（靠会话兜底）。
- `issuer`/`audience` 必须与主仓库完全一致（默认 `https://findverse.cc/api` / `metafusion`），
  否则存量令牌全部失效；受众按登记集合校验，OIDC `id_token` 以 `client_id` 为受众。
- 注销为单实例内存实现（jti 集合直到自然过期）：多副本部署需要共享状态，当前未支持。

## 数据与迁移

账号表位于**独立的 `auth` schema**，与目录库同实例但不同 schema，且不跨 schema 建外键
（目录侧只保留裸 UUID 引用）。因此本服务**不需要数据搬运**：

- 切流前：主仓库继续服务 `/api/auth/*` 等路由（唯一写入方），本服务只做验证性启动。
- 切流时：把网关的五个前缀指到本服务即可，数据仍在同一个 `auth` schema。
- 切流后：主仓库的相关路由随 P4 下线，`auth` schema 由本服务独占写入。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `8081` | 监听端口 |
| `DATABASE_URL` | 由 `DB_*` 拼装 | PostgreSQL 连接串（只使用 `auth` schema） |
| `AUTH_JWT_PRIVATE_KEY` | 空 | RS256 私钥（PEM / base64 PEM） |
| `AUTH_JWT_ISSUER` / `AUTH_JWT_AUDIENCE` | `https://findverse.cc/api` / `metafusion` | 必须与主仓库一致 |
| `AUTH_ACCOUNT_URL` | 空 | 未登录跳转的账号页绝对地址；为空则用站点相对路径 `/account` |

## 运行

```bash
go run cmd/server/main.go
go test ./... && go vet ./...
```

## 迁移状态

- 主仓库仍提供全部认证端点（当前线上入口），本服务为切流目标；两者共用同一 `auth` schema，
  切流前保持"单体唯一写入"，因此不存在双写冲突。
- 服务端会话（`auth.sessions`）保留为查库兜底：存量不透明令牌与"登出立即失效"依赖它，
  因此主仓库切流后仍应保留验签+兜底双模式，直到存量令牌自然过期。
