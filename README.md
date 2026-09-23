# MetaFusion Auth

MetaFusion 统一账号与令牌服务：用户、会话、OAuth 2.0 / OIDC 与 RS256 令牌签发验签。

拆分基准见主仓库 [docs/architecture/service-split-migration.md](https://github.com/MoeclubM/MetaFusion/blob/main/docs/architecture/service-split-migration.md) 的 P3 阶段。

## 职责边界

- **拥有**：`auth.users`、`auth.sessions`、`auth.personal_access_tokens`、`auth.oauth_clients`、
  `auth.oauth_codes`、`auth.oauth_tokens`、`auth.oauth_audit` 与 RSA 密钥（令牌签发/注销/JWKS）。
- **对外**：签发短期 RS256 访问令牌（15 分钟）+ 服务端会话轮转（refresh），并提供 JWKS 供其他服务本地验签。
- **不拥有**：实体元数据（目录服务）、文件（存储服务）、论坛与互动记录（互动服务）。
  其他服务只验签、不查本服务的库；本服务也不读它们的库。

## HTTP 契约

账号服务是这些路径的唯一实现；路径与请求/响应形状保持切流前不变，前端与第三方客户端不需要改动（主仓库的账号实现与路由已删除，见文末「迁移状态」）。

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET/POST | `/api/setup` | 首次初始化 | 检查是否仍需初始化首管 / 创建首个管理员（已有用户则拒绝 `setup_complete`） |
| POST | `/api/auth/login` | 匿名 | 用户名+密码换取令牌，同时下发 HttpOnly Cookie `mf_session` |
| POST | `/api/auth/register` | 匿名 | 自助注册：受实例设置约束（开放注册 + 可选邀请码，见 `/api/auth/settings`）；成功即签发令牌并下发 Cookie |
| POST | `/api/auth/refresh` | 令牌 | 用当前 Bearer/Cookie 换发新令牌（服务端轮转会话行，无需独立 refresh_token） |
| GET | `/api/auth/me` | 令牌 | 当前账号 |
| POST | `/api/auth/logout` | 令牌 | 注销当前会话并清 Cookie |
| GET | `/api/auth/settings` | 匿名 | 实例准入能力：注册/邀请等设置的**持久化结果**（不是代码常量）；`require_email_verification` 恒为 false（邮件通道未接入） |
| GET | `/api/users/:id` | 匿名 | 公开账号资料（前端用户主页）：`user` 给 `id`/`username`/`role`（被 ban 时带 `banned:true`），`stats.invited_count` 为该用户邀请成功的人数。`email` **只在请求者就是本人时**出现；非 uuid 或不存在的 id 一律 404 `not_found` |
| GET/POST | `/api/auth/invite` | 令牌 | 个人邀请页：我的邀请码台账与由我邀请进来的人（`items`/`members`/`can_create`）/ 新建邀请码（`note`/`max_uses`/`expires_in_days`） |
| PUT | `/api/auth/password` | 令牌 | 修改自己的密码（`old_password`/`new_password`） |
| POST | `/api/auth/logout-all` | 令牌 | 吊销该用户全部会话 |
| GET | `/api/auth/oauth-grants` | 令牌 | 我授权过的第三方应用（`items`：`client_id`/`name`/`scopes`/`active`/`last_authorized_at`/`expires_at`） |
| DELETE | `/api/auth/oauth-grants/{client_id}` | 令牌 | 撤回**我自己**对该应用的授权（删未过期令牌与未兑换授权码，回 `{"ok":true,"revoked":N}`；只作用于本人） |
| GET/POST | `/api/auth/tokens` | 令牌 | 个人访问令牌（PAT）：列出**本人**的令牌 / 创建（`201` 回明文 + 元数据，明文只此一次），见「个人访问令牌」 |
| DELETE | `/api/auth/tokens/{id}` | 令牌 | 吊销本人的 PAT（写 `revoked_at`，不删行；幂等） |
| POST | `/api/auth/tokens/introspect` | **无** | 内省：下游服务凭明文换 `{valid,user_id,username,role,permissions[],expires_at}`；无效/吊销/过期/封禁统一 `401 invalid_token` |
| GET/POST | `/api/admin/users` | 管理员 | 账号列表（含 `banned`）/ 创建账号（默认角色 `editor`） |
| PUT | `/api/admin/users/{id}/role`、`/api/admin/users/{id}/password` | 管理员 | 改角色（`user/editor/admin`，不得降级最后一个管理员）/ 重置密码 |
| PUT | `/api/admin/users/{id}/groups` | `auth.users.manage` | 设置该用户的权限组（`groups` 整组替换） |
| PUT | `/api/admin/users/{id}/ban` | `auth.users.manage` | 封禁 / 解封（body `{"banned":true|false}`，缺字段 400 `invalid_payload`）；封禁同时删除该用户的会话、第三方令牌与未兑换授权码，且验签立即拒绝（见「账号封禁」） |
| GET/PUT | `/api/admin/settings` | `auth.settings.manage` | 实例设置的读取与局部更新（管理台用）；只认接受表里的键，表外的键一律 `400 invalid_setting: <key>` |
| GET/POST | `/api/admin/invites` | `auth.invites.manage` | 邀请码台账（`items`）/ 新建 |
| POST | `/api/admin/invites/{code}/revoke` | `auth.invites.manage` | 作废邀请码 |
| GET/POST | `/api/admin/groups` | `auth.groups.manage` | 权限组列表（`items`）/ 新建 |
| PUT/DELETE | `/api/admin/groups/{code}` | `auth.groups.manage` | 更新 / 删除权限组 |
| GET | `/api/admin/permissions` | `auth.groups.manage` | 权限码清单（`items`），供管理台按域展示可授予的码 |
| GET | `/api/oauth/authorize` | 登录 | 授权码流程：校验 client 与 redirect_uri 白名单、校验并收敛 scope；已登录但未表态时渲染同意页，`consent=allow` 才发码，`consent=deny` 带 `error=access_denied` 回跳；`trusted` 客户端跳过同意页。PKCE 支持 `S256`/`plain` |
| POST | `/api/oauth/token` | 匿名 | 授权码换令牌（表单或 JSON），响应含收敛后的 `scope`、真实 `expires_in` 与 `id_token`（aud 指向客户端） |
| GET | `/api/oauth/userinfo` | 令牌 | OIDC 用户信息，**按令牌 scope 裁剪**：`sub`/`id` 恒回，`profile` → `username`/`role`，`email` → `email`；以 `auth.oauth_tokens` 的存活行为准，令牌被吊销/客户端停用后立即 401。实例自身的会话令牌（scope 为空串，排障用）保持全字段 |
| GET/POST | `/api/admin/oauth/clients` | `auth.oauth.manage` | 管理面客户端列表（`items`）/ 创建（返回一次性明文密钥，库里只存 bcrypt 哈希） |
| PUT/DELETE | `/api/admin/oauth/clients/{id}` | `auth.oauth.manage` | 更新（改名 / 回调白名单 / scope 白名单 / trusted / 停用）/ 删除（第一方种子客户端不可删） |
| POST | `/api/admin/oauth/clients/{id}/rotate-secret` | `auth.oauth.manage` | 轮换密钥：明文只返回一次，老密钥立即失效 |
| POST | `/api/admin/oauth/clients/{id}/revoke-tokens`、`/api/admin/users/{id}/revoke-oauth-tokens` | `auth.oauth.manage` | 吊销未过期令牌（连未兑换的授权码一起作废），按客户端或按用户 |
| GET | `/api/admin/oauth/audits` | `auth.oauth.manage` | 授权审计（同意/拒绝与客户端管理动作，可按 `client_id` 过滤） |
| GET | `/api/admin/audit-logs` | `auth.audit.read` | **跨服务审计留痕的唯一读取面**（catalog / auth / community / storage 的写操作都写 `audit.audit_log`）：过滤 `service`/`action`/`actor_user_id`/`actor`（用户名前缀）/`target_type`/`target_id`/`result`/`from`/`to`/`request_id`，分页 `page`/`per_page`（默认 1/50，上限 200），排序 `occurred_at DESC, id DESC`；非法参数 400 `invalid_query:<参数>`。字段与脱敏规则见 [审计留痕契约](https://github.com/MoeclubM/MetaFusion/blob/main/docs/architecture/audit-log.md) |
| GET | `/api/.well-known/openid-configuration`、`/.well-known/openid-configuration` | 匿名 | OIDC 发现文档（两个入口同一份内容，地址取自 issuer） |
| GET | `/api/oidc/jwks`、`/.well-known/jwks.json` | 匿名 | 验签公钥（JWKS） |
| GET | `/api/developer/overview` | 登录 | 开发者中心的接入配置：issuer、端点地址（authorize / token / userinfo / jwks / discovery）、`grant_types`、scope 四语说明；**不含任何客户端清单** |
| GET | `/api/developer/apps` | 登录 | 我的应用：**只含归属当前账号的应用**（管理员也不例外），带归属、是否已核验、是否已配密钥 |
| POST | `/api/developer/apps` | 登录 | 自助登记应用：归属调用者，返回一次性明文 `client_secret`；`trusted` / `disabled` / `verified` 由服务端置 false |
| GET/PUT/DELETE | `/api/developer/apps/{id}` | 登录 + 归属 | 详情 / 局部更新（名称、简介、主页、回调白名单、scope 白名单）/ 删除；不是自己的应用按 404 处理（管理员同样，没有例外） |
| POST | `/api/developer/apps/{id}/rotate-secret` | 登录 + 归属 | 轮换该应用密钥，明文只返回一次，旧密钥立即失效 |

限流：认证写入类接口按 IP 固定窗口限流，**速率与开关来自实例设置**（`auth_rate_limit_enabled` /
`auth_rate_limit_per_minute`，默认 `true` / 15 次每分钟，即接线前的强制值）。`enabled=false` 时不计数直接放行；
改设置立即生效（策略有 5 秒短缓存，写设置时作废）。超限返回 429 `rate_limited` 与 `Retry-After`（秒）。
PAT 内省是另一套独立限流（IP 与令牌双维度，**不读**上面两个设置），见「个人访问令牌」。

实例设置（`GET/PUT /api/admin/settings`）当前只认 6 个键：`registration_enabled`、`invite_required`、
`require_email_verification`、`auth_rate_limit_enabled`、`auth_rate_limit_per_minute`、
`registration_default_groups`。表外的键一律 `400 invalid_setting: <key>`，读取面也只回传这张表里的键；
写接口的**未知字段同样拒绝**（`400 invalid_payload`，见 `handler.body` 的 `DisallowUnknownFields`），
避免"载荷里的字段被静默吞掉"：`/api/setup`、`/api/auth/*`、`/api/admin/*`、`/api/developer/*` 的 JSON
写接口统一走它。唯一的例外是 `/api/oauth/token`：按 OAuth 2.0 规范先读表单参数、再回落 `c.BindJSON`，
规范之外的附加参数按规范保留。
**站点名不是实例设置**：它由前端构建期文案决定（主站与文档站的品牌文案随发布一起改），账号服务既不保存
也不下发；历史上被写入过的 `site_name` 行留在库里，但不进任何读取面（`settingsWith` 只回传已知键）。

## 开发者中心（应用自助登记）

`/api/developer/*` 是独立开发者中心的接口：**任何登录账号**都能自助登记自己的应用（应用归属该账号），
拿到 `client_id` / `client_secret` 后走标准授权码流程接入。`GET /api/developer/overview` 只回接入配置
（issuer、端点地址、grant 类型与 scope 四语说明），**不含任何客户端清单**：系统应用与别人登记的应用
都不在任何登录账号的可见面里。管理台（`/api/admin/oauth/*`，受 `auth.oauth.manage`）仍是平台管理员的
治理面：核验第三方应用、提升自有平台、按客户端或按用户吊销令牌、查审计。

- **只看自己的**：列表与读 / 改 / 轮换 / 删四条路径共用同一判定——**归属 = 当前账号**，不分角色。
  管理员在这里也只看得到自己登记的应用：全量视图与治理能力都在管理面（`/api/admin/oauth/clients*`），
  自助面不再提供第二份；归属为空的系统应用与别人登记的应用都不会出现在列表里，也读不到。
- **归属隔离**：`auth.oauth_clients.owner_user_id` 记录创建者；不是自己的应用一律返回 `client_not_found`（404），
  不把「这个 client_id 已被占用」这个事实透给调用方。管理面走的是另一条判定（权限码 + 审计），不从这里借道。
- **自有平台自动核验**：种子客户端（catalog / forum / resources）`trusted=true`、`verified=true`，
  免同意且展示为已核验。开发者中心**写不了** `trusted` / `disabled` / `verified`——传了会被明确拒绝
  （`invalid_field: app_managed_fields`），而不是静默忽略：免同意是平台自己的身份，不能由请求方声明。
- **未核验提示**：第三方应用在同意页上多一条「该应用尚未通过核验」的提示；管理员核验后
  （`PUT /api/admin/oauth/clients/{id}` 带 `verified=true`）提示消失。自有平台连同意页都不出现。
- **配额**：每个账号最多 20 个应用（`store.MaxDeveloperAppsPerUser`），超限报 `app_quota_exceeded`，
  管理员同一口径（开发者面对所有角色只有一条规则；管理面的批量登记本来就不走这个上限）。
- **密钥**：明文 secret 只在创建与轮换的响应里出现一次，库里只有 bcrypt 哈希，之后无处可取。

## 账号封禁

`auth.users.banned`（默认 `false`）由 `PUT /api/admin/users/{id}/ban` 维护，需 `auth.users.manage`。
封禁不是"打个标记"，而是**立即失效**：

- 登录：口令正确但账号被封禁 → `403` + `{"error":"account_banned"}`（与 `invalid_credentials` 区分，
  客户端才能提示"账号已停用、联系站务"而不是让人反复猜密码）；
- 续期：`POST /api/auth/refresh` 同样回 `account_banned`；
- 验签：`Authenticate` 在无状态 JWT 验签通过后仍查一次封禁状态，因此手里那张 ≤15 分钟的令牌立刻作废
  （只删库行拦不住无状态令牌）；查询结果按账号缓存 5 秒，封禁动作立即改写缓存；
- 连带清理：删除该用户的服务端会话、第三方令牌与未兑换的授权码。

护栏两条（与"不得降级最后一个管理员"同口径）：**不能封自己**（`cannot_ban_self`），
**不能封掉最后一个还能登录的管理员**（`cannot_ban_sole_admin`，已封禁的管理员不计入剩余数量）。
解封只需再调一次 `{"banned":false}`。

## 个人访问令牌（PAT）

外部应用、Agent 与 CI 的长期机器接入凭证。明文格式：`mfp_` + 32 字节随机数的 base62 定长表示
（共 47 字符，`^mfp_[0-9A-Za-z]{43}$`）；库里只存哈希与展示前缀（明文前 12 字符）。

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/auth/tokens` | 令牌 | 只列**本人**的令牌（`items`：`id`/`name`/`token_prefix`/`scopes`/`expires_at`/`last_used_at`/`created_at`/`revoked_at`/`active`） |
| POST | `/api/auth/tokens` | 令牌 | 创建（`name` / `scopes[]` **至少一个权限码** / `expires_in_days?`，0 或缺省 = 永不过期）→ `201 {token, item}`，**明文只此一次** |
| DELETE | `/api/auth/tokens/{id}` | 令牌 | 吊销本人的令牌（写 `revoked_at`，不删行；幂等，已吊销再删仍 200；不是本人的一律 404 `token_not_found`） |
| POST | `/api/auth/tokens/introspect` | 无 | 内省（下游服务调用）：body `{"token":"mfp_..."}` → `{valid,user_id,username,role,permissions[],scopes[],token_prefix,expires_at}` |

- **明文只出现一次**：`auth.personal_access_tokens.token_hash` 是 SHA-256 十六进制（唯一索引）+
  `token_prefix`（明文前 12 字符）。为什么不是 bcrypt：PAT 明文是 32 字节高熵随机串，不存在被猜解的
  口令空间，而校验必须能按哈希**直查**（bcrypt 每行自带盐，无法索引查询）。
- **scopes 是权限码**（`catalog.entity.edit`、`storage.asset.upload` …），且必须是**账号自己持有**的码：
  超出本人权限的创建直接拒绝（`400 scope_not_granted: <code>`），不静默取交集——否则用户会拿到
  一张比他要的更弱的令牌却毫无察觉。
- **空 scopes 被拒绝**（`400 invalid_scope: empty`，缺失该字段、传 `[]` 或全空白都算）：创建时必须
  至少给一个权限码。理由不是洁癖：**没有权限的令牌在既有判定下会变成全权令牌**——`Can` 在
  `permissions` 为空时按 `role` 兜底到 admin/editor，而这条兜底在下游照抄 `Can` 的地方一定会生效，
  于是"什么都做不了"的令牌对管理员账号等于全权 PAT。与其留一个静默扩权的语义，不如在创建时挡住。
- **有效权限 = 账号现时权限 ∩ 该 PAT 的 scopes**，内省每次回表重算（账号权限被收回后，
  同一张令牌的下一次内省立刻就窄了）。下游仍然只用一份权限判定，不需要为 PAT 写第二套逻辑。
- **下游的判定口径（第二道防线，必须照做）**：PAT principal 一律用
  `HasPermission(principal.Permissions, code)` 语义判定。`permissions` 非空时它与 `Can(user, code)`
  完全等价，但**为空时只有它安全**：`Can` 会按 `role` 兜底到 admin/editor。交集为空是真会发生的
  （创建后账号丢了那个权限码），此时令牌应当什么都做不了，而不是变成全权令牌。
- **内省不缓存、下游缓存 60 秒**：本服务每次内省都查库（自身即时），下游按 `token_hash` 缓存 60 秒，
  因此**端到端吊销最长 60 秒生效**——不要对用户声称立即失效。
- **限流**：内省按来源 IP（600 次/分）与令牌哈希（60 次/分）双维度固定窗口；超限 `429 rate_limited`
  与 `Retry-After: 60`。两个维度都**不读实例设置**：内省是读语义，`auth_rate_limit_*` 是认证写入类
  端点的开关，为压注册洪水关掉写入限流不该连带松开下游的鉴权限流。
- **错误不区分原因**：不存在 / 已吊销 / 已过期 / 账号被封禁一律 `401 {"error":"invalid_token"}`
  （区分原因等于告诉探测者"这个令牌曾经有效"）；只有"读不动库"是 `503 introspection_unavailable`，
  下游必须把非 200 一律当作"不认这个令牌"（fail-closed）。
- **PAT 不是登录态**：三条自助端点只认访问令牌或 `mf_session` Cookie，`Authorization: Bearer mfp_...`
  按匿名处理（401）；这些请求**不产出 `mf_session`**（内省也不）。因此"PAT 不能再创建 PAT"天然成立。
- **创建参数校验**：名称 1–64 字（`400 invalid_token_name`）；权限码格式非法 `400 invalid_scope: <code>`、
  一个码都没有 `400 invalid_scope: empty`；`expires_in_days` 取 1–3650（`400 invalid_expiry`）；
  每账号最多 10 张未吊销令牌（`400 token_limit_reached`，吊销一张即可再建）。
- **`last_used_at` 的写节奏**：同一条令牌 **60 秒内只写一次**（与下游缓存同节奏）：内省在每个
  未命中缓存的请求上都会被调用，逐次 UPDATE 会把读路径变成写路径。
- **`X-API-Key`**：字典里承诺的另一种携带方式由下游服务（目录 / 互动 / 存储）在各自的鉴权中间件里
  解析成同一张令牌再调内省，本服务不额外提供入口。
- **表与迁移**：新表 `auth.personal_access_tokens` 按本服务既有约定只**追加**在 `Init` 的 DDL 末尾
  （`CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS`，既有语句一字未改），列形状冻结在
  `internal/store/pat_schema_parity_test.go`；真库回归见 `internal/store/pat_test.go` 与
  `internal/handler/pat_postgres_test.go`。
- **管理他人令牌未做**（`/api/admin/tokens*` 本轮留空）：要做时沿用开发者面那套归属判定 +
  `auth.oauth_audit` 审计动作，别把"管理员能看全量"塞进 `/api/auth/tokens` 的归属判定里。

## OAuth 授权方（同意、scope 与吊销）

**同意页是服务端渲染 HTML**（`internal/handler/consent.go`），不跳账号前端页面：

- 授权请求本身就是浏览器顶层跳转，页面随本服务发布：第三方站点与本地开发端口行为一致，
  也不受前端站点是否可达影响；本次改动不涉及主仓库前端（不需要新增页面与路由）；
- 同意页展示 client 名称与 ID、`redirect_uri`（让用户看清会跳回哪里）以及请求的 scope 与
  将授予的权限说明；按钮是两条普通链接（在同一个授权请求上追加 `consent=allow` / `consent=deny`），
  页面无脚本无表单，响应头带 `Content-Security-Policy: default-src 'none'`、
  `X-Frame-Options: DENY`、`Cache-Control: no-store`；
- 会话 Cookie 是 `SameSite=Strict`，跨站发起的请求根本不带会话，因此不存在"别的站点替你点同意"的 CSRF 面；
- 文案四语齐备（`Accept-Language` 选语言，匹配不到回落 `en-US`，不拿中文兜底）；
  新增受支持的 scope 必须同步补四语说明，用例会拦住漏项。

`client.trusted=true` 的第一方客户端跳过同意页直接发码，第一方自动化流程不因同意页中断。

**scope**：受支持集合是 `openid`、`profile`、`email`（发现文档 `scopes_supported` 与它同源）。
请求里出现不支持的 scope 直接 `invalid_scope`（错误体点明是哪一项），其余按
**「客户端白名单 ∩ 请求」**收敛；发码与换码各收敛一次（管理员中途收紧白名单，令牌只会更少），
令牌响应里的 `scope` 就是最终授予的集合。`auth.oauth_clients.scopes` 是每个客户端自己的白名单，
存量行按列默认值补齐全部三种，行为与拆分前一致。

**令牌用途隔离（S01）**：站内会话、第三方 OAuth 访问令牌、`id_token`、PAT 是四种不同用途，
签发侧已不再签出可越权的第三方令牌：

| 令牌 | `token_use` | 身份内容 | 管理 API |
| --- | --- | --- | --- |
| 站内会话（login/register/refresh） | `session` | 完整身份：真实 `role`/`groups`/`permissions`/`email` | 按权限码正常判定 |
| 第三方 OAuth 访问令牌 | `oauth`（另带 `client_id`/`scope`） | 最小身份：`role` 恒为 `user`、组与权限恒空；`username` 仅 profile 授予时有值，`email` 仅 email 授予时有值 | **默认拒绝**（本站管理路由 403，下游同样必须拒绝） |
| `id_token`（`aud` 指向当事客户端） | `id_token` | 与 userinfo 同口径（profile→`username`/`role`，email→`email`，组与权限不带） | **默认拒绝** |
| PAT（`mfp_`，走内省） | 无（不在 JWT 体系内） | 内省返回有效权限（账号现时权限 ∩ scopes） | 按内省 `permissions` 用 `HasPermission` 判定，空即无权 |

- `audience` 仍是平台受众（JWKS/issuer 配置不动）：下游**不能只验 aud**，必须再看 `token_use`。
  未升级的下游也不会被越权——第三方令牌里的 `role`/`permissions` 已是最小值，`Can` 类按 `role` 兜底的旧判定同样放行不了。
- `/api/oauth/token` 响应的 `user` 与 `access_token`/`id_token` 自身都按授予 scope 裁剪
  （JWT 可被第三方直接解码，userinfo 的裁剪盖不住它）；`GET /api/auth/me` 对第三方令牌只返回令牌投影，不再回表补昵称/简介。
- 本站管理闸门（`requirePermission`/`store.Can`）对 `token_use=oauth`/`id_token` 统一拒绝；
  `POST /api/auth/tokens`（PAT 创建）等自助端点同样不再接受第三方令牌提权（`NormalizePATScopes` 经 `Can` 直接失败）。
- 历史令牌（无 `token_use` 字段，≤15 分钟自然过期）仍按会话语义兼容，不做强制作废。

**下游验签/内省契约更新与迁移说明**（目录 / 互动 / 存储同步实施）：

1. 验签保持 issuer/audience/JWKS 不变，新增一条规则：`token_use` 缺席或为 `session` 才进入管理授权；
   `oauth`/`id_token` 在管理路由上直接 401/403，只在纯身份读取面按 `scope` 裁剪展示（`sub` 恒可用，
   `username` 需 profile，`email` 需 email）。未知 `token_use` 取值一律拒收。
2. 授权判定统一为：会话令牌走既有权限码判定（含历史 role 兜底，仅限无 `permissions` 声明的老令牌）；
   第三方与 PAT 身份一律用 `HasPermission(permissions, code)` 语义——**显式空权限就是无权，
   不得回落到 `role=admin`**（存储 `permission.go:76` 与互动兼容路径的同类兜底同步删除）。
3. 上线顺序：账号服务与各业务服务同批部署；单服务先上不影响另一侧（新令牌对旧下游是最小权限，
   旧令牌对新下游按历史语义兼容，均 fail-closed）。第一方前端的管理操作必须走站内会话
   （login/refresh + Cookie），不得再拿 OAuth 访问令牌调用管理 API。

**令牌有效期与续期**：访问令牌是 15 分钟 RS256 JWT（`expires_in` 报真实值）；
未配置签发器时退化为不透明令牌（30 天，`expires_in` 为 2592000，兼容旧口径）。
本服务**不签发 `refresh_token`**：

- 第一方前端的续期走 `POST /api/auth/refresh` + 服务端会话轮转，本来就不需要 `refresh_token`；
- 第三方走授权码 + PKCE，令牌到期后重新走一次授权：用户仍处于登录态，
  `trusted` 客户端连同意页都不会出现；**当前访问令牌有效期 15 分钟，到期需要重新授权**；
- 再引入一套 `refresh_token` 会同时带来"两套续期"和"两套吊销语义"，与既有设计冲突。
  将来若要做，前提是把 refresh 令牌并入同一套吊销表，并明确轮转与 TTL。

**吊销**：`POST /api/admin/oauth/clients/{id}/revoke-tokens`（按客户端）与
`POST /api/admin/users/{id}/revoke-oauth-tokens`（按用户）删除 `auth.oauth_tokens` 中未过期的行并作废尚未兑换的授权码；`userinfo` 会按存活行判定，因此吊销或停用后立即 401。其它服务以 JWKS 本地验签的无状态 access token 不查询这张表，不能据 `userinfo` 的即时失效推断下游验签立即撤销；无状态令牌的撤销窗口与 jti 处理见下文限制。

- **用户自助撤回**：`GET /api/auth/oauth-grants` 列出"我给过哪些站点授权"，`DELETE /api/auth/oauth-grants/{client_id}`
  撤回其中一个。它与管理面两条吊销端点的区别是**归属**：路径里没有别人的 user id，只按当前登录身份删本人
  （`user_id + client_id`）的令牌与授权码，因此普通成员也能用；管理面端点保留（治理用，按客户端或按用户）。
  撤回是幂等的：本来就没有有效令牌时回 `revoked:0`，列表里该应用转为 `active:false`（同意审计仍在，用户能看到"曾授权过"）。
- **限制（如实说明）**：下游服务持有缓存 JWKS、只做本地验签时，账号服务进程内的 jti 注销集合不会同步到这些下游；即使此处 `userinfo` 已立即返回 401，下游仍可能在令牌剩余有效期（最多 15 分钟）内接受其签名。要即时统一撤销，需另有下游 introspection / 共享撤销状态机制；当前不得把 `userinfo` 的结果等同于所有服务立即拒绝。
- 按用户吊销只动第三方令牌，不删该用户自己的服务端会话（那是 `/api/auth/logout-all` 的职责）。

**审计**：`auth.oauth_audit` 记录 `consent_allow` / `consent_deny` / `trusted_allow` 与客户端
创建、更新、轮换、删除、`tokens_revoked`，含 actor、client_id、scope 与时间。同意动作在发码**之前**写入，
写失败即拒绝授权（不允许出现"码发了却查不到同意记录"）。

**接口形状**：客户端列表只在管理面 `GET /api/admin/oauth/clients`（返回 `items`，受
`auth.oauth.manage`）；过去那个"登录即可读全量客户端"的 `GET /api/oauth/clients` 已删除——它会把
任何登录账号不拥有的 client_id、回调地址、scope 与归属一并回出去。客户端对象含 `scopes`、
`disabled`、`verified` 等字段（追加，不改既有字段）。

## 令牌与密钥

- 算法固定 RS256；验签只接受 RS256，拒绝 `none`/`HS*`，避免算法混淆攻击。
- 私钥来自 `AUTH_JWT_PRIVATE_KEY`（PEM 或 base64 后的 PEM，PKCS#1/PKCS#8）；**未配置即拒绝启动**
  ——进程内临时密钥会让每次重启都静默换掉签发密钥、JWKS 发布没人固定过的公钥（审计 S-9）。
  只有显式打开本地开发开关 `AUTH_JWT_ALLOW_EPHEMERAL_KEY` 才回退到进程内临时密钥
  （重启后已签发令牌失效，靠会话兜底），此时启动会打 WARNING。
- `issuer`/`audience` 必须与主仓库完全一致（默认 `https://findverse.cc/api` / `metafusion`），
  否则存量令牌全部失效；受众按登记集合校验，OIDC `id_token` 以 `client_id` 为受众。
- 载荷新增 `token_use`（`session`/`oauth`/`id_token`，历史令牌缺席）与第三方绑定的
  `client_id`/`scope`：用途区分不靠 `audience` 区分（见上节「令牌用途隔离」），未知取值验签直接拒绝。
- 不透明降级路径（未配置签发器）同样隔离：第三方令牌行在读侧（`User`/`UserFromOAuthToken`/
  `OAuthUserinfo`）按行内 `scope` 裁剪为最小身份，不补权限组；会话行才补 `WithAccess`。
- 注销为单实例内存实现（jti 集合直到自然过期）：多副本部署需要共享状态，当前未支持。

## 数据与迁移

账号表位于**独立的 `auth` schema**，与目录库同实例但不同 schema，且不跨 schema 建外键
（目录侧只保留裸 UUID 引用）。因此切流**不需要数据搬运**，只需要把网关前缀指过来。

- 表结构：`Init` 幂等建表（`CREATE ... IF NOT EXISTS` + 放宽 `users_role_check`），
  **线上 auth schema 的列形状是唯一基线**（见 `internal/store/schema_parity_test.go` 的冻结值）。
- 第一方 OAuth 客户端（`metafusion-catalog` / `-forum` / `-resources`）的种子也在 `Init` 里，
  与建表同一处：这三个客户端原先由目录服务在启动时写入，账号拆出后随 schema 一起搬进来，
  `ON CONFLICT DO NOTHING` 保护后台改过的配置。目录服务现在**不再创建、也不再写入任何 auth 对象**。
- 该服务**没有版本化迁移**：建表语句即当前终态，改动需同时更新冻结用例。
- 本轮新增的列与表都以 `ADD COLUMN IF NOT EXISTS` / `CREATE TABLE IF NOT EXISTS` 写在 `Init` 里
  （`oauth_clients.scopes`、`oauth_clients.disabled`、`oauth_tokens.jti`、`auth.oauth_audit`、
  `auth.personal_access_tokens`），老库启动即补齐，不需要手工迁移；冻结值同步在
  `schema_parity_test.go`、`schema_lifecycle_parity_test.go` 与 `pat_schema_parity_test.go`。
  追加只加在末尾：既有语句一字不改（幂等 DDL 就是本服务的"up-only 追加"）。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `8081` | 监听端口 |
| `DATABASE_URL` | 由 `DB_*` 拼装 | PostgreSQL 连接串（只使用 `auth` schema） |
| `AUTH_JWT_PRIVATE_KEY` | **必填** | RS256 私钥（PEM / base64 PEM）；为空即拒绝启动 |
| `AUTH_JWT_ALLOW_EPHEMERAL_KEY` | 空 | 本地开发开关：`1`/`true`/`yes`/`on` 时允许进程内临时密钥（生产不要开，启动会打 WARNING） |
| `AUTH_JWT_ISSUER` / `AUTH_JWT_AUDIENCE` | `https://findverse.cc/api` / `metafusion` | 必须与主仓库一致 |
| `AUTH_ACCOUNT_URL` | 空 | 未登录跳转的账号页绝对地址；为空则用站点相对路径 `/account` |

## 运行

```bash
go run cmd/server/main.go
go test ./... && go vet ./...

# 真实库回归（可选）：库名必须含 _test；两个测试包都会重建测试数据，需串行
AUTH_TEST_DSN='postgres://user:pw@127.0.0.1:5432/metafusion_test?sslmode=disable' go test -p 1 ./...
```

## 已知缺口与待定

- **不签发 `refresh_token`**（理由见上）：第三方访问令牌 15 分钟到期后需要重新授权；
  是否给第三方单独放宽 TTL 属产品决策，当前未放宽。
- **同意不记忆**：每次授权都会重新询问（`trusted` 客户端除外）。用户已可通过
  `GET /api/auth/oauth-grants` 自查并撤回（见「吊销」），但同意页仍不做"已授权则跳过"。
- **RFC 7009 撤销端点没有**；introspection 只对 PAT 有（`POST /api/auth/tokens/introspect`）：
  无状态访问令牌仍是"下游本地验签 + 等 15 分钟自然过期"，PAT 走的才是可撤销的内省路径。
- **PAT 的管理面未做**：管理员无法列出 / 吊销他人的令牌（本轮只做自助 + 内省）。
- **jti 注销集合是单实例内存实现**：多副本部署需要共享状态（Redis 集合），当前未支持。
- **公开资料只有账号列**：`auth.users` 里没有 `display_name` / `avatar_url` / `bio` / `created_at` /
  `favorites_public` 这些展示列，`GET /api/users/:id` 因此**不返回**它们，也不填占位值——
  空串或 false 会被读成"这个人就是没头像 / 就是没开收藏"，而事实是"没有这个来源"。
  前端按缺字段降级；要补齐得先决定新增列与存量行的回填口径（`created_at` 尤其如此：账号行上
  没有任何创建时间列）。收藏数在互动服务、作品数在目录服务，本服务不读它们的库，
  所以 `stats` 只给 `invited_count`——给 0 会变成"这个人什么都没写"。
- **`invite_code` 不是 `auth.users` 的列**：邀请码台账在 `auth.invites`（可限次/可过期/可吊销，一个人也可能有多张），
  已由 `GET /api/auth/invite` **只对本人**提供，公开资料里不合成这个字段。

## 管理台（admin/）

账号域的治理界面是本仓库内的**独立 Next.js 应用**（`admin/`），不属于主仓库前端
（解耦审计 2026-09 §7.3 D1：每个服务自带 UI，独立应用 + 同域路径 + 网关按路径聚合）：

- 挂载在 `/admin/account`（`basePath`），容器内监听 3000，网关上游名 `auth-admin:3000`；
- 健康检查 `GET /admin/account/api/health` → `{"ok":true,"service":"auth-admin"}`，不依赖登录态；
- 只调用本服务已有的 `/api/auth/*`、`/api/admin/*`；会话是同域 Cookie，
  未登录或 401 跳主站 `/login?redirect=<当前路径>`，权限一律以 `/api/auth/me` 的 `permissions` 为准；
- 页面：用户治理、权限组、邀请、OAuth 客户端、实例与设置（只读）。

本地开发、镜像构建、环境变量与完整契约见 [admin/README.md](admin/README.md)；
compose 与网关由主仓库负责，本仓库只保证端口、basePath 与健康检查与约定一致。

## 迁移状态

- **已切流（2026-09-14，开发实例）**：网关把 `/api/setup`、`/api/auth/*`、`/api/admin/users*`、
  `/api/oauth/*`、`/api/oidc/*`、`/api/.well-known/*` 指到本服务，本服务是这些端点的唯一实现。
- 主仓库已删除账号实现（`identity.go` / `token.go` 的签发侧 / 相关路由），只保留 RS256 验签：
  目录侧验签失败不再回退查 `auth.sessions`，`auth` schema 的读写方只有本服务。
- 服务端会话（`auth.sessions`）仍然是本服务的一部分：登录写入、refresh 轮转、登出删除；
  它同时兜底存量不透明会话令牌（老实例登录后仍带着 Cookie 的用户不会掉线）。
