# MetaFusion 账号管理台（admin/）

账号域自带的管理界面：**独立应用 + 同域路径 + 网关按路径聚合**（解耦审计 2026-09 §7.3 D1、§8.1）。
它只调用账号服务（metafusion-auth）的 HTTP 接口，不 import 其它应用的内部代码，也不读任何服务的库。

## 与网关和主仓库的契约

| 项 | 值 | 说明 |
| --- | --- | --- |
| 应用挂载点 | `/admin/account` | `next.config.mjs` 的 `basePath`；`next/link` 会自动带上 |
| 容器内端口 | `3000` | `EXPOSE 3000`、`PORT=3000`、`HOSTNAME=0.0.0.0` |
| 网关上游名 | `auth-admin:3000` | 由主仓库 `deploy/docker-compose.yml` 加服务并接进网关 |
| 健康检查 | `GET /admin/account/api/health` | 返回 `{"ok":true,"service":"auth-admin"}`，**不依赖登录态**（`src/app/api/health/route.ts`） |
| 尾斜杠 | `trailingSlash: true` + `skipTrailingSlashRedirect: true` | 网关把 `/admin/account` 301 到带尾斜杠形式；应用必须同向认领这个规范形式，否则两边互打回（`ERR_TOO_MANY_REDIRECTS`）。关掉 Next 自己的归一化重定向，健康端点才能在契约里的字面路径上直接 200 |
| 语言 | `NEXT_LOCALE` cookie | 键 `zh-CN` / `en-US` / `zh-TW` / `ja-JP`，与主站同名同值 |
| 会话 | 同域 Cookie `mf_session` | 账号服务签发；页面用 `credentials: "include"` 取 `GET /api/auth/me` |
| 未登录 | 跳 `/login?redirect=<当前路径>` | `/login` 是**主站**登录页，绝对路径、不带 basePath |
| 权限判定 | 服务端 `permissions` | 含 `*` 通配；前端只做「看不见」的界面收敛，不替代服务端鉴权 |

改成上面任何一项都要同时改主仓库的 compose / 网关：

```nginx
# 主仓库 deploy/nginx.conf 里需要（由主仓库维护，本仓库不提供）
location /admin/account/ {
    proxy_pass http://auth-admin:3000;   # 路径原样转发，不重写
}
```

## 本地跑

```bash
cd admin
bun install
bun run dev          # http://127.0.0.1:3000/admin/account
```

本应用**不代理** `/api/*`：它和账号服务必须同源，页面里的 `fetch("/api/auth/me")` 走的是浏览器当前源。
因此本地开发有两条路：

1. 起一套网关（主仓库 compose），从 `https://<站点>/admin/account` 访问；
2. 或者用一个最简单的同源反代，把 `/api/*` 指到本地账号服务（`go run cmd/server/main.go`，默认 8081）。

直接打开 `http://127.0.0.1:3000/admin/account` 而不同源挂 `/api` 时，页面会停在「无法确认登录状态」并给出重试——
这是如实反馈，不是 bug。

## 构建镜像

构建上下文是**仓库根**（主编排传 `context=${MF_AUTH_DIR:-../../metafusion-auth}`、
`dockerfile=admin/Dockerfile`），所以要在仓库根执行：

```bash
cd metafusion-auth
docker build -f admin/Dockerfile -t metafusion-auth-admin:dev .
docker run --rm -p 3000:3000 metafusion-auth-admin:dev
curl -s localhost:3000/admin/account/api/health   # {"ok":true,"service":"auth-admin"}
```

同理，忽略规则放在**仓库根**的 `.dockerignore`（同一个上下文还给账号服务的 Go 镜像用），
放在 `admin/` 下面不会生效。

构建期不需要任何环境变量。运行期只有 Next standalone 自带的那几个：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | Dockerfile 里已设定 |
| `HOSTNAME` | `0.0.0.0` | Dockerfile 里已设定 |
| `NEXT_TELEMETRY_DISABLED` | `1` | Dockerfile 里已设定 |

**没有 `NEXT_PUBLIC_*`**：本应用的页面、静态资源与接口全部是同源相对路径，构建期不需要外部地址
（主仓库前端的那些构建参数是给「跨域嵌入」用的，这里没有那个需求）。

## 部署

由主仓库 `deploy/docker-compose.yml` 负责：加服务（构建上下文指向本仓库的 `admin/`）、
接进网关上游 `auth-admin:3000`、按 `/admin/account/` 挂载。本仓库的
`Dockerfile` / `.dockerignore` 只保证镜像本身可构建、可探活。

## 页面

| 路径 | 页面 | 需要的权限码 |
| --- | --- | --- |
| `/` | 用户治理：列表 / 搜索 / 改角色 / 改密码 / 封禁解封 / 权限组分配 | `auth.users.manage`（组清单另需 `auth.groups.manage`） |
| `/groups` | 权限组：列表、新建 / 编辑 / 删除、权限码说明 | `auth.groups.manage` |
| `/invites` | 邀请：台账、创建、吊销、使用情况 | `auth.invites.manage` |
| `/oauth-clients` | OAuth 客户端：列表、创建（一次性密钥）、轮换、停用、删除 | `auth.oauth.manage` |
| `/instance` | 实例与设置：只读展示实例设置与当前身份 | `auth.settings.manage` |

前端**不发明**任何接口：每一条请求都对应账号服务已有的 `/api/auth/*`、`/api/admin/*`
（契约见仓库根 `README.md` 与 `internal/handler/handler.go`）。

## 边界与安全

- **破坏性动作都要二次确认**：改角色、封禁/解封、删除权限组、删除客户端、停用客户端、轮换密钥、吊销邀请码。
- **改角色会清空该用户手工分配的权限组**（服务端 `UpdateUserRole` 按 `RoleToGroups` 重建成员关系）：
  界面上直接写明，并在提交前锁住组选择、改角色单独确认一次。
- **403 按块降级**：每个面板各自取数，任一接口 403 只让那一块换成「没有进入这一块的权限」说明卡，
  页面其余部分照常可用；上游不可达给的是「账号服务不可达 + 重试」，不是空列表。
- 明文 `client_secret` 只在创建/轮换的响应里出现一次（库里只有 bcrypt 哈希），
  界面弹一次「请立即保存」并说明关掉后只能轮换。
- 账号封禁不是打标记：会话、第三方令牌、未兑换授权码一并删除，验签立即拒绝——确认对话框里写清了。

## 设计 token

`tailwind.config.ts`、`postcss.config.mjs`、`globals.css` 的设计 token 抄自
`MetaFusion/frontend`，放在 `src/shared/theme/`，文件头注明了来源；
等 §7.3 的共享前端包落地后整体替换。`postcss.config.mjs` 只是把 Tailwind 指到那份共享配置的接线。

## 校验

```bash
cd admin
bun install
bun run i18n:check   # 四语键集合一致 + 源码字面量键都存在
bunx tsc --noEmit
bunx next build      # 产物 .next/standalone
```

这四条也是 CI（`.github/workflows/ci.yml` 的 `admin-ui` job）跑的东西。

改了 `basePath` / `trailingSlash` / 健康端点之后，再打一遍路由矩阵——**必须无 3xx**，
有 301/308 就说明应用的尾斜杠方向与网关不一致：

```bash
bunx next build && bunx next start -p 3000 &   # 或容器里的 bun .next/standalone/server.js
for p in /admin/account /admin/account/ /admin/account/groups/ /admin/account/invites/ \
         /admin/account/oauth-clients/ /admin/account/instance/ \
         /admin/account/api/health /admin/account/api/health/ /admin/account/nope /; do
  printf '%-36s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://127.0.0.1:3000$p)"
done
```

期望：前 8 条 200（健康端点带不带尾斜杠都直接 200），`/admin/account/nope` 与 `/` 是 404。

## 未纳入本期

- **实例设置的写入**：`PUT /api/admin/settings` 存在且受 `auth.settings.manage` 保护，
  但本期只做只读展示（写入界面涉及键类型校验与并发覆盖语义，另行排期）。
- **开发者中心**（`/api/developer/*`）：那是给普通登录账号自助登记应用的独立界面，与平台治理面不同源，未纳入。
- **OAuth 授权审计**（`GET /api/admin/oauth/audits`）：未纳入本期页面。
- **登录 / 注册 / 改密 / 个人邀请 / 已授权应用撤回**：这些是账号服务的对外页面，
  由主站 `/login`、`/account`、`/developer` 承载（审计 §8.1 的 UI 路径列），不在治理台内重复实现。
