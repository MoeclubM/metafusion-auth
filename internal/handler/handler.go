// Package handler 暴露账号服务的 HTTP 契约：/api/setup、/api/auth/*、/api/admin/users*、
// /api/oauth/*、/api/oidc/jwks 与 OIDC 发现文档。路径与请求响应形状与主仓库
// catalog 包逐字一致，切流时前端与第三方客户端都不需要改动。
//
// 同时按 OIDC 标准在根路径提供 /.well-known/openid-configuration 与
// /.well-known/jwks.json：发现文档里的地址来自 issuer（AUTH_JWT_ISSUER），
// 因此两个入口返回完全一致的内容，第三方依赖任一种挂载方式都能接入。
package handler

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

type Handler struct {
	store *store.Store
	// oauth 是 OAuth 端点使用的存储能力（生产环境就是下面的 store）。
	// 抽成接口是为了让整条授权链路能在没有数据库的环境里用 httptest 跑完，见 oauth.go。
	oauth oauthStore
	// developer 是开发者中心的存储能力（生产环境同样是下面的 store）。
	// 与 oauth 分开注入：两条路径的判定不同（一个按权限码，一个按应用归属）。
	developer developerStore
	// tokens 是个人访问令牌（PAT）端点的存储能力（生产环境同样是下面的 store）。
	tokens patStore
	// rateLimitPolicy 覆盖"是否限流、每分钟几次"的来源：生产为 nil（走 store 的实例设置），
	// 用例据此在不建库的前提下断言开关与速率。
	rateLimitPolicy func(context.Context) (bool, int)
}

func New(s *store.Store) *Handler { return &Handler{store: s, oauth: s, developer: s, tokens: s} }

// Register 挂载全部路由。限流沿用主仓库的口径：只对认证写入类接口按 IP 固定窗口限流，
// 但速率与开关按请求读实例设置（auth_rate_limit_enabled / auth_rate_limit_per_minute），
// 让管理台里的两个设置真正生效——接线前它们公开给前端却没人读。
func (h *Handler) Register(r *gin.Engine) {
	limiter := h.rateLimiter()
	api := r.Group("/api")
	api.Use(h.identity())
	h.registerAuth(api, limiter)
	h.registerOAuth(api, limiter)
	h.registerDeveloper(api, limiter)
	// 个人访问令牌：/api/auth/tokens*（自助创建/列出/吊销 + 下游用的内省）。
	h.registerTokens(api, limiter)
	// 公开账号资料 GET /users/:id（匿名可读，email 仅本人可见）。
	h.registerPublicUsers(api)

	// OIDC 标准路径：
	//   /.well-known/openid-configuration、/.well-known/jwks.json
	// 与 issuer 基址下的 /api/.well-known/...、/api/oidc/jwks 提供同一份文档。
	r.GET("/.well-known/openid-configuration", h.discovery)
	r.GET("/.well-known/jwks.json", h.jwks)
}

func (h *Handler) registerAuth(api *gin.RouterGroup, limiter gin.HandlerFunc) {
	s := h.store
	api.GET("/setup", func(c *gin.Context) {
		needed, err := s.SetupNeeded(c.Request.Context())
		respond(c, gin.H{"needed": needed, "is_initialized": !needed, "has_admin": !needed}, err)
	})
	api.POST("/setup", limiter, func(c *gin.Context) {
		var in struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !body(c, &in) {
			return
		}
		u, err := s.CreateUser(c.Request.Context(), in.Username, in.Email, in.Password, true, nil)
		respond(c, u, err)
	})
	api.POST("/auth/login", limiter, func(c *gin.Context) {
		var in struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !body(c, &in) {
			return
		}
		token, u, err := s.Login(c.Request.Context(), in.Username, in.Password)
		if err == nil {
			setSessionCookie(c, token, 86400)
		}
		respond(c, gin.H{"token": token, "access_token": token, "token_type": "Bearer", "expires_in": int(store.AccessTokenTTL.Seconds()), "user": u}, err)
	})

	// POST /auth/refresh 用当前 Bearer/Cookie 令牌换发新令牌（服务端轮转会话行）。
	// 前端据此在访问令牌临近过期时续期，无需单独的 refresh_token 字段。
	api.POST("/auth/refresh", limiter, func(c *gin.Context) {
		token := tokenFromRequest(c)
		next, u, err := s.Refresh(c.Request.Context(), token)
		if err == nil && next != "" {
			setSessionCookie(c, next, 86400)
		}
		respond(c, gin.H{"token": next, "access_token": next, "token_type": "Bearer", "expires_in": int(store.AccessTokenTTL.Seconds()), "user": u}, err)
	})

	api.GET("/auth/me", requireUser(false), func(c *gin.Context) { respond(c, currentUser(c), nil) })
	api.POST("/auth/logout", requireUser(false), func(c *gin.Context) {
		token := tokenFromRequest(c)
		clearSessionCookie(c)
		respond(c, gin.H{"ok": true}, s.Logout(c.Request.Context(), token))
	})

	// GET /auth/settings 供未登录页面读取实例准入能力：值为**实例设置的持久化结果**
	// （registration_enabled / invite_required 等），不是代码里的常量。
	// require_email_verification 目前恒为 false：邮件通道未接入，前端据此隐藏验证流程。
	api.GET("/auth/settings", func(c *gin.Context) {
		v, err := s.PublicSettings(c.Request.Context())
		respond(c, v, err)
	})

	// POST /auth/register 自助注册：受实例设置约束（开放注册 + 可选邀请码），
	// 成功即签发登录令牌，前端可直接进入登录态。
	api.POST("/auth/register", limiter, func(c *gin.Context) {
		var in struct {
			Username   string `json:"username"`
			Email      string `json:"email"`
			Password   string `json:"password"`
			InviteCode string `json:"invite_code"`
		}
		if !body(c, &in) {
			return
		}
		u, token, err := s.Register(c.Request.Context(), in.Username, in.Email, in.Password, in.InviteCode)
		if err == nil && token != "" {
			setSessionCookie(c, token, 86400)
		}
		respond(c, gin.H{"token": token, "access_token": token, "token_type": "Bearer", "expires_in": int(store.AccessTokenTTL.Seconds()), "user": u}, err)
	})

	// 个人邀请页：我的邀请码台账 + 由我邀请进来的人。
	api.GET("/auth/invite", requireUser(false), func(c *gin.Context) {
		u := currentUser(c)
		invites, err := s.ListInvites(c.Request.Context(), u)
		if err != nil {
			respond(c, nil, err)
			return
		}
		members, err := s.InvitedMembers(c.Request.Context(), u)
		respond(c, gin.H{
			"items":      invites,
			"members":    members,
			"can_create": store.Can(u, "auth.invites.manage"),
		}, err)
	})
	api.POST("/auth/invite", requireUser(false), func(c *gin.Context) {
		var in struct {
			Note          string `json:"note"`
			MaxUses       int    `json:"max_uses"`
			ExpiresInDays int    `json:"expires_in_days"`
		}
		if !body(c, &in) {
			return
		}
		var ttl time.Duration
		if in.ExpiresInDays > 0 {
			ttl = time.Duration(in.ExpiresInDays) * 24 * time.Hour
		}
		inv, err := s.CreateInvite(c.Request.Context(), in.Note, in.MaxUses, ttl, currentUser(c))
		respond(c, inv, err)
	})

	// ── 管理台：实例设置 ──
	api.GET("/admin/settings", requirePermission("auth.settings.manage"), func(c *gin.Context) {
		v, err := s.Settings(c.Request.Context())
		respond(c, v, err)
	})
	api.PUT("/admin/settings", requirePermission("auth.settings.manage"), func(c *gin.Context) {
		var in map[string]any
		if !body(c, &in) {
			return
		}
		respond(c, gin.H{"ok": true}, s.UpdateSettings(c.Request.Context(), in, currentUser(c)))
	})

	// ── 管理台：邀请码 ──
	api.GET("/admin/invites", requirePermission("auth.invites.manage"), func(c *gin.Context) {
		v, err := s.ListInvites(c.Request.Context(), currentUser(c))
		respond(c, gin.H{"items": v}, err)
	})
	api.POST("/admin/invites", requirePermission("auth.invites.manage"), func(c *gin.Context) {
		var in struct {
			Note          string `json:"note"`
			MaxUses       int    `json:"max_uses"`
			ExpiresInDays int    `json:"expires_in_days"`
		}
		if !body(c, &in) {
			return
		}
		var ttl time.Duration
		if in.ExpiresInDays > 0 {
			ttl = time.Duration(in.ExpiresInDays) * 24 * time.Hour
		}
		inv, err := s.CreateInvite(c.Request.Context(), in.Note, in.MaxUses, ttl, currentUser(c))
		respond(c, inv, err)
	})
	api.POST("/admin/invites/:code/revoke", requirePermission("auth.invites.manage"), func(c *gin.Context) {
		respond(c, gin.H{"ok": true}, s.RevokeInvite(c.Request.Context(), c.Param("code"), currentUser(c)))
	})

	// ── 管理台：权限组与成员分配 ──
	api.GET("/admin/groups", requirePermission("auth.groups.manage"), func(c *gin.Context) {
		v, err := s.ListGroups(c.Request.Context())
		respond(c, gin.H{"items": v}, err)
	})
	api.GET("/admin/permissions", requirePermission("auth.groups.manage"), func(c *gin.Context) {
		respond(c, gin.H{"items": store.PermissionCatalog()}, nil)
	})
	api.POST("/admin/groups", requirePermission("auth.groups.manage"), func(c *gin.Context) {
		var in store.Group
		if !body(c, &in) {
			return
		}
		g, err := s.CreateGroup(c.Request.Context(), in, currentUser(c))
		respond(c, g, err)
	})
	api.PUT("/admin/groups/:code", requirePermission("auth.groups.manage"), func(c *gin.Context) {
		var in store.Group
		if !body(c, &in) {
			return
		}
		g, err := s.UpdateGroup(c.Request.Context(), c.Param("code"), in, currentUser(c))
		respond(c, g, err)
	})
	api.DELETE("/admin/groups/:code", requirePermission("auth.groups.manage"), func(c *gin.Context) {
		respond(c, gin.H{"ok": true}, s.DeleteGroup(c.Request.Context(), c.Param("code"), currentUser(c)))
	})
	api.PUT("/admin/users/:id/groups", requirePermission("auth.users.manage"), func(c *gin.Context) {
		var in struct {
			Groups []string `json:"groups"`
		}
		if !body(c, &in) {
			return
		}
		respond(c, gin.H{"ok": true}, s.SetUserGroups(c.Request.Context(), c.Param("id"), in.Groups, currentUser(c)))
	})

	// 改自己的密码只有这一条入口（前端设置页也只调它），参数是 old_password/new_password。
	changePassword := func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var in struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}
		if !body(c, &in) {
			return
		}
		respond(c, gin.H{"ok": true}, s.ChangePassword(c.Request.Context(), u.ID, in.OldPassword, in.NewPassword))
	}
	api.PUT("/auth/password", requireUser(false), changePassword)

	api.POST("/auth/logout-all", requireUser(false), func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		clearSessionCookie(c)
		respond(c, gin.H{"ok": true}, s.LogoutAll(c.Request.Context(), u.ID))
	})

	// 用户自助管理自己的第三方授权（设置页的"已授权应用"）。
	// 与管理员的 /admin/users/{id}/revoke-oauth-tokens 的区别是**归属**：
	// 这里只认当前登录身份，路径里没有别人的 user id，因此普通成员也能收回自己的授权。
	api.GET("/auth/oauth-grants", requireUser(false), func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		items, err := s.ListOAuthGrants(c.Request.Context(), u.ID)
		respond(c, gin.H{"items": items}, err)
	})
	api.DELETE("/auth/oauth-grants/:client_id", requireUser(false), func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		n, err := s.RevokeOwnOAuthGrant(c.Request.Context(), u.ID, c.Param("client_id"))
		// 幂等：本来就没有有效令牌时 revoked=0 仍回 ok——用户点"移除"要的是结果状态。
		respond(c, gin.H{"ok": true, "revoked": n}, err)
	})

	api.GET("/admin/users", requirePermission("auth.users.manage"), func(c *gin.Context) {
		users, err := s.ListUsers(c.Request.Context())
		respond(c, gin.H{"items": users}, err)
	})
	api.POST("/admin/users", requirePermission("auth.users.manage"), func(c *gin.Context) {
		var in struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !body(c, &in) {
			return
		}
		u, err := s.CreateUser(c.Request.Context(), in.Username, in.Email, in.Password, false, currentUser(c))
		respond(c, u, err)
	})
	api.PUT("/admin/users/:id/role", requirePermission("auth.users.manage"), func(c *gin.Context) {
		var in struct {
			Role string `json:"role"`
		}
		if !body(c, &in) {
			return
		}
		respond(c, gin.H{"ok": true}, s.UpdateUserRole(c.Request.Context(), c.Param("id"), in.Role, currentUser(c)))
	})
	api.PUT("/admin/users/:id/password", requirePermission("auth.users.manage"), func(c *gin.Context) {
		var in struct {
			Password string `json:"password"`
		}
		if !body(c, &in) {
			return
		}
		respond(c, gin.H{"ok": true}, s.ResetUserPassword(c.Request.Context(), c.Param("id"), in.Password, currentUser(c)))
	})

	// PUT /admin/users/:id/ban 封禁或解封账号（body {banned: bool}）。
	// 封禁会连带删除该用户的服务端会话、第三方令牌与未兑换授权码，并让验签路径立即拒绝，
	// 所以这里返回"保存后的账号投影"，管理台据此刷新该行而不是猜结果。
	api.PUT("/admin/users/:id/ban", requirePermission("auth.users.manage"), func(c *gin.Context) {
		var in struct {
			Banned *bool `json:"banned"`
		}
		if !body(c, &in) {
			return
		}
		if in.Banned == nil {
			// 缺字段按非法载荷拒绝：把"没传"当成解封，会让一次误请求悄悄放人进来。
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
			return
		}
		u, err := s.SetUserBanned(c.Request.Context(), c.Param("id"), *in.Banned, currentUser(c))
		if err != nil {
			respond(c, nil, err)
			return
		}
		respond(c, gin.H{"ok": true, "user": u}, nil)
	})
}

// identity 解析调用者身份：Bearer 与 Cookie 各试一次（前端可能带着刚过期的
// Bearer 令牌，而 HttpOnly Cookie 里是刷新后的新令牌，不能互相顶掉）。
func (h *Handler) identity() gin.HandlerFunc {
	return func(c *gin.Context) {
		bearer := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		cookie, _ := c.Cookie("mf_session")
		for _, token := range []string{bearer, cookie} {
			if token == "" {
				continue
			}
			if u, err := h.store.Authenticate(c.Request.Context(), token); err == nil {
				c.Set(userKey, u)
				break
			}
		}
		c.Next()
	}
}

const userKey = "auth_user"

func currentUser(c *gin.Context) *store.User {
	if v, ok := c.Get(userKey); ok {
		if u, ok := v.(*store.User); ok {
			return u
		}
	}
	return nil
}

func requireUser(admin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		if admin && !store.Can(u, store.WildcardPermission) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

// requirePermission 是管理台的细粒度闸门：**只认这一条码**（判定见 store.Can）。
// 这里刻意不做"持任意 auth.* 码即视为管理员"的兜底：那会让持 auth.invites.manage 的
// 成员通过 /api/admin/users 等其它域的闸门，把"每人只拿到被授予的那些码"打穿。
func requirePermission(code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		if !store.Can(u, code) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden", "required_permission": code})
			return
		}
		c.Next()
	}
}

// isAdmin 判定"全权管理员"：* 通配码，或老令牌（无 permissions 声明）的历史 role=admin。
// 与 requirePermission 同源（store.Can），不再按 auth.* 前缀放宽。
func isAdmin(u *store.User) bool { return store.Can(u, store.WildcardPermission) }

func tokenFromRequest(c *gin.Context) string {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		token, _ = c.Cookie("mf_session")
	}
	return token
}

// setSessionCookie 与主仓库保持同一套 Cookie 语义：httpOnly + SameSite=Strict，
// Secure 依据实际协议判定（反代后看 X-Forwarded-Proto）。
func setSessionCookie(c *gin.Context, token string, maxAge int) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("mf_session", token, maxAge, "/", "", isSecure(c), true)
}

func clearSessionCookie(c *gin.Context) {
	// 清 Cookie 的 Secure 必须与写入时一致，否则 HTTPS 下清不掉。
	c.SetCookie("mf_session", "", -1, "/", "", isSecure(c), true)
}

func isSecure(c *gin.Context) bool {
	return c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
}

func body(c *gin.Context, v any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	if err := c.ShouldBindJSON(v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return false
	}
	return true
}

const codeInternalError = "internal_error"

// respond 把 store 的稳定错误码映射为 HTTP 状态码；响应体统一为单一 error 字段。
//
// 只有"机器码形状"的错误文本才作为码交给客户端：库层/驱动/网络/反序列化的原文
// （可能带表名、约束名、SQL 片段、内网地址或文件路径）一律只进服务端日志，对外回通用码。
// 触发面是注册的"先查后插"竞态——并发同名会撞 users_username_key，撞名是用户可自纠的
// 错误，必须有稳定码与恰当状态码（2026-09-19 第二轮架构报告 #9/#15/#16）。
func respond(c *gin.Context, v any, err error) {
	if err == nil {
		c.JSON(http.StatusOK, v)
		return
	}
	var pg *pq.Error
	switch {
	case errors.Is(err, sql.ErrNoRows):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.As(err, &pg):
		status, code := postgresErrorResponse(pg)
		if status >= http.StatusInternalServerError {
			// SQLSTATE、约束名与 detail 只进服务端日志：客户端拿到表名/约束名既看不懂，也泄露库结构。
			slog.Error("账号服务：数据库错误", "sqlstate", string(pg.Code), "constraint", pg.Constraint,
				"detail", pg.Detail, "err", err.Error())
		}
		c.JSON(status, gin.H{"error": code})
	case internalFailure(err):
		slog.Error("账号服务：未登记的错误（原文不外发）", "err", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": codeInternalError})
	default:
		c.JSON(authStatusFor(err.Error()), gin.H{"error": err.Error()})
	}
}

// postgresErrorResponse 把 SQLSTATE 翻成 (状态码, 稳定码)，与目录服务同口径
// （backend/internal/catalog/http.go 的 respond）：唯一约束 409、外键/CHECK 与非法字面量 400、
// 其余 500 database_error。约束名只用来挑码与记日志，绝不回给客户端。
func postgresErrorResponse(pg *pq.Error) (int, string) {
	switch pg.Code {
	case "23505": // unique_violation
		switch pg.Constraint {
		case "users_username_key":
			return http.StatusConflict, "username_or_email_taken"
		case "groups_code_key":
			return http.StatusConflict, "group_exists"
		default:
			return http.StatusConflict, "conflict"
		}
	case "23503", "23514": // foreign_key_violation / check_violation：引用了不存在或越界的行
		return http.StatusBadRequest, "constraint_violation"
	case "22P02": // invalid_text_representation：uuid 之类的字面量不合法
		return http.StatusBadRequest, "invalid_id"
	default:
		return http.StatusInternalServerError, "database_error"
	}
}

// authStatusFor 按错误码给状态码：未登记的码保持 400（接线前的行为不变），只有需要客户端
// 分流处理的语义才升级——403 决定"联系站务"还是"重新登录"，409 让"撞名"这类可自纠的冲突
// 能被识别，404 让"不存在/不属于你"不泄露存在性。判定按错误文本的首段，因此
// "group_not_found: member" 这类带细节的码同样命中。
func authStatusFor(message string) int {
	switch firstCode(message) {
	case "forbidden", "account_banned":
		// 口令/令牌本身没问题，是账号被停用：401 会让客户端引导"重新登录"然后又被拒一次，
		// 403 才能让前端提示"账号已停用，请联系站务"。
		return http.StatusForbidden
	case "invalid_credentials", "invalid_token":
		return http.StatusUnauthorized
	case "version_conflict", "username_or_email_taken", "group_exists":
		return http.StatusConflict
	// client_not_found / token_not_found：不是自己的应用或令牌按"不存在"处理，
	// 不把"这东西存在但不属于你"透给调用方。
	case "client_not_found", "token_not_found":
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// firstCode 取错误文本的首段：store 用"码"或"码: 细节"表达业务错误。
func firstCode(message string) string {
	if i := strings.Index(message, ":"); i >= 0 {
		return strings.TrimSpace(message[:i])
	}
	return strings.TrimSpace(message)
}

// internalFailure 判定"这不是业务错误码，而是后端故障原文"：标准库/驱动的哨兵值，
// 或首段不是机器码形状。驱动与网络原文一定不满足形状（含空格、大写、斜杠、引号），
// 例如 "dial tcp 10.0.0.5:5432: connect: connection refused"、
// "invalid character 'x' looking for beginning of value"、"open /etc/passwd: permission denied"。
func internalFailure(err error) bool {
	var pg *pq.Error
	if errors.As(err, &pg) {
		return true
	}
	for _, sentinel := range []error{
		context.Canceled, context.DeadlineExceeded,
		sql.ErrConnDone, sql.ErrTxDone, driver.ErrBadConn,
		io.EOF, io.ErrUnexpectedEOF,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	if infraErrorPrefixes[firstCode(err.Error())] {
		return true
	}
	return !machineCode(firstCode(err.Error()))
}

// infraErrorPrefixes 是标准库/驱动自己的错误前缀：它们的形状与机器码一样
// （"sql: connection is already closed"、"driver: bad connection"、"pq: ..."），
// 必须显式挡掉，否则会被当成业务码原样回给客户端。
var infraErrorPrefixes = map[string]bool{
	"sql": true, "driver": true, "pq": true, "pgx": true,
	"context": true, "net": true, "tls": true, "x509": true,
	"io": true, "os": true, "fs": true, "http": true,
}

// machineCodePattern 是稳定机器码的形状：小写字母开头，只含 [a-z0-9_.-]（字段路径可能带点）。
var machineCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)

func machineCode(s string) bool { return machineCodePattern.MatchString(s) }

// rateLimiter 是按 IP 的固定窗口计数（与主仓库 setup/login 的限流口径一致），
// 速率与开关按请求从实例设置读取：
//
//	· auth_rate_limit_enabled=false  → 直接放行，且不计数（关掉就是关掉，不留半开状态）；
//	· auth_rate_limit_per_minute=N   → 每分钟 N 次，改设置后立即用新上限（已累计的计数不重置，
//	  与固定窗口语义一致：窗口内超限仍然拒绝，不会因为"刚改了上限"而白送配额）。
//
// 策略本身带短缓存（见 store.RateLimitPolicy），避免每个请求打库。
func (h *Handler) rateLimiter() gin.HandlerFunc {
	var mu sync.Mutex
	buckets := map[string]*bucket{}
	window := time.Minute
	return func(c *gin.Context) {
		// 没有注入来源时按默认策略（与接线前的硬编码 15/分钟一致）：
		// 直接构造 Handler 的用例（oauth 内存替身）也走同一条判定，不会悄悄变成"不限流"。
		enabled, limit := true, store.DefaultRateLimitPerMinute
		policy := h.rateLimitPolicy
		if policy == nil && h.store != nil {
			policy = h.store.RateLimitPolicy
		}
		if policy != nil {
			enabled, limit = policy(c.Request.Context())
		}
		if !enabled || limit <= 0 {
			c.Next()
			return
		}
		key := c.ClientIP()
		now := time.Now()
		mu.Lock()
		b, ok := buckets[key]
		if !ok {
			b = &bucket{start: now}
			buckets[key] = b
		}
		// 桶只在超过 4096 个时才清理一次：清理与限流判定分开加锁，避免长临界区。
		if len(buckets) > 4096 {
			for k, v := range buckets {
				if now.Sub(v.lastSeen) > window {
					delete(buckets, k)
				}
			}
		}
		mu.Unlock()
		b.mu.Lock()
		if now.Sub(b.start) > window {
			b.start = now
			b.n = 0
		}
		b.n++
		b.lastSeen = now
		over := b.n > limit
		b.mu.Unlock()
		if over {
			c.Header("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		c.Next()
	}
}

// rateLimiter 是按 IP 的固定窗口计数（与主仓库 setup/login 的限流口径一致）。
type bucket struct {
	mu       sync.Mutex
	start    time.Time
	n        int
	lastSeen time.Time
}
