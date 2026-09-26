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
	"encoding/json"
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

	"github.com/MoeclubM/metafusion-auth/internal/audit"
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
	// loginGuardFactory 生产登录失败保护计数器：生产为 newLoginGuard（每个 Register 一份，
	// 状态随引擎存活），用例据此换成假时钟实例来断言窗口与递增延迟。
	loginGuardFactory func() *loginGuard
	// audit 是审计写入器（写跨服务共用的 audit.audit_log，见 internal/audit 与
	// docs/architecture/audit-log.md）。为 nil 时审计中间件退化为空操作。
	audit *audit.Recorder
}

func New(s *store.Store) *Handler {
	return &Handler{store: s, oauth: s, developer: s, tokens: s, loginGuardFactory: newLoginGuard,
		audit: audit.NewRecorder(s.DB, audit.ServiceName)}
}

// Register 挂载全部路由。限流沿用主仓库的口径：只对认证写入类接口按 IP 固定窗口限流，
// 但速率与开关按请求读实例设置（auth_rate_limit_enabled / auth_rate_limit_per_minute），
// 让管理台里的两个设置真正生效——接线前它们公开给前端却没人读。
func (h *Handler) Register(r *gin.Engine) {
	limiter := h.rateLimiter()
	api := r.Group("/api")
	api.Use(h.identity())
	// 审计中间件必须挂在任何路由注册之前：gin 的 RouterGroup.Use 只对之后注册的路由生效
	// （注册时把当时的 handler 链复制进路由表）。
	api.Use(h.auditMiddleware())
	h.registerAuth(api, limiter)
	h.registerOAuth(api, limiter)
	h.registerDeveloper(api, limiter)
	// 个人访问令牌：/api/auth/tokens*（自助创建/列出/吊销 + 下游用的内省）。
	h.registerTokens(api, limiter)
	// 公开账号资料 GET /users/:id（匿名可读，email 仅本人可见）。
	h.registerPublicUsers(api)
	// 审计读取面 GET /admin/audit-logs（跨服务审计的唯一读取端点）。
	h.registerAudit(api)

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
		if err == nil {
			// 首个管理员此时还没有会话（不签发令牌），凭据类型按 anonymous 记，靠 changes.via 区分入口。
			audit.SetActor(c, audit.Actor{UserID: u.ID, Username: u.Username, CredentialType: audit.CredentialAnonymous})
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID, Changes: map[string]any{
				"username": u.Username, "email": in.Email, "via": "setup"}})
		}
		respond(c, u, err)
	})
	// 登录失败保护：先过按 IP 的请求速率层（limiter），再过按账号+IP 的失败凭据层
	// （loginGuardMiddleware，见 login_guard.go 的层次说明与阈值）。
	api.POST("/auth/login", limiter, h.loginGuardMiddleware(), func(c *gin.Context) {
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
			// 登录成功后操作者就是登录者本人；用会话令牌继续操作，凭据类型 session。
			audit.SetActor(c, audit.Actor{UserID: u.ID, Username: u.Username, CredentialType: audit.CredentialSession})
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID})
		} else {
			// 失败也要留痕（撞库/爆破的取证面）。attempted_username 若填的是邮箱，
			// 会被 audit 包的邮箱遮罩兜住；口令永远不进 changes。
			audit.SetAction(c, "session.login_failed")
			audit.Describe(c, audit.Detail{TargetType: "account", Changes: map[string]any{
				"attempted_username": in.Username, "via": "password"}})
		}
		respond(c, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int(store.AccessTokenTTL.Seconds()), "user": u}, err)
	})

	// POST /auth/refresh 用当前 Bearer/Cookie 令牌换发新令牌（服务端轮转会话行）。
	// 前端据此在访问令牌临近过期时续期，无需单独的 refresh_token 字段。
	api.POST("/auth/refresh", limiter, func(c *gin.Context) {
		token := tokenFromRequest(c)
		next, u, err := s.Refresh(c.Request.Context(), token)
		if err == nil && next != "" {
			setSessionCookie(c, next, 86400)
		}
		respond(c, gin.H{"access_token": next, "token_type": "Bearer", "expires_in": int(store.AccessTokenTTL.Seconds()), "user": u}, err)
	})

	api.GET("/auth/me", requireUser(), func(c *gin.Context) {
		u := currentUser(c)
		// 昵称/简介读穿 DB：JWT 投影至多陈旧一个令牌周期，/auth/me 按 id 回表取最新。
		// 行没了（令牌有效期内账号被删）也不在这里 404——认证链已放行，资料缺省即可。
		// S01：第三方令牌跳过读穿——它的身份就是签发时 scope 裁剪后的投影，
		// 回表补昵称/简介等于把没授予的展示字段再贴回去。
		if u != nil && !u.IsThirdParty() {
			_ = s.FillProfile(c.Request.Context(), u)
		}
		respond(c, u, nil)
	})
	// 改自己的昵称与简介只有这一条入口（前端设置页也只调它）。空串=未设置，超限 400。
	updateProfile := func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var in struct {
			DisplayName string `json:"display_name"`
			Bio         string `json:"bio"`
		}
		if !body(c, &in) {
			return
		}
		out, err := s.UpdateProfile(c.Request.Context(), u.ID, in.DisplayName, in.Bio)
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID, Changes: map[string]any{"profile_updated": true, "self_service": true}})
		}
		respond(c, out, err)
	}
	api.PUT("/auth/profile", requireUser(), updateProfile)
	api.POST("/auth/logout", requireUser(), func(c *gin.Context) {
		token := tokenFromRequest(c)
		clearSessionCookie(c)
		err := s.Logout(c.Request.Context(), token)
		if u := currentUser(c); u != nil {
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID})
		}
		respond(c, gin.H{"ok": true}, err)
	})

	// GET /auth/settings 供未登录页面读取实例准入能力：值为**实例设置的持久化结果**
	// （registration_enabled / invite_required 等），不是代码里的常量。
	// require_email_verification 恒为 false：邮件通道未接入，没有任何强制点；store 侧一律按
	// 生效值回答 false 并拒绝写入 true（unsupported_setting），前端据此不显示验证流程。
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
		if err == nil {
			audit.SetActor(c, audit.Actor{UserID: u.ID, Username: u.Username, CredentialType: audit.CredentialSession})
			// 邀请码是准凭据：只记掩码后的前 4 位（契约 §4）。
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID, Changes: map[string]any{
				"username": u.Username, "email": in.Email,
				"invite_code": audit.MaskSecret(in.InviteCode)}})
		}
		respond(c, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int(store.AccessTokenTTL.Seconds()), "user": u}, err)
	})

	// 个人邀请页：我的邀请码台账 + 由我邀请进来的人。
	api.GET("/auth/invite", requireUser(), func(c *gin.Context) {
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
	api.POST("/auth/invite", requireUser(), func(c *gin.Context) {
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
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "invite", TargetID: audit.MaskSecret(inv.Code),
				Changes: map[string]any{"code": audit.MaskSecret(inv.Code), "max_uses": in.MaxUses,
					"expires_in_days": in.ExpiresInDays}})
		}
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
		before, _ := s.Settings(c.Request.Context())
		err := s.UpdateSettings(c.Request.Context(), in, currentUser(c))
		if err == nil {
			after, _ := s.Settings(c.Request.Context())
			audit.Describe(c, audit.Detail{TargetType: "instance_settings", TargetID: "instance",
				Changes: settingsChanges(before, after, in)})
		}
		respond(c, gin.H{"ok": true}, err)
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
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "invite", TargetID: audit.MaskSecret(inv.Code),
				Changes: map[string]any{"code": audit.MaskSecret(inv.Code), "max_uses": in.MaxUses,
					"expires_in_days": in.ExpiresInDays}})
		}
		respond(c, inv, err)
	})
	api.POST("/admin/invites/:code/revoke", requirePermission("auth.invites.manage"), func(c *gin.Context) {
		masked := audit.MaskSecret(c.Param("code"))
		err := s.RevokeInvite(c.Request.Context(), c.Param("code"), currentUser(c))
		audit.Describe(c, audit.Detail{TargetType: "invite", TargetID: masked, Changes: map[string]any{"code": masked}})
		respond(c, gin.H{"ok": true}, err)
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
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "group", TargetID: g.Code, Changes: groupChanges(nil, &g)})
		}
		respond(c, g, err)
	})
	api.PUT("/admin/groups/:code", requirePermission("auth.groups.manage"), func(c *gin.Context) {
		var in store.Group
		if !body(c, &in) {
			return
		}
		before, _ := s.AuditGroupSnapshot(c.Request.Context(), c.Param("code"))
		g, err := s.UpdateGroup(c.Request.Context(), c.Param("code"), in, currentUser(c))
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "group", TargetID: g.Code, Changes: groupChanges(before, &g)})
		}
		respond(c, g, err)
	})
	api.DELETE("/admin/groups/:code", requirePermission("auth.groups.manage"), func(c *gin.Context) {
		before, _ := s.AuditGroupSnapshot(c.Request.Context(), c.Param("code"))
		err := s.DeleteGroup(c.Request.Context(), c.Param("code"), currentUser(c))
		audit.Describe(c, audit.Detail{TargetType: "group", TargetID: c.Param("code"), Changes: groupChanges(before, nil)})
		respond(c, gin.H{"ok": true}, err)
	})
	api.PUT("/admin/users/:id/groups", requirePermission("auth.users.manage"), func(c *gin.Context) {
		var in struct {
			Groups []string `json:"groups"`
		}
		if !body(c, &in) {
			return
		}
		before, _ := s.AuditUserSnapshot(c.Request.Context(), c.Param("id"))
		err := s.SetUserGroups(c.Request.Context(), c.Param("id"), in.Groups, currentUser(c))
		if err == nil {
			// auditUserChanges 已带 before 的 groups；这里只补 after，避免同一语义写两遍。
			changes := auditUserChanges(before)
			changes["after_groups"] = in.Groups
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: c.Param("id"), Changes: changes})
		}
		respond(c, gin.H{"ok": true}, err)
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
		err := s.ChangePassword(c.Request.Context(), u.ID, in.OldPassword, in.NewPassword)
		if err == nil {
			// 新旧口令都不进审计（它们是凭据本身），只记"谁在什么时候改了自己的口令"。
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID, Changes: map[string]any{"password_changed": true, "self_service": true}})
		}
		respond(c, gin.H{"ok": true}, err)
	}
	api.PUT("/auth/password", requireUser(), changePassword)

	api.POST("/auth/logout-all", requireUser(), func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		clearSessionCookie(c)
		err := s.LogoutAll(c.Request.Context(), u.ID)
		audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID, Changes: map[string]any{"self_service": true}})
		respond(c, gin.H{"ok": true}, err)
	})

	// 用户自助管理自己的第三方授权（设置页的"已授权应用"）。
	// 与管理员的 /admin/users/{id}/revoke-oauth-tokens 的区别是**归属**：
	// 这里只认当前登录身份，路径里没有别人的 user id，因此普通成员也能收回自己的授权。
	api.GET("/auth/oauth-grants", requireUser(), func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		items, err := s.ListOAuthGrants(c.Request.Context(), u.ID)
		respond(c, gin.H{"items": items}, err)
	})
	api.DELETE("/auth/oauth-grants/:client_id", requireUser(), func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		clientID := c.Param("client_id")
		n, err := s.RevokeOwnOAuthGrant(c.Request.Context(), u.ID, clientID)
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "oauth_client", TargetID: clientID,
				Changes: map[string]any{"revoked": n, "self_service": true}})
		}
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
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: u.ID, Changes: map[string]any{
				"username": u.Username, "email": in.Email, "via": "admin"}})
		}
		respond(c, u, err)
	})
	api.PUT("/admin/users/:id/password", requirePermission("auth.users.manage"), func(c *gin.Context) {
		var in struct {
			Password string `json:"password"`
		}
		if !body(c, &in) {
			return
		}
		before, _ := s.AuditUserSnapshot(c.Request.Context(), c.Param("id"))
		err := s.ResetUserPassword(c.Request.Context(), c.Param("id"), in.Password, currentUser(c))
		if err == nil {
			// 只记"发生了一次重置"与对象：新旧口令一个字都不进 changes。
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: c.Param("id"), Changes: map[string]any{
				"password_reset": true, "target_username": usernameOf(before)}})
		}
		respond(c, gin.H{"ok": true}, err)
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
			audit.Fail(c, "invalid_payload")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
			return
		}
		before, _ := s.AuditUserSnapshot(c.Request.Context(), c.Param("id"))
		u, err := s.SetUserBanned(c.Request.Context(), c.Param("id"), *in.Banned, currentUser(c))
		if err != nil {
			respond(c, nil, err)
			return
		}
		// 封禁与解封是同一路由的两种语义：动作码按请求体分流，查"谁被封过"时不用看 changes。
		if *in.Banned {
			audit.SetAction(c, "user.banned")
		} else {
			audit.SetAction(c, "user.unbanned")
		}
		changes := map[string]any{"after_banned": *in.Banned, "target_username": usernameOf(before)}
		if before != nil {
			changes["before_banned"] = before.Banned
		}
		audit.Describe(c, audit.Detail{TargetType: "user", TargetID: c.Param("id"), Changes: changes})
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

// requireUser 是"登录即可"的闸门。此前它带一个 admin bool 与一条
// `store.Can(u, store.WildcardPermission)` 分支，但 10 处调用**全部传 false**——
// 分支永不成立，读代码的人却会以为还有一条"按 role 判管理员"的路径。
// 管理员权限一律走 requirePermission(code)（细粒度码，见下），故这里删掉参数与分支
// （2026-09-19 第二轮审计 #8）。
func requireUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			audit.Fail(c, "authentication_required")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		c.Next()
	}
}

// requirePermission 是管理台的细粒度闸门：**只认这一条码**（判定见 store.Can）。
// 这里刻意不做"持任意 auth.* 码即视为管理员"的兜底：那会让持 auth.invites.manage 的
// 成员通过 /api/admin/users 等其它域的闸门，把"每人只拿到被授予的那些码"打穿。
// S01：第三方 OAuth 令牌（token_use=oauth/id_token）在 store.Can 里统一拒绝，
// 因此无需在此逐个判断——profile-only 的第三方令牌打管理路由一律 403。
func requirePermission(code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			audit.Fail(c, "authentication_required")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		if !store.Can(u, code) {
			audit.Fail(c, "forbidden")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden", "required_permission": code})
			return
		}
		c.Next()
	}
}

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

// maxJSONBody 是 JSON 写接口的请求体上限。必须自己封顶：网关的 client_max_body_size 是 1G，
// 应用层不设限就等于把"一个请求能让服务占多少内存"交给调用方决定。
const maxJSONBody = 2 << 20

// body 是 JSON 写接口统一的请求解析：2MB 上限 + **拒绝未知字段**。
//
// 未知字段一律拒绝而不是静默忽略：字段名拼错的请求不会再"看起来成功了"。此前
// POST /api/setup 会把 site_name / registration_enabled / invite_required 静默吞掉
// （请求体只声明 username/email/password），调用方以为这些开关已经生效。口径与目录、
// 互动、存储三个服务的写接口一致；收 map[string]any 的端点（PUT /api/admin/settings）
// 天然不受影响——未知的**设置键**由 store.UpdateSettings 的接受表拒绝。
func body(c *gin.Context, v any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONBody)
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		audit.Fail(c, "invalid_payload")
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
		audit.Fail(c, "not_found")
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.As(err, &pg):
		status, code := postgresErrorResponse(pg)
		if status >= http.StatusInternalServerError {
			// SQLSTATE、约束名与 detail 只进服务端日志：客户端拿到表名/约束名既看不懂，也泄露库结构。
			slog.Error("账号服务：数据库错误", "sqlstate", string(pg.Code), "constraint", pg.Constraint,
				"detail", pg.Detail, "err", err.Error())
		}
		audit.Fail(c, code)
		c.JSON(status, gin.H{"error": code})
	case internalFailure(err):
		slog.Error("账号服务：未登记的错误（原文不外发）", "err", err.Error())
		audit.Fail(c, codeInternalError)
		c.JSON(http.StatusInternalServerError, gin.H{"error": codeInternalError})
	default:
		audit.Fail(c, err.Error())
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
			audit.Fail(c, "rate_limited")
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
