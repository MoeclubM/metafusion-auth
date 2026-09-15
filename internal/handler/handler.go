// Package handler 暴露账号服务的 HTTP 契约：/api/setup、/api/auth/*、/api/admin/users*、
// /api/oauth/*、/api/oidc/jwks 与 OIDC 发现文档。路径与请求响应形状与主仓库
// catalog 包逐字一致，切流时前端与第三方客户端都不需要改动。
//
// 同时按 OIDC 标准在根路径提供 /.well-known/openid-configuration 与
// /.well-known/jwks.json：发现文档里的地址来自 issuer（AUTH_JWT_ISSUER），
// 因此两个入口返回完全一致的内容，第三方依赖任一种挂载方式都能接入。
package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

type Handler struct {
	store *store.Store
}

func New(s *store.Store) *Handler { return &Handler{store: s} }

// Register 挂载全部路由。限流沿用主仓库的口径：只对认证写入类接口按 IP 固定窗口限流。
func (h *Handler) Register(r *gin.Engine) {
	limiter := rateLimiter(15, time.Minute)
	api := r.Group("/api")
	api.Use(h.identity())
	h.registerAuth(api, limiter)
	h.registerOAuth(api, limiter)

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
			"can_create": store.HasPermission(u.Permissions, "auth.invites.manage"),
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

	// PUT /auth/password 与 POST /auth/change-password 语义相同（当前用户改自己密码），
	// 参数形状均为 old_password/new_password，复用同一个实现。
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
	api.POST("/auth/change-password", requireUser(false), changePassword)

	api.POST("/auth/logout-all", requireUser(false), func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		clearSessionCookie(c)
		respond(c, gin.H{"ok": true}, s.LogoutAll(c.Request.Context(), u.ID))
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
}

func (h *Handler) registerOAuth(api *gin.RouterGroup, limiter gin.HandlerFunc) {
	s := h.store
	oauth := api.Group("/oauth")
	// 客户端列表不含密钥哈希（SecretHash json:"-"），但仍需登录后可读，
	// 避免匿名枚举 client_id/redirect_uris。
	oauth.GET("/clients", requireUser(false), func(c *gin.Context) {
		clients, err := s.ListOAuthClients(c.Request.Context())
		respond(c, gin.H{"clients": clients}, err)
	})
	oauth.GET("/authorize", limiter, func(c *gin.Context) {
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		responseType := c.Query("response_type")
		state := c.Query("state")
		scope := c.DefaultQuery("scope", "profile")
		if responseType != "code" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
			return
		}
		client, err := s.GetOAuthClient(c.Request.Context(), clientID)
		if err != nil || client == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}
		validURI := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				validURI = true
				break
			}
		}
		if !validURI {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
			return
		}
		u := currentUser(c)
		if u == nil {
			// 未登录先回账号页，登录后带 return_to 回到本授权请求。
			target := "/account?return_to=" + url.QueryEscape(c.Request.RequestURI)
			if base := h.accountPageBase(); base != "" {
				target = base + "?return_to=" + url.QueryEscape(c.Request.RequestURI)
			}
			c.Redirect(http.StatusFound, target)
			return
		}
		code, err := s.CreateOAuthCode(c.Request.Context(), clientID, u.ID, redirectURI, scope, c.Query("code_challenge"), c.Query("code_challenge_method"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		target := fmt.Sprintf("%s%scode=%s", redirectURI, sep, url.QueryEscape(code))
		if state != "" {
			target += "&state=" + url.QueryEscape(state)
		}
		c.Redirect(http.StatusFound, target)
	})
	oauth.POST("/token", limiter, func(c *gin.Context) {
		grantType := c.PostForm("grant_type")
		code := c.PostForm("code")
		clientID := c.PostForm("client_id")
		clientSecret := c.PostForm("client_secret")
		redirectURI := c.PostForm("redirect_uri")
		verifier := c.PostForm("code_verifier")
		if grantType == "" {
			// 兼容 JSON 提交（OIDC 客户端常用）。
			var payload struct {
				GrantType    string `json:"grant_type"`
				Code         string `json:"code"`
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
				RedirectURI  string `json:"redirect_uri"`
				Verifier     string `json:"code_verifier"`
			}
			if c.BindJSON(&payload) == nil {
				grantType = payload.GrantType
				code = payload.Code
				clientID = payload.ClientID
				clientSecret = payload.ClientSecret
				redirectURI = payload.RedirectURI
				verifier = payload.Verifier
			}
		}
		if grantType != "authorization_code" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
			return
		}
		token, u, err := s.ExchangeOAuthCode(c.Request.Context(), clientID, clientSecret, code, redirectURI, verifier)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		resp := gin.H{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   int((30 * 24 * time.Hour).Seconds()),
			"scope":        "profile",
			"user":         u,
		}
		// OIDC：同密钥签发 id_token（aud 指向该客户端），客户端可用 JWKS 本地验签。
		if idToken, exp, ierr := s.IDToken(*u, clientID); ierr == nil && idToken != "" {
			resp["id_token"] = idToken
			resp["id_token_expires_at"] = exp
		}
		c.JSON(http.StatusOK, resp)
	})
	oauth.GET("/userinfo", func(c *gin.Context) {
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
			return
		}
		u, err := s.Authenticate(c.Request.Context(), token)
		if err != nil || u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"sub":      u.ID,
			"id":       u.ID,
			"username": u.Username,
			"role":     u.Role,
			"email":    u.Email,
		})
	})

	// OIDC 发现与 JWKS：外部服务用公钥在本地验签访问令牌/id_token，无需回调本服务。
	api.GET("/.well-known/openid-configuration", h.discovery)
	api.GET("/oidc/jwks", h.jwks)
}

// accountPageBase 是未登录时跳转的账号页；配置为空则用站点相对路径。
func (h *Handler) accountPageBase() string {
	if v := strings.TrimSpace(os.Getenv("AUTH_ACCOUNT_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return ""
}

func (h *Handler) discovery(c *gin.Context) {
	base := strings.TrimSuffix(h.store.TokenIssuerURL(), "/")
	if base == "" {
		base = strings.TrimSuffix(c.Request.URL.Scheme+c.Request.Host, "/")
	}
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"userinfo_endpoint":                     base + "/oauth/userinfo",
		"jwks_uri":                              base + "/oidc/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"profile", "email"},
		"claims_supported":                      []string{"sub", "preferred_username", "email", "role"},
	})
}

func (h *Handler) jwks(c *gin.Context) {
	if h.store.Tokens == nil {
		c.JSON(http.StatusOK, gin.H{"keys": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": []any{h.store.Tokens.PublicJWK()}})
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
		if admin && !isAdmin(u) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

// requirePermission 是管理台的细粒度闸门：权限码由权限组给出（见 store.PermissionCatalog）。
// 兼容两条旧路径：role=admin（老令牌没有 permissions 声明）与 * 通配。
func requirePermission(code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := currentUser(c)
		if u == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		if !store.HasPermission(u.Permissions, code) && !isAdmin(u) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden", "required_permission": code})
			return
		}
		c.Next()
	}
}

// isAdmin 判定管理员：* 权限、auth.* 管理权限，或历史 role=admin。
func isAdmin(u *store.User) bool {
	if u == nil {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	for _, p := range u.Permissions {
		if p == "*" || strings.HasPrefix(p, "auth.") {
			return true
		}
	}
	return false
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

func body(c *gin.Context, v any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	if err := c.ShouldBindJSON(v); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return false
	}
	return true
}

// respond 把 store 的稳定错误码映射为 HTTP 状态码；响应体统一为单一 error 字段。
func respond(c *gin.Context, v any, err error) {
	if err == nil {
		c.JSON(http.StatusOK, v)
		return
	}
	status, code := http.StatusBadRequest, err.Error()
	switch {
	case errors.Is(err, sql.ErrNoRows):
		status, code = http.StatusNotFound, "not_found"
	case code == "forbidden":
		status = http.StatusForbidden
	case code == "invalid_credentials":
		status = http.StatusUnauthorized
	case code == "version_conflict":
		status = http.StatusConflict
	case code == "invalid_token":
		status = http.StatusUnauthorized
	}
	c.JSON(status, gin.H{"error": code})
}

// rateLimiter 是按 IP 的固定窗口计数（与主仓库 setup/login 的限流口径一致）。
type bucket struct {
	mu       sync.Mutex
	start    time.Time
	n        int
	lastSeen time.Time
}

func rateLimiter(limit int, window time.Duration) gin.HandlerFunc {
	var mu sync.Mutex
	buckets := map[string]*bucket{}
	return func(c *gin.Context) {
		key := c.ClientIP()
		now := time.Now()
		mu.Lock()
		b, ok := buckets[key]
		if !ok {
			b = &bucket{start: now}
			buckets[key] = b
		}
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
