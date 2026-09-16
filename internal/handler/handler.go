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
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

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
}

func New(s *store.Store) *Handler { return &Handler{store: s, oauth: s, developer: s} }

// Register 挂载全部路由。限流沿用主仓库的口径：只对认证写入类接口按 IP 固定窗口限流。
func (h *Handler) Register(r *gin.Engine) {
	limiter := rateLimiter(15, time.Minute)
	api := r.Group("/api")
	api.Use(h.identity())
	h.registerAuth(api, limiter)
	h.registerOAuth(api, limiter)
	h.registerDeveloper(api, limiter)

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
	case code == "client_not_found":
		status = http.StatusNotFound
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
