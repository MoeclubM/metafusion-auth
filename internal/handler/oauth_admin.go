package handler

// 管理台的 OAuth 客户端管理与令牌吊销端点（统一受 auth.oauth.manage 保护）。
//
// 客户端读取只有管理面这一套：带 scope 白名单、启停、密钥轮换与按客户端/按用户的
// 令牌吊销。面向登录用户的"可枚举客户端列表"没有第二份（见 oauth.go 的说明）。

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/audit"
	"github.com/MoeclubM/metafusion-auth/internal/store"
)

func (h *Handler) registerOAuthAdmin(api *gin.RouterGroup) {
	s := h.oauth
	manage := requirePermission("auth.oauth.manage")

	api.GET("/admin/oauth/clients", manage, func(c *gin.Context) {
		clients, err := s.ListOAuthClients(c.Request.Context())
		respond(c, gin.H{"items": clients}, err)
	})
	api.POST("/admin/oauth/clients", manage, func(c *gin.Context) {
		var in store.OAuthClientInput
		if !body(c, &in) {
			return
		}
		client, secret, err := s.CreateOAuthClient(c.Request.Context(), in, currentUser(c))
		if err != nil {
			respond(c, nil, err)
			return
		}
		audit.Describe(c, audit.Detail{TargetType: "oauth_client", TargetID: client.ID, Changes: oauthClientChanges(nil, &client)})
		// 明文密钥只在这一个响应里出现：库里只有 bcrypt 哈希，之后无法再读。
		respond(c, gin.H{"client": client, "client_secret": secret}, nil)
	})
	api.PUT("/admin/oauth/clients/:id", manage, func(c *gin.Context) {
		var in store.OAuthClientInput
		if !body(c, &in) {
			return
		}
		before, _ := s.GetOAuthClient(c.Request.Context(), c.Param("id"))
		client, err := s.UpdateOAuthClient(c.Request.Context(), c.Param("id"), in, currentUser(c))
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "oauth_client", TargetID: client.ID, Changes: oauthClientChanges(before, &client)})
		}
		respond(c, gin.H{"client": client}, err)
	})
	api.POST("/admin/oauth/clients/:id/rotate-secret", manage, func(c *gin.Context) {
		client, secret, err := s.RotateOAuthClientSecret(c.Request.Context(), c.Param("id"), currentUser(c))
		if err != nil {
			respond(c, nil, err)
			return
		}
		audit.Describe(c, audit.Detail{TargetType: "oauth_client", TargetID: client.ID,
			Changes: map[string]any{"secret_rotated": true}})
		respond(c, gin.H{"client": client, "client_secret": secret}, nil)
	})
	api.DELETE("/admin/oauth/clients/:id", manage, func(c *gin.Context) {
		before, _ := s.GetOAuthClient(c.Request.Context(), c.Param("id"))
		err := s.DeleteOAuthClient(c.Request.Context(), c.Param("id"), currentUser(c))
		audit.Describe(c, audit.Detail{TargetType: "oauth_client", TargetID: c.Param("id"), Changes: oauthClientChanges(before, nil)})
		respond(c, gin.H{"ok": true}, err)
	})

	// 吊销：按客户端（某个第三方站点的全部授权）或按用户（某个人给出去的全部授权）。
	// 只删 oauth_tokens 的存活行（加内存 jti 注销），不动该用户自己的服务端会话——
	// 那是 /api/auth/logout-all 的职责。
	api.POST("/admin/oauth/clients/:id/revoke-tokens", manage, func(c *gin.Context) {
		n, err := s.RevokeOAuthTokensByClient(c.Request.Context(), c.Param("id"), currentUser(c))
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "oauth_client", TargetID: c.Param("id"),
				Changes: map[string]any{"revoked": n}})
		}
		respond(c, gin.H{"revoked": n}, err)
	})
	api.POST("/admin/users/:id/revoke-oauth-tokens", manage, func(c *gin.Context) {
		n, err := s.RevokeOAuthTokensByUser(c.Request.Context(), c.Param("id"), currentUser(c))
		if err == nil {
			audit.Describe(c, audit.Detail{TargetType: "user", TargetID: c.Param("id"),
				Changes: map[string]any{"revoked": n}})
		}
		respond(c, gin.H{"revoked": n}, err)
	})

	// 审计：谁在什么时候同意/拒绝了哪个客户端、授了哪些 scope（排障与合规核对用）。
	api.GET("/admin/oauth/audits", manage, func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.Query("limit"))
		items, err := s.ListOAuthAudits(c.Request.Context(), c.Query("client_id"), limit)
		respond(c, gin.H{"items": items}, err)
	})
}
