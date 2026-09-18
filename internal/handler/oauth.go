package handler

// OAuth 2.0 / OIDC 授权方端点：授权码流程、换令牌、userinfo，以及发现文档与 JWKS。
// 客户端列表**不在这里**：全量列表只在管理面（/api/admin/oauth/clients，受 auth.oauth.manage），
// 过去那个登录即可枚举全部 client_id / 回调地址 / 归属的 GET /api/oauth/clients 已删除。
// 路径与请求/响应形状与主仓库 catalog 包逐字一致，
// 切流时前端与第三方客户端都不需要改动；两个入口的发现文档内容完全相同。

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// oauthStore 是 OAuth 端点依赖的存储能力。生产实现是 *store.Store（New 里注入）；
// 抽成接口是为了让"authorize → 同意页 → 授权码 → 令牌 → userinfo"整条链路能在
// 没有数据库的环境里用 httptest 跑完（本仓库默认测试环境没有 PostgreSQL）。
type oauthStore interface {
	ListOAuthClients(ctx context.Context) ([]store.OAuthClient, error)
	GetOAuthClient(ctx context.Context, id string) (*store.OAuthClient, error)
	CreateOAuthCode(ctx context.Context, clientID string, userID string, redirectURI, requestedScope, challenge, method string) (string, string, error)
	ExchangeOAuthCode(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (store.OAuthGrant, error)
	OAuthUserinfo(ctx context.Context, token string) (*store.User, string, error)
	IDToken(u store.User, clientID string) (string, int64, error)
	RecordOAuthAudit(ctx context.Context, entry store.OAuthAuditEntry) error
	CreateOAuthClient(ctx context.Context, in store.OAuthClientInput, actor *store.User) (store.OAuthClient, string, error)
	UpdateOAuthClient(ctx context.Context, id string, in store.OAuthClientInput, actor *store.User) (store.OAuthClient, error)
	RotateOAuthClientSecret(ctx context.Context, id string, actor *store.User) (store.OAuthClient, string, error)
	DeleteOAuthClient(ctx context.Context, id string, actor *store.User) error
	RevokeOAuthTokensByClient(ctx context.Context, clientID string, actor *store.User) (int, error)
	RevokeOAuthTokensByUser(ctx context.Context, userID string, actor *store.User) (int, error)
	ListOAuthAudits(ctx context.Context, clientID string, limit int) ([]store.OAuthAuditEntry, error)
}

// 生产实现必须是 *store.Store：接口与实现一旦对不上，这里先编译失败。
var _ oauthStore = (*store.Store)(nil)

func (h *Handler) registerOAuth(api *gin.RouterGroup, limiter gin.HandlerFunc) {
	s := h.oauth
	oauth := api.Group("/oauth")
	oauth.GET("/authorize", limiter, func(c *gin.Context) {
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		responseType := c.Query("response_type")
		state := c.Query("state")
		rawScope := c.Query("scope")
		consent := c.Query("consent")
		if responseType != "code" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
			return
		}
		// 先校验请求本身的 scope（不支持的项直接 invalid_scope），再收敛成
		// 「客户端允许 ∩ 请求」：写进授权码与令牌的只能是这个交集。
		requested, scopeErr := store.ParseScopes(rawScope)
		if scopeErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "unsupported_scopes": store.UnsupportedScopes(rawScope), "supported_scopes": store.SupportedScopes})
			return
		}
		client, err := s.GetOAuthClient(c.Request.Context(), clientID)
		if err != nil || client == nil || client.Disabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}
		if !store.RedirectURIAllowed(client.RedirectURIs, redirectURI) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
			return
		}
		granted := store.ConvergeScopes(requested, client.Scopes)
		if len(granted) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "client_scopes": client.Scopes, "supported_scopes": store.SupportedScopes})
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
		// 发码前的三方分支：
		//   trusted 第一方 —— 跳过同意页（自动化流程不因同意页而断）；
		//   consent=allow —— 用户在同意页点过同意；
		//   consent=deny  —— 用户拒绝，带 error=access_denied 回回调地址；
		//   其它（含首次进入）—— 渲染同意页，展示 client 名称、申请 scope 与将授予的权限。
		if !client.Trusted && consent == "deny" {
			// 拒绝路径也要留痕（写审计失败不改变"拒绝"这个结果本身）。
			_ = s.RecordOAuthAudit(c.Request.Context(), store.OAuthAuditEntry{
				ActorID: u.ID, SubjectID: u.ID, ClientID: client.ID,
				Action: store.OAuthActionConsentDeny, Scopes: granted, Detail: redirectURI,
			})
			c.Redirect(http.StatusFound, oauthRedirect(redirectURI, [][2]string{{"error", "access_denied"}, {"state", state}}))
			return
		}
		if !client.Trusted && consent != "allow" {
			h.renderConsent(c, client, granted)
			return
		}
		action := store.OAuthActionConsentAllow
		if client.Trusted {
			action = store.OAuthActionTrustedAllow
		}
		// 同意结果先落审计再发码：写失败即拒绝授权——"谁把哪些 scope 授给了谁"
		// 是这次授权唯一的凭据，不能出现"码发了但查不到同意记录"。
		if err := s.RecordOAuthAudit(c.Request.Context(), store.OAuthAuditEntry{
			ActorID: u.ID, SubjectID: u.ID, ClientID: client.ID,
			Action: action, Scopes: granted, Detail: redirectURI,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_failed"})
			return
		}
		code, _, err := s.CreateOAuthCode(c.Request.Context(), clientID, u.ID, redirectURI, store.FormatScopes(granted), c.Query("code_challenge"), c.Query("code_challenge_method"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.Redirect(http.StatusFound, oauthRedirect(redirectURI, [][2]string{{"code", code}, {"state", state}}))
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
		grant, err := s.ExchangeOAuthCode(c.Request.Context(), clientID, clientSecret, code, redirectURI, verifier)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		resp := gin.H{
			"access_token": grant.Token,
			"token_type":   "Bearer",
			"expires_in":   grant.ExpiresIn,
			"scope":        grant.Scope,
			"user":         grant.User,
		}
		// OIDC：同密钥签发 id_token（aud 指向该客户端），客户端可用 JWKS 本地验签。
		if idToken, exp, ierr := s.IDToken(*grant.User, clientID); ierr == nil && idToken != "" {
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
		// 以 auth.oauth_tokens 的**存活行**为准（吊销 / 客户端停用即时生效），
		// 没有该行时回退服务端会话，保持"登录令牌也能调 userinfo"的既有行为。
		// scope 必须一并取回：返回字段由它决定（原先用 _ 丢弃，等于无视同意范围）。
		u, scope, err := s.OAuthUserinfo(c.Request.Context(), token)
		if err != nil || u == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
		c.JSON(http.StatusOK, userinfoFields(u, scope))
	})

	// 管理台：客户端管理与令牌吊销（受 auth.oauth.manage 保护）。
	h.registerOAuthAdmin(api)

	// OIDC 发现与 JWKS：外部服务用公钥在本地验签访问令牌/id_token，无需回调本服务。
	api.GET("/.well-known/openid-configuration", h.discovery)
	api.GET("/oidc/jwks", h.jwks)
}

// userinfoFields 按令牌 scope 组装 userinfo 响应：只回**被授予 scope 覆盖**的字段，
// 否则"同意页说只给 A、实际给了 A+B"，用户给出的同意就是失效的（2026-09-19 审计 S-10）。
//
//   - sub / id 恒回：第三方需要一个稳定的用户标识，也是 OIDC 的 subject；
//   - profile → username / role（账号的公开资料）；
//   - email   → email。
//
// scope 为空串是**会话令牌**的兼容分支（见 store.OAuthUserinfo 的注释）：那是用户自己的令牌、
// 不经过第三方同意流程，保持全字段以便排障；第三方令牌一定带着它被授予的 scope。
func userinfoFields(u *store.User, scope string) map[string]any {
	granted := map[string]bool{}
	for _, code := range strings.Fields(scope) {
		granted[code] = true
	}
	session := len(granted) == 0
	out := map[string]any{"sub": u.ID, "id": u.ID}
	if session || granted["profile"] {
		out["username"] = u.Username
		out["role"] = u.Role
	}
	if session || granted["email"] {
		out["email"] = u.Email
	}
	return out
}

// accountPageBase 是未登录时跳转的账号页；配置为空则用站点相对路径。
func (h *Handler) accountPageBase() string {
	if v := strings.TrimSpace(os.Getenv("AUTH_ACCOUNT_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return ""
}

func (h *Handler) discovery(c *gin.Context) {
	// 基址与开发者中心的 endpoints 同源（见 developer.go 的 issuerBase）：
	// 两处各算一遍，迟早在反代/多域名下给出不一致的地址。
	base := h.issuerBase(c)
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
		"scopes_supported":                      store.SupportedScopes,
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"claims_supported":                      []string{"sub", "preferred_username", "email", "role"},
	})
}

// oauthRedirect 把参数拼回回调地址：已有的 query 用 & 续接，键值统一转义，
// state 原样带回（第三方靠它对齐自己发起的请求）。空值参数直接跳过。
func oauthRedirect(redirectURI string, params [][2]string) string {
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	var b strings.Builder
	b.WriteString(redirectURI)
	for _, p := range params {
		if p[1] == "" {
			continue
		}
		b.WriteString(sep)
		b.WriteString(url.QueryEscape(p[0]))
		b.WriteString("=")
		b.WriteString(url.QueryEscape(p[1]))
		sep = "&"
	}
	return b.String()
}

func (h *Handler) jwks(c *gin.Context) {
	if h.store.Tokens == nil {
		c.JSON(http.StatusOK, gin.H{"keys": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": []any{h.store.Tokens.PublicJWK()}})
}
