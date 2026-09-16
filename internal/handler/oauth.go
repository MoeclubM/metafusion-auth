package handler

// OAuth 2.0 / OIDC 授权方端点：客户端列表、授权码流程、换令牌、userinfo，
// 以及发现文档与 JWKS。路径与请求/响应形状与主仓库 catalog 包逐字一致，
// 切流时前端与第三方客户端都不需要改动；两个入口的发现文档内容完全相同。

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

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
		rawScope := c.Query("scope")
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
		if err != nil || client == nil {
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
