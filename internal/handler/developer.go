package handler

// 开发者中心（Developer Center）的 HTTP 契约：/api/developer/*。
//
// 与 /api/admin/oauth/* 的分工：管理台是"平台管理员治理所有客户端"（受 auth.oauth.manage 保护），
// 这里是"任何人自助登记自己的应用"（受归属保护）。两边写的是同一张表、走同一份校验，
// 差别只在授权判定：管理台按权限码，这里按 owner_user_id。
//
// 路径带 /developer 前缀而不是复用 /oauth：它对外提供的是"接入配置"（issuer、端点、
// scope 说明、自有平台清单）加"我的应用"，与授权端点是两件事，拆开也让网关路由一目了然。

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// developerStore 是开发者中心端点依赖的存储能力（生产实现是 *store.Store）。
// 抽成接口是为了让这些端点能在没有数据库的环境里用 httptest 跑完（与 oauthStore 同理）。
type developerStore interface {
	ListDeveloperApps(ctx context.Context, actor *store.User) ([]store.DeveloperApp, error)
	GetDeveloperApp(ctx context.Context, id string, actor *store.User) (*store.DeveloperApp, error)
	CreateDeveloperApp(ctx context.Context, in store.DeveloperAppInput, actor *store.User) (store.DeveloperApp, string, error)
	UpdateDeveloperApp(ctx context.Context, id string, in store.DeveloperAppInput, actor *store.User) (store.DeveloperApp, error)
	RotateDeveloperAppSecret(ctx context.Context, id string, actor *store.User) (store.DeveloperApp, string, error)
	DeleteDeveloperApp(ctx context.Context, id string, actor *store.User) error
	ListPlatformApps(ctx context.Context) ([]store.DeveloperApp, error)
}

// 生产实现必须是 *store.Store：接口与实现一旦对不上，这里先编译失败。
var _ developerStore = (*store.Store)(nil)

// developers 返回开发者中心用的存储实现：测试注入的替身优先，否则回落真实 store。
// 回落让"只换掉 oauth 替身"的既有链路用例也能注册本路由而不 panic。
func (h *Handler) developers() developerStore {
	if h.developer != nil {
		return h.developer
	}
	return h.store
}

func (h *Handler) registerDeveloper(api *gin.RouterGroup, limiter gin.HandlerFunc) {
	s := h.developers()
	authed := requireUser(false)
	group := api.Group("/developer")

	// GET /developer/overview 是开发者中心的"接入配置"：端点、scope 说明与自有平台清单。
	// 需要登录：平台清单里带 client_id 与回调地址，匿名可枚举（与 /oauth/clients 同一口径）。
	group.GET("/overview", authed, func(c *gin.Context) {
		platforms, err := s.ListPlatformApps(c.Request.Context())
		if err != nil {
			respond(c, nil, err)
			return
		}
		respond(c, gin.H{
			"issuer":                 h.issuerBase(c),
			"account_url":            h.developerAccountURL(),
			"endpoints":              h.developerEndpoints(c),
			"grant_types":            []string{"authorization_code"},
			"response_types":         []string{"code"},
			"code_challenge_methods": []string{"S256", "plain"},
			"scopes":                 ScopeCatalog(),
			"platforms":              platforms,
		}, nil)
	})

	group.GET("/apps", authed, func(c *gin.Context) {
		apps, err := s.ListDeveloperApps(c.Request.Context(), currentUser(c))
		respond(c, gin.H{"items": apps}, err)
	})
	group.POST("/apps", limiter, authed, func(c *gin.Context) {
		var in store.DeveloperAppInput
		if !body(c, &in) {
			return
		}
		app, secret, err := s.CreateDeveloperApp(c.Request.Context(), in, currentUser(c))
		if err != nil {
			respond(c, nil, err)
			return
		}
		// 明文密钥只在这一个响应里出现：库里只有 bcrypt 哈希，之后无处可取。
		respond(c, gin.H{"app": app, "client_secret": secret}, nil)
	})
	group.GET("/apps/:id", authed, func(c *gin.Context) {
		app, err := s.GetDeveloperApp(c.Request.Context(), c.Param("id"), currentUser(c))
		respond(c, gin.H{"app": app}, err)
	})
	group.PUT("/apps/:id", authed, func(c *gin.Context) {
		var in store.DeveloperAppInput
		if !body(c, &in) {
			return
		}
		app, err := s.UpdateDeveloperApp(c.Request.Context(), c.Param("id"), in, currentUser(c))
		respond(c, gin.H{"app": app}, err)
	})
	group.POST("/apps/:id/rotate-secret", limiter, authed, func(c *gin.Context) {
		app, secret, err := s.RotateDeveloperAppSecret(c.Request.Context(), c.Param("id"), currentUser(c))
		if err != nil {
			respond(c, nil, err)
			return
		}
		respond(c, gin.H{"app": app, "client_secret": secret}, nil)
	})
	group.DELETE("/apps/:id", authed, func(c *gin.Context) {
		respond(c, gin.H{"ok": true}, s.DeleteDeveloperApp(c.Request.Context(), c.Param("id"), currentUser(c)))
	})
}

// ScopeInfo 是开发者中心要展示的一项 scope：四语名称与说明。
type ScopeInfo struct {
	Code         string            `json:"code"`
	Names        map[string]string `json:"names"`
	Descriptions map[string]string `json:"descriptions"`
}

// ScopeCatalog 返回受支持 scope 的四语说明，文案**直接取同意页那一份**（consentTexts）：
// 另维护一份文档文案必然会与同意页漂移，而"文档说能读邮箱、同意页却没提"这种事
// 用户只有在授权之后才会发现。
func ScopeCatalog() []ScopeInfo {
	out := []ScopeInfo{}
	for _, code := range store.SupportedScopes {
		item := ScopeInfo{Code: code, Names: map[string]string{}, Descriptions: map[string]string{}}
		for lang, text := range consentTexts {
			if s, ok := text.Scopes[code]; ok {
				item.Names[lang] = s.Name
				item.Descriptions[lang] = s.Desc
			}
		}
		out = append(out, item)
	}
	return out
}

// issuerBase 是发现文档与接入端点的基址：取签发器的 issuer（与令牌 iss 声明同一处），
// 没配置签发器时退回请求自身的 scheme+host。
func (h *Handler) issuerBase(c *gin.Context) string {
	if h.store != nil {
		if base := strings.TrimSuffix(h.store.TokenIssuerURL(), "/"); base != "" {
			return base
		}
	}
	return strings.TrimSuffix(c.Request.URL.Scheme+c.Request.Host, "/")
}

// developerEndpoints 是接入方要写进自己配置的那几个地址，与 OIDC 发现文档同源。
func (h *Handler) developerEndpoints(c *gin.Context) gin.H {
	base := h.issuerBase(c)
	return gin.H{
		"issuer":        base,
		"authorization": base + "/oauth/authorize",
		"token":         base + "/oauth/token",
		"userinfo":      base + "/oauth/userinfo",
		"jwks":          base + "/oidc/jwks",
		"discovery":     base + "/.well-known/openid-configuration",
	}
}

// developerAccountURL 是登录页地址：AUTH_ACCOUNT_URL 未配置时给站点相对路径，
// 与 authorize 未登录时的回跳口径一致（都是"去账号页登录，带 return_to 回来"）。
func (h *Handler) developerAccountURL() string {
	if base := h.accountPageBase(); base != "" {
		return base
	}
	return "/account"
}
