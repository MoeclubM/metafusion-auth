package handler

// 个人访问令牌（PAT）的 HTTP 契约：/api/auth/tokens*。
//
// 三条自助端点（创建 / 列出 / 吊销）需登录，且只动本人：路径里没有别人的 user id，
// 归属判定就是"当前登录身份"本身（与 /api/auth/oauth-grants 同一口径）。
//
// 内省端点 POST /api/auth/tokens/introspect 是给**下游服务**用的：token 放在请求体里，
// 调用方不需要也不该带其它凭据，因此它既不读 Cookie、也不下发 mf_session——PAT 不是登录态，
// 拿它当 Bearer 打 /api/auth/* 一律 401（"PAT 不能再创建 PAT"就是这么成立的）。

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// patStore 是 PAT 端点依赖的存储能力（生产实现是 *store.Store）。
// 抽成接口是为了让这几条端点能在没有数据库的环境里用 httptest 跑完（与 oauthStore 同理）。
type patStore interface {
	CreatePersonalAccessToken(ctx context.Context, actor *store.User, name string, scopes []string, expiresIn time.Duration) (store.PersonalAccessToken, string, error)
	ListPersonalAccessTokens(ctx context.Context, userID string) ([]store.PersonalAccessToken, error)
	RevokePersonalAccessToken(ctx context.Context, userID, id string) error
	IntrospectPersonalAccessToken(ctx context.Context, token string) (*store.PATPrincipal, error)
}

// 生产实现必须是 *store.Store：接口与实现一旦对不上，这里先编译失败。
var _ patStore = (*store.Store)(nil)

// personalTokens 返回 PAT 端点用的存储实现：测试注入的替身优先，否则回落真实 store。
func (h *Handler) personalTokens() patStore {
	if h.tokens != nil {
		return h.tokens
	}
	return h.store
}

const (
	// maxPATExpiryDays 是 expires_in_days 的上限（10 年）。再长就等于"永不过期"，
	// 却会让界面显示一个没人看的日期；真要不限期就别传这个字段（expires_at 留空）。
	maxPATExpiryDays = 3650
	// patIntrospectPerIPPerMinute 与 patIntrospectPerTokenPerMinute 是内省的双维度限流：
	// IP 维度挡住"拿一堆无效令牌扫"的探测，令牌维度挡住"同一张有效令牌被高频重放"
	// （正常下游有 60 秒结果缓存，60 次/分钟已非常宽松）。
	//
	// 两个维度都不读实例设置：auth_rate_limit_enabled / _per_minute 是**认证写入类端点**的
	// 开关，内省是读语义——运维为了压注册洪水关掉写入限流，不该连带把下游的鉴权限流松开。
	patIntrospectPerIPPerMinute    = 600
	patIntrospectPerTokenPerMinute = 60
	// patIntrospectWindow 是上面两个限额的固定窗口长度。
	patIntrospectWindow = time.Minute
)

func (h *Handler) registerTokens(api *gin.RouterGroup, limiter gin.HandlerFunc) {
	s := h.personalTokens()
	authed := requireUser(false)
	byIP := newPATBuckets(patIntrospectPerIPPerMinute)
	byToken := newPATBuckets(patIntrospectPerTokenPerMinute)

	api.GET("/auth/tokens", authed, func(c *gin.Context) {
		items, err := s.ListPersonalAccessTokens(c.Request.Context(), currentUser(c).ID)
		respond(c, gin.H{"items": items}, err)
	})

	// 创建：需登录（自助），限流沿用认证写入那一套（默认 15 次/分钟，按实例设置）。
	// 201 的响应体是**明文唯一出现的地方**：库里只有哈希，之后任何路径都取不回。
	api.POST("/auth/tokens", limiter, authed, func(c *gin.Context) {
		var in struct {
			Name          string   `json:"name"`
			Scopes        []string `json:"scopes"`
			ExpiresInDays int      `json:"expires_in_days"`
		}
		if !body(c, &in) {
			return
		}
		// 0 或缺字段 = 永不过期（expires_at 留空）；负数/超上限一律拒绝，
		// 免得"填 -1 以为是永不过期"这类歧义悄悄落库。
		if in.ExpiresInDays < 0 || in.ExpiresInDays > maxPATExpiryDays {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_expiry"})
			return
		}
		var ttl time.Duration
		if in.ExpiresInDays > 0 {
			ttl = time.Duration(in.ExpiresInDays) * 24 * time.Hour
		}
		item, plain, err := s.CreatePersonalAccessToken(c.Request.Context(), currentUser(c), in.Name, in.Scopes, ttl)
		if err != nil {
			respond(c, nil, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"token": plain, "item": item})
	})

	// 吊销：只写 revoked_at，幂等（已经吊销过再删仍然 200）。生效窗口见内省注释。
	api.DELETE("/auth/tokens/:id", limiter, authed, func(c *gin.Context) {
		respond(c, gin.H{"ok": true}, s.RevokePersonalAccessToken(c.Request.Context(), currentUser(c).ID, c.Param("id")))
	})

	// 内省：无凭据、无 Cookie、无状态写入。限流按"来源 IP"与"令牌哈希"双维度，
	// 因此这里先解析请求体（token 就是限流键之一），再判定。
	api.POST("/auth/tokens/introspect", func(c *gin.Context) {
		var in struct {
			Token string `json:"token"`
		}
		if !body(c, &in) {
			return
		}
		now := time.Now()
		if byIP.use(c.ClientIP(), now) || byToken.use(store.HashPersonalAccessToken(in.Token), now) {
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		p, err := s.IntrospectPersonalAccessToken(c.Request.Context(), in.Token)
		switch {
		case err == nil:
			// 结果里含身份与权限，代理/浏览器缓存都会让"吊销后仍在用"的窗口变长。
			c.Header("Cache-Control", "no-store")
			c.JSON(http.StatusOK, gin.H{
				"valid": true, "user_id": p.UserID, "username": p.Username, "role": p.Role,
				"permissions": p.Permissions, "scopes": p.Scopes,
				"token_prefix": p.TokenPrefix, "expires_at": p.ExpiresAt,
			})
		case errors.Is(err, store.ErrInvalidPAT):
			// 无效 / 已吊销 / 已过期 / 账号被封：同一状态码 + 同一个机器码，不区分原因。
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		default:
			// 读不动库不是"令牌无效"：503 让下游与运维都能看出是基础设施问题。
			// 下游必须把非 200 一并当作"不认这个令牌"（fail-closed）。
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "introspection_unavailable"})
		}
	})
}

// patBuckets 是一组按 key 计数的固定窗口桶（内省的两个维度各一个实例）。
// 与 handler.go 的认证限流同一口径：窗口固定一分钟，超限即拒。
type patBuckets struct {
	mu      sync.Mutex
	limit   int
	buckets map[string]*bucket
}

func newPATBuckets(limit int) *patBuckets {
	return &patBuckets{limit: limit, buckets: map[string]*bucket{}}
}

// use 记一次请求并报告是否超限。清理放在查桶之前：先建新桶再清理，
// 会把刚建出来、尚未记 lastSeen 的那个桶删掉，限流就失准了。
func (b *patBuckets) use(key string, now time.Time) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buckets) > 4096 {
		for k, v := range b.buckets {
			if now.Sub(v.lastSeen) > patIntrospectWindow {
				delete(b.buckets, k)
			}
		}
	}
	bk, ok := b.buckets[key]
	if !ok {
		bk = &bucket{start: now, lastSeen: now}
		b.buckets[key] = bk
	}
	if now.Sub(bk.start) > patIntrospectWindow {
		bk.start, bk.n = now, 0
	}
	bk.n++
	bk.lastSeen = now
	return bk.n > b.limit
}
