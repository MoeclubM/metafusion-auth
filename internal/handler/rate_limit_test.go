package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// 限流的速率与开关来自实例设置，而不是构造时的常量。
// 这里注入策略验证中间件本身：关掉就完全不计数、上限 N 就按 N 拦、缺省与接线前一致（15/分钟）。
// 空体 POST /api/auth/login 会在业务前被 400 拦下，正好只观察限流行为（不碰数据库）。
func TestRateLimiterHonoursPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	newServer := func(policy func(context.Context) (bool, int)) *gin.Engine {
		s := &store.Store{Tokens: newTestIssuer(t)}
		h := New(s)
		if policy != nil {
			h.rateLimitPolicy = policy
		}
		r := gin.New()
		h.Register(r)
		return r
	}
	post := func(r *gin.Engine) int {
		return doJSON(t, r, http.MethodPost, "/api/auth/login", "", "").Code
	}

	// 上限 2/分钟：前两次照常进业务（无体 → 400），第三次被限流拦下。
	r := newServer(func(context.Context) (bool, int) { return true, 2 })
	for i := 0; i < 2; i++ {
		if code := post(r); code != http.StatusBadRequest {
			t.Fatalf("第 %d 次应进业务（400），实际 %d", i+1, code)
		}
	}
	w := doJSON(t, r, http.MethodPost, "/api/auth/login", "", "")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("超过上限应 429，实际 %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 必须带 Retry-After，客户端才知道退避多久")
	}
	var body struct {
		Error string `json:"error"`
	}
	decodeInto(t, w, &body)
	if body.Error != "rate_limited" {
		t.Fatalf("错误码应为 rate_limited，实际 %q", body.Error)
	}

	// 关掉限流：连打 50 次都不该出现 429。
	off := newServer(func(context.Context) (bool, int) { return false, 15 })
	for i := 0; i < 50; i++ {
		if code := post(off); code == http.StatusTooManyRequests {
			t.Fatalf("关闭限流后第 %d 次仍被拦下", i+1)
		}
	}
	// 不注入策略时用默认值（与接线前的硬编码 15/分钟一致）：第 16 次被拦。
	def := newServer(nil)
	for i := 0; i < store.DefaultRateLimitPerMinute; i++ {
		if code := post(def); code == http.StatusTooManyRequests {
			t.Fatalf("默认上限内第 %d 次不该被拦", i+1)
		}
	}
	if code := post(def); code != http.StatusTooManyRequests {
		t.Fatalf("默认策略应在第 %d 次拦下，实际 %d", store.DefaultRateLimitPerMinute+1, code)
	}
}
