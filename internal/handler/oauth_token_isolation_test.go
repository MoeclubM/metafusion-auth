package handler

// S01 签发侧验收（无数据库）：profile-only 第三方令牌打本站管理路由必须 403；
// token 响应的 user 与 id_token 同样按授予 scope 裁剪，不向第三方泄露未授权 email。

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// 第三方令牌（profile-only，持有人是管理员）打管理路由一律 403：
// 拒绝发生在业务逻辑之前（与既有 editor 403 用例同口径，不触碰数据库）。
func TestThirdPartyTokenDeniedOnAdminRoutes(t *testing.T) {
	r, s := newTestServer(t)
	admin := store.User{ID: "11111111-1111-1111-1111-111111111111", Username: "root", Email: "root@example.test", Permissions: []string{"*"}}
	third, _, _, err := s.Tokens.SignOAuth(admin, "third-party", []string{"profile"})
	if err != nil {
		t.Fatalf("sign oauth: %v", err)
	}
	for _, path := range []string{"/api/admin/users", "/api/admin/settings", "/api/admin/groups", "/api/admin/oauth/clients"} {
		if w := do(t, r, http.MethodGet, path, third); w.Code != http.StatusForbidden {
			t.Fatalf("%s 用第三方令牌应 403，实际 %d：%s", path, w.Code, w.Body.String())
		}
	}
	// id_token（aud 指向客户端，本服务验签接受已登记受众）同样不得进管理路由。
	idToken, _, err := s.Tokens.SignForAudience(store.IDTokenUser(admin, []string{"openid", "profile", "email"}), "third-party")
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	if w := do(t, r, http.MethodGet, "/api/admin/users", idToken); w.Code != http.StatusForbidden {
		t.Fatalf("id_token 打管理路由应 403，实际 %d：%s", w.Code, w.Body.String())
	}
	// 对照：匿名 401（既有口径不变）。
	if w := do(t, r, http.MethodGet, "/api/admin/users", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("匿名应 401，实际 %d", w.Code)
	}
}

// 走完整授权码链路：token 响应的 user 按 scope 裁剪，未授予 email 时不得出现。
func TestTokenResponseUserSlicedByGrantedScope(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile", "email"}, false, "s3cret-value")
	admin := store.User{ID: "99999999-9999-9999-9999-999999999999", Username: "root", Email: "root@example.test"}
	fake.addUser(admin)
	bearer := signBearer(t, s, admin)

	grant := func(scope string) map[string]any {
		t.Helper()
		code := codeFromRedirect(t, authorize(t, r, bearer,
			"client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+
				"&response_type=code&scope="+url.QueryEscape(scope)+"&consent=allow"), chainCallback)
		resp := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {"third-party"}, "client_secret": {"s3cret-value"}})
		if resp.Code != http.StatusOK {
			t.Fatalf("换令牌 %q: %d %s", scope, resp.Code, resp.Body.String())
		}
		var body map[string]any
		decodeJSON(t, resp.Body.Bytes(), &body)
		return body
	}

	// profile-only：user 里有 username、没有 email 和 role。
	profileOnly := grant("profile")
	user, _ := profileOnly["user"].(map[string]any)
	if user == nil {
		t.Fatalf("token 响应缺少 user：%v", profileOnly)
	}
	if user["username"] != "root" {
		t.Errorf("已授予 profile 就必须回 username：%v", user)
	}
	// user 是 User 结构体形状（email/username 键恒在，与 /api/auth/me 同形）：
	// 断言的是值为空，而不是键缺席——空串不携带任何信息。
	if email, _ := user["email"].(string); email != "" {
		t.Errorf("未授予 email 不得在 token 响应里回 email：%v", user)
	}
	if _, ok := user["role"]; ok {
		t.Errorf("token 响应的 user 不得包含 role：%v", user)
	}
	// access_token 自身同样不携带 email：第三方可直接解码 JWT。
	access, _ := profileOnly["access_token"].(string)
	if email := jwtClaim(t, access, "email"); email != nil {
		t.Errorf("profile-only 访问令牌不得携带 email claim：%v", email)
	}
	if role := jwtClaim(t, access, "role"); role != nil {
		t.Errorf("访问令牌不得携带 role claim")
	}
	if use := jwtClaim(t, access, "token_use"); use != "oauth" {
		t.Errorf("访问令牌必须标记 token_use=oauth，实际 %v", use)
	}
	// id_token 按 scope 裁剪：profile-only 的 id_token 不得带 email。
	if idToken, ok := profileOnly["id_token"].(string); ok && idToken != "" {
		if email := jwtClaim(t, idToken, "email"); email != nil {
			t.Errorf("profile-only id_token 不得带 email claim：%v", email)
		}
	} else {
		t.Errorf("换令牌应附 id_token：%v", profileOnly)
	}

	// email-only：user 里有 email、没有 username。
	emailOnly := grant("email")
	eu, _ := emailOnly["user"].(map[string]any)
	if eu == nil || eu["email"] != "root@example.test" {
		t.Errorf("已授予 email 就必须回 email：%v", eu)
	}
	if name, _ := eu["username"].(string); name != "" {
		t.Errorf("未授予 profile 不得回 username：%v", eu)
	}
}

// jwtClaim 只解码载荷段不验签：断言的是第三方直接能看到什么，验签由其它用例覆盖。
func jwtClaim(t *testing.T, token, key string) any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("不是 JWT：%s", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("载荷解码失败: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("载荷不是 JSON: %v", err)
	}
	return claims[key]
}
