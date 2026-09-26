package handler

// userinfo 的字段裁剪（审计 S-10）：令牌里有哪些 scope，就只回哪些 scope 覆盖的字段。
// 同一链路的内存实现，无需数据库；真实库版本见 developer_postgres_test.go / oauth_postgres_test.go。

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// 纯函数边界：只回被授予 scope 覆盖的字段。
func TestUserinfoFieldsByScope(t *testing.T) {
	u := &store.User{ID: "11111111-1111-1111-1111-111111111111", Username: "kana", Email: "kana@example.test"}
	for _, tc := range []struct {
		name    string
		scope   string
		want    []string
		missing []string
	}{
		{"空 scope", "", []string{"sub", "id"}, []string{"username", "role", "email"}},
		{"只授 email", "email", []string{"sub", "id", "email"}, []string{"username", "role"}},
		{"只授 profile", "profile", []string{"sub", "id", "username"}, []string{"role", "email"}},
		{"只授 openid", "openid", []string{"sub", "id"}, []string{"username", "role", "email"}},
		{"三项全授", "openid profile email", []string{"sub", "id", "username", "email"}, []string{"role"}},
		{"多余空白与重复", "  email  email profile ", []string{"sub", "id", "username", "email"}, []string{"role"}},
		{"未知 scope 不放行", "openid phone", []string{"sub", "id"}, []string{"username", "role", "email"}},
	} {
		got := userinfoFields(u, tc.scope)
		for _, key := range tc.want {
			if _, ok := got[key]; !ok {
				t.Errorf("%s: 缺字段 %s（%v）", tc.name, key, got)
			}
		}
		for _, key := range tc.missing {
			if v, ok := got[key]; ok {
				t.Errorf("%s: 未授予却回了 %s=%v", tc.name, key, v)
			}
		}
	}
}

// 端到端：走真实的 authorize → 令牌 → userinfo，按授予的 scope 校验响应体。
// 反向验证：把 handler 改回"恒回五项"（忽略 scope），只授 email 的那一轮立即失败。
func TestUserinfoSlicesFieldsByGrantedScope(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile", "email"}, false, "s3cret-value")
	user := store.User{ID: "99999999-9999-9999-9999-999999999999", Username: "kana", Email: "kana@example.test"}
	fake.addUser(user)
	bearer := signBearer(t, s, user)

	// grant 按请求的 scope 走一遍授权码流程，返回 userinfo 的响应体。
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
		var tokenResp struct {
			AccessToken string `json:"access_token"`
			Scope       string `json:"scope"`
		}
		decodeJSON(t, resp.Body.Bytes(), &tokenResp)
		if tokenResp.Scope != scope {
			t.Fatalf("令牌 scope = %q，期望 %q", tokenResp.Scope, scope)
		}
		w := userinfo(t, r, tokenResp.AccessToken)
		if w.Code != http.StatusOK {
			t.Fatalf("userinfo %q: %d %s", scope, w.Code, w.Body.String())
		}
		var info map[string]any
		decodeJSON(t, w.Body.Bytes(), &info)
		return info
	}

	// 只授 email：拿得到邮箱，拿不到资料；sub 恒在（第三方要稳定的用户标识）。
	emailOnly := grant("email")
	if emailOnly["email"] != user.Email {
		t.Errorf("已授予 email 就必须回 email: %v", emailOnly)
	}
	if emailOnly["sub"] != user.ID {
		t.Errorf("sub 应恒回: %v", emailOnly)
	}
	for _, absent := range []string{"username"} {
		if v, ok := emailOnly[absent]; ok {
			t.Errorf("未授予 profile 不得回 %s=%v（同意范围被放大）", absent, v)
		}
	}

	// 只授 profile：拿得到资料，拿不到邮箱。
	profileOnly := grant("profile")
	if profileOnly["username"] != user.Username {
		t.Errorf("已授予 profile 就必须回资料: %v", profileOnly)
	}
	if v, ok := profileOnly["email"]; ok {
		t.Errorf("未授予 email 不得回 email=%v", v)
	}

	// 三项全授：字段齐全（不误伤正常接入）。
	full := grant("openid profile email")
	for _, key := range []string{"sub", "id", "username", "email"} {
		if _, ok := full[key]; !ok {
			t.Errorf("全量授权下缺字段 %s: %v", key, full)
		}
	}
}
