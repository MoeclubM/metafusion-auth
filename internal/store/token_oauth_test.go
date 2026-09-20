package store

import (
	"testing"
)

// S01：第三方 OAuth 访问令牌必须自带"无管理能力"——即使下游尚未升级验签逻辑
// （只验 aud/iss），仅凭载荷里的 role/permissions 也拿不到任何权限。
func TestSignOAuthMinimizesThirdPartyIdentity(t *testing.T) {
	iss := newIssuer(t, "https://findverse.cc/api", "metafusion")
	admin := User{ID: "11111111-1111-1111-1111-111111111111", Username: "root", Email: "root@example.test", Role: "admin", Groups: []string{"admin"}, Permissions: []string{"*"}}

	token, jti, _, err := iss.SignOAuth(admin, "third-party", []string{"profile"})
	if err != nil {
		t.Fatalf("sign oauth: %v", err)
	}
	if jti == "" {
		t.Fatal("第三方令牌同样需要 jti（吊销与审计关联）")
	}
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// 用途与授权绑定必须进载荷：下游靠它们区分会话与第三方。
	if claims.TokenUse != TokenUseOAuth {
		t.Fatalf("token_use = %q，期望 oauth", claims.TokenUse)
	}
	if claims.ClientID != "third-party" || claims.Scope != "profile" {
		t.Fatalf("授权绑定丢失: client=%q scope=%q", claims.ClientID, claims.Scope)
	}
	// aud 仍是平台受众（JWKS/issuer 配置不动），安全靠最小化载荷兜底。
	if claims.Audience != "metafusion" {
		t.Fatalf("audience = %q，期望平台受众", claims.Audience)
	}
	// 管理能力清零：role 恒为 user（防 Can 按 role 兜底），组与权限恒空。
	if claims.Role != "user" {
		t.Fatalf("role = %q，第三方令牌不得携带真实管理角色", claims.Role)
	}
	if len(claims.Groups) != 0 || len(claims.Permissions) != 0 {
		t.Fatalf("组/权限未清零: %+v", claims)
	}
	// profile 授予：username 在，未授予 email：email 不在（JWT 可被第三方直接解码，
	// userinfo 的裁剪盖不住它）。
	if claims.Username != "root" {
		t.Fatalf("已授予 profile 却拿不到 username")
	}
	if claims.Email != "" {
		t.Fatalf("未授予 email 却带出 email=%q", claims.Email)
	}

	// 还原后的身份在授权判定里必须是什么都做不了，而不是回落成 admin。
	got := ClaimsToUser(claims)
	if !got.IsThirdParty() {
		t.Fatal("第三方身份未被标记")
	}
	if Can(got, "auth.users.manage") || HasPermission(got.Permissions, "auth.users.manage") {
		t.Fatal("profile-only 第三方令牌拿到了管理能力")
	}
}

// scope 裁剪按授予集合走：email-only 拿得到邮箱、拿不到资料；openid-only 只剩 sub。
func TestSignOAuthScopeSlicing(t *testing.T) {
	iss := newIssuer(t, "https://findverse.cc/api", "metafusion")
	u := User{ID: "22222222-2222-2222-2222-222222222222", Username: "kana", Email: "kana@example.test", Role: "admin"}

	token, _, _, err := iss.SignOAuth(u, "third-party", []string{"email"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Email != u.Email {
		t.Fatalf("已授予 email 就必须带 email")
	}
	if claims.Username != "" {
		t.Fatalf("未授予 profile 不得带 username=%q", claims.Username)
	}
	if claims.Role != "user" || len(claims.Permissions) != 0 {
		t.Fatalf("email 令牌仍带管理身份: role=%q perms=%v", claims.Role, claims.Permissions)
	}

	openid, _, _, err := iss.SignOAuth(u, "third-party", []string{"openid"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	open, err := iss.Verify(openid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if open.Subject != u.ID || open.Username != "" || open.Email != "" {
		t.Fatalf("openid-only 令牌只应剩 sub: %+v", open)
	}
}

// 站内会话令牌不受影响：完整身份 + 用途标记 + 管理能力照常。
func TestSessionTokenKeepsFullIdentity(t *testing.T) {
	iss := newIssuer(t, "https://findverse.cc/api", "metafusion")
	admin := User{ID: "33333333-3333-3333-3333-333333333333", Username: "root", Email: "root@example.test", Role: "admin", Groups: []string{"admin"}, Permissions: []string{"*"}}
	token, _, _, err := iss.Sign(admin)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TokenUse != TokenUseSession {
		t.Fatalf("token_use = %q，期望 session", claims.TokenUse)
	}
	if claims.Role != "admin" || claims.Email != admin.Email || len(claims.Permissions) != 1 {
		t.Fatalf("会话身份被收窄: %+v", claims)
	}
	if !Can(ClaimsToUser(claims), "auth.users.manage") {
		t.Fatal("站内管理员会话应保留管理能力")
	}
}

// 未知用途取值直接拒收；历史令牌（无 token_use）仍按会话语义兼容。
func TestTokenUseValidation(t *testing.T) {
	for _, use := range []string{"", TokenUseSession, TokenUseOAuth, TokenUseIDToken} {
		if !validTokenUse(use) {
			t.Fatalf("%q 应合法", use)
		}
	}
	for _, use := range []string{"admin", "SESSION", "oauth2", "*"} {
		if validTokenUse(use) {
			t.Fatalf("%q 必须非法", use)
		}
	}
	// 历史会话令牌（签发时还没有 token_use 字段）解码后用途为空，仍走 role 兜底。
	legacy := &Claims{Subject: "u1", Role: "admin"}
	if !Can(ClaimsToUser(legacy), "auth.users.manage") {
		t.Fatal("历史令牌的兼容语义被破坏")
	}
}

// 最小化构造是纯函数：兑换、回退、替身三处共用同一份判定，不各写一套。
func TestOAuthTokenUserHelpers(t *testing.T) {
	u := User{ID: "u1", Username: "kana", Email: "kana@example.test", Role: "admin", Groups: []string{"admin"}, Permissions: []string{"*"}}
	min := OAuthTokenUser(u, []string{"profile"})
	if min.ID != "u1" || min.Username != "kana" || min.Email != "" || min.Role != "user" || len(min.Permissions) != 0 || len(min.Groups) != 0 {
		t.Fatalf("OAuthTokenUser 收敛不符: %+v", min)
	}
	id := IDTokenUser(u, []string{"openid", "profile", "email"})
	if id.Username != "kana" || id.Email != u.Email || id.Role != "admin" || len(id.Permissions) != 0 {
		t.Fatalf("IDTokenUser 应与 userinfo 同口径: %+v", id)
	}
	bare := IDTokenUser(u, []string{"openid"})
	if bare.Username != "" || bare.Email != "" || bare.Role != "user" {
		t.Fatalf("openid-only id_token 只应剩 sub: %+v", bare)
	}
}
