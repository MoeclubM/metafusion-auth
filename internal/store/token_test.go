package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"
)

func newIssuer(t *testing.T, issuer, audience string) *TokenIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemText := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	t.Setenv("AUTH_JWT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(pemText))
	iss, err := NewTokenIssuerFromEnv(issuer, audience)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	if iss.Ephemeral() {
		t.Fatal("配置了持久私钥时不应使用进程内临时密钥")
	}
	return iss
}

// 令牌闭环是账号服务的地基：签发 → 验签 → 身份还原 → 注销后拒绝。
func TestTokenRoundTripAndRevocation(t *testing.T) {
	iss := newIssuer(t, "https://findverse.cc/api", "metafusion")
	u := User{ID: "11111111-1111-1111-1111-111111111111", Username: "kana", Email: "kana@example.com"}

	token, jti, exp, err := iss.Sign(u)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if token == "" || jti == "" || !exp.After(time.Now()) {
		t.Fatal("签发结果不完整")
	}
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	got := ClaimsToUser(claims)
	if got.ID != u.ID || got.Username != u.Username || got.Email != u.Email {
		t.Fatalf("身份还原不一致: %+v", got)
	}

	iss.RevokeToken(token)
	if _, err = iss.Verify(token); err == nil {
		t.Fatal("已注销的令牌仍然可用")
	}
}

// 受众与 issuer 是跨服务隔离的唯一手段：任一项不符必须拒绝。
func TestVerifyRejectsWrongIssuerOrAudience(t *testing.T) {
	iss := newIssuer(t, "https://findverse.cc/api", "metafusion")
	token, _, _, err := iss.Sign(User{ID: "u1", Username: "kana"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, tc := range []struct{ issuer, audience string }{
		{"https://evil.example/api", "metafusion"},
		{"https://findverse.cc/api", "other-service"},
	} {
		other := &TokenIssuer{issuer: tc.issuer, audience: tc.audience, revoked: map[string]int64{}, audiences: map[string]bool{tc.audience: true}, priv: iss.priv, kid: iss.kid}
		if _, err := other.Verify(token); err == nil {
			t.Fatalf("issuer=%s audience=%s 不应接受该令牌", tc.issuer, tc.audience)
		}
	}
}

// JWKS 只暴露公钥材料：外部服务靠它本地验签，kid/n/e 缺一不可。
func TestPublicJWKShape(t *testing.T) {
	iss := newIssuer(t, "https://findverse.cc/api", "metafusion")
	jwk := iss.PublicJWK()
	for _, k := range []string{"kty", "use", "alg", "kid", "n", "e"} {
		if v, ok := jwk[k]; !ok || v == "" {
			t.Fatalf("JWK 缺少 %s: %+v", k, jwk)
		}
	}
	if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" {
		t.Fatalf("JWK 算法不符合预期: %+v", jwk)
	}
}

// PKCE 按 RFC 7636 校验：S256 用 BASE64URL(SHA256(verifier))，plain 直接比对；
// 无 challenge 的存量授权码按公开客户端历史行为放行。
func TestVerifyPKCE(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFG"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !verifyPKCE("S256", challenge, verifier) {
		t.Fatal("合法的 S256 校验被拒")
	}
	if verifyPKCE("S256", challenge, verifier+"x") {
		t.Fatal("verifier 不符必须拒绝")
	}
	if !verifyPKCE("plain", "abc", "abc") {
		t.Fatal("plain 比对失败")
	}
	if verifyPKCE("plain", "abc", "abd") {
		t.Fatal("plain 不一致必须拒绝")
	}
	if verifyPKCE("S256", challenge, "") {
		t.Fatal("有 challenge 时必须提供 verifier")
	}
	if !verifyPKCE("S256", "", "") {
		t.Fatal("无 challenge 的存量授权码应放行")
	}
}

// 未配置私钥时的语义（审计 S-9）：默认拒绝启动，只有显式打开本地开发开关才允许临时密钥。
// 反向验证：把 ephemeralKeyAllowed 的默认分支改成 true（即原先的静默降级），本用例立即失败。
func TestEphemeralKeyRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("AUTH_JWT_PRIVATE_KEY", "")
	// 空值、错拼、显式关闭一律拒绝：开关写错不能把生产悄悄变回静默降级。
	for _, wrong := range []string{"", "0", "false", "yes-please", "ephemeral", "off"} {
		t.Setenv("AUTH_JWT_ALLOW_EPHEMERAL_KEY", wrong)
		if _, err := NewTokenIssuerFromEnv("https://findverse.cc/api", "metafusion"); err == nil {
			t.Fatalf("AUTH_JWT_ALLOW_EPHEMERAL_KEY=%q 时必须拒绝启动（不得静默使用进程内临时密钥）", wrong)
		}
	}
	// 显式真值：允许临时密钥，且必须被标记出来（调用方据此打 WARNING）。
	for _, right := range []string{"1", "true", "YES", "on"} {
		t.Setenv("AUTH_JWT_ALLOW_EPHEMERAL_KEY", right)
		iss, err := NewTokenIssuerFromEnv("https://findverse.cc/api", "metafusion")
		if err != nil {
			t.Fatalf("显式开关 %q 下应允许临时密钥: %v", right, err)
		}
		if !iss.Ephemeral() {
			t.Fatalf("显式开关 %q 下应标记为临时密钥（调用方据此告警）", right)
		}
		// "允许"必须真的可用：签得出、验得回。
		token, _, _, err := iss.Sign(User{ID: "11111111-1111-1111-1111-111111111111", Username: "kana"})
		if err != nil {
			t.Fatalf("临时密钥签发失败: %v", err)
		}
		if _, err := iss.Verify(token); err != nil {
			t.Fatalf("临时密钥验签失败: %v", err)
		}
	}
}
