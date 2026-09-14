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
	u := User{ID: "11111111-1111-1111-1111-111111111111", Username: "kana", Email: "kana@example.com", Role: "editor"}

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
	if got.ID != u.ID || got.Username != u.Username || got.Role != u.Role || got.Email != u.Email {
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
	token, _, _, err := iss.Sign(User{ID: "u1", Username: "kana", Role: "admin"})
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
