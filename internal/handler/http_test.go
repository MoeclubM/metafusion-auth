package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// 这些用例完全不碰数据库：它们验证的是切流时网关会直接命中的几个端点
// （发现文档、JWKS、准入能力）与鉴权边界（401/403 在进入业务前就被拦下）。
func newTestServer(t *testing.T) (*gin.Engine, *store.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := &store.Store{Tokens: newTestIssuer(t)}
	r := gin.New()
	New(s).Register(r)
	return r, s
}

// newTestIssuer 生成一对进程内 RSA 密钥并配好 AUTH_JWT_PRIVATE_KEY，返回可用的签发器。
// 单独抽出来是为了让需要真实数据库的用例也能拿到同一套签发器。
func newTestIssuer(t *testing.T) *store.TokenIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	t.Setenv("AUTH_JWT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	issuer, err := store.NewTokenIssuerFromEnv("https://findverse.cc/api", "metafusion")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return issuer
}

func do(t *testing.T, r *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// 发现文档两个入口必须返回同一份内容，且地址都指向 issuer 基址
// （第三方依赖任一挂载方式都能接入；不一致会让某些客户端拿到的端点 404）。
func TestDiscoveryIsIdenticalOnBothPaths(t *testing.T) {
	r, _ := newTestServer(t)
	a := do(t, r, http.MethodGet, "/.well-known/openid-configuration", "")
	b := do(t, r, http.MethodGet, "/api/.well-known/openid-configuration", "")
	if a.Code != 200 || b.Code != 200 {
		t.Fatalf("状态码 %d / %d", a.Code, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Fatalf("两个入口内容不一致:\n%s\n%s", a.Body.String(), b.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(a.Body.Bytes(), &doc); err != nil {
		t.Fatalf("发现文档不是 JSON: %v", err)
	}
	if doc["issuer"] != "https://findverse.cc/api" {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		v, _ := doc[k].(string)
		if v != "https://findverse.cc/api"+map[string]string{
			"authorization_endpoint": "/oauth/authorize",
			"token_endpoint":         "/oauth/token",
			"userinfo_endpoint":      "/oauth/userinfo",
			"jwks_uri":               "/oidc/jwks",
		}[k] {
			t.Fatalf("%s = %q，未指向 issuer 基址", k, v)
		}
	}
	if alg, _ := doc["id_token_signing_alg_values_supported"].([]any); len(alg) != 1 || alg[0] != "RS256" {
		t.Fatalf("声明了非 RS256 算法: %v", doc["id_token_signing_alg_values_supported"])
	}
}

// JWKS 两个入口返回同一把公钥，且字段齐备：其他服务本地验签全靠它。
func TestJWKSExposesSigningKey(t *testing.T) {
	r, s := newTestServer(t)
	a := do(t, r, http.MethodGet, "/api/oidc/jwks", "")
	b := do(t, r, http.MethodGet, "/.well-known/jwks.json", "")
	if a.Code != 200 || b.Code != 200 || a.Body.String() != b.Body.String() {
		t.Fatalf("JWKS 两个入口不一致: %d/%d", a.Code, b.Code)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(a.Body.Bytes(), &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("JWKS 结构不符: %v / %d keys", err, len(doc.Keys))
	}
	want := s.Tokens.PublicJWK()
	for _, k := range []string{"kid", "n", "e"} {
		if doc.Keys[0][k] != want[k] {
			t.Fatalf("JWKS 的 %s 与签发器公钥不一致", k)
		}
	}
}

// 准入能力端点：读到的是实例设置的持久化结果，默认全部关闭（fail-closed）。
// 邮件验证通道未接入，故 email_verification_enabled 恒为 false。
func TestAuthSettingsDefaultsAreClosed(t *testing.T) {
	r, _ := newTestServer(t)
	w := do(t, r, http.MethodGet, "/api/auth/settings", "")
	if w.Code != 200 {
		t.Fatalf("状态码 %d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	for _, k := range []string{"registration_enabled", "invite_required", "require_email_verification", "email_verification_enabled"} {
		if v, ok := got[k]; !ok || v != false {
			t.Fatalf("%s 应为 false，实际 %v", k, v)
		}
	}
	if got["registration_default_groups"] == nil {
		t.Fatal("缺少 registration_default_groups：注册默认组应是可配置事实，而不是写死在注册代码里")
	}
}

// 鉴权边界必须在进入业务逻辑前生效：匿名 401、角色不足 403（都不触碰数据库）。
func TestAdminEndpointsEnforceAuthBeforeBusinessLogic(t *testing.T) {
	r, s := newTestServer(t)
	if w := do(t, r, http.MethodGet, "/api/admin/users", ""); w.Code != 401 {
		t.Fatalf("匿名访问管理端应 401，实际 %d", w.Code)
	}
	editorToken, _, _, err := s.Tokens.Sign(store.User{ID: "11111111-1111-1111-1111-111111111111", Username: "kana", Role: "editor"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if w := do(t, r, http.MethodGet, "/api/admin/users", editorToken); w.Code != 403 {
		t.Fatalf("editor 访问管理端应 403，实际 %d", w.Code)
	}
}

// OAuth 令牌端点对不支持的授权类型必须在解析业务前拒绝。
func TestOAuthTokenRejectsUnsupportedGrant(t *testing.T) {
	r, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/oauth/token", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{"grant_type": {"client_credentials"}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("状态码 = %d，期望 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unsupported_grant_type") {
		t.Fatalf("错误码不符: %s", w.Body.String())
	}
}
