package handler

import (
	"encoding/json"
	"net/http"
	"testing"
)

// 不支持的 scope 必须在触碰客户端/回调校验之前就被拒（invalid_scope），
// 并且错误体里点明是哪一项、受支持的是哪些（第三方据此改请求）。
// 本用例的 store 没有数据库连接：能通过说明拒绝发生在查库之前。
func TestAuthorizeRejectsUnsupportedScope(t *testing.T) {
	r, _ := newTestServer(t)
	w := do(t, r, http.MethodGet, "/api/oauth/authorize?client_id=demo&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&response_type=code&scope=openid+phone", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d，期望 400", w.Code)
	}
	var body struct {
		Error             string   `json:"error"`
		UnsupportedScopes []string `json:"unsupported_scopes"`
		SupportedScopes   []string `json:"supported_scopes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("错误体不是 JSON: %v / %s", err, w.Body.String())
	}
	if body.Error != "invalid_scope" {
		t.Fatalf("错误码 = %q，期望 invalid_scope", body.Error)
	}
	if len(body.UnsupportedScopes) != 1 || body.UnsupportedScopes[0] != "phone" {
		t.Fatalf("unsupported_scopes = %v", body.UnsupportedScopes)
	}
	seen := map[string]bool{}
	for _, code := range body.SupportedScopes {
		seen[code] = true
	}
	for _, code := range []string{"openid", "profile", "email"} {
		if !seen[code] {
			t.Fatalf("错误体未声明受支持的 scope %s: %v", code, body.SupportedScopes)
		}
	}
}

// 发现文档的 scopes_supported 与 PKCE 方法声明是第三方的接入依据：
// 必须与 store 的支持集合一致，且两个入口内容相同。
func TestDiscoveryAdvertisesSupportedScopesAndPKCE(t *testing.T) {
	r, _ := newTestServer(t)
	a := do(t, r, http.MethodGet, "/.well-known/openid-configuration", "")
	b := do(t, r, http.MethodGet, "/api/.well-known/openid-configuration", "")
	if a.Code != 200 || b.Code != 200 || a.Body.String() != b.Body.String() {
		t.Fatalf("两个入口不一致: %d/%d", a.Code, b.Code)
	}
	var doc struct {
		Scopes    []string `json:"scopes_supported"`
		Methods   []string `json:"code_challenge_methods_supported"`
		Endpoints []string `json:"grant_types_supported"`
	}
	if err := json.Unmarshal(a.Body.Bytes(), &doc); err != nil {
		t.Fatalf("发现文档不是 JSON: %v", err)
	}
	seen := map[string]bool{}
	for _, code := range doc.Scopes {
		seen[code] = true
	}
	for _, code := range []string{"openid", "profile", "email"} {
		if !seen[code] {
			t.Fatalf("scopes_supported 缺少 %s: %v", code, doc.Scopes)
		}
	}
	method := map[string]bool{}
	for _, m := range doc.Methods {
		method[m] = true
	}
	if !method["S256"] || !method["plain"] {
		t.Fatalf("code_challenge_methods_supported 应声明 S256 与 plain: %v", doc.Methods)
	}
}
