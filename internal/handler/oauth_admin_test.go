package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// doJSON 发一个可带 JSON 体的管理请求。
func doJSON(t *testing.T, r *gin.Engine, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeInto(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("响应不是 JSON: %v / %s", err, w.Body.String())
	}
}

// 管理面权限边界：匿名 401、无码成员 403（都在进入业务之前拦下），持码者可用。
func TestOAuthAdminEndpointsEnforcePermission(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	_ = fake
	member := store.User{ID: "77777777-7777-7777-7777-777777777777", Username: "member", Role: "user", Permissions: []string{"community.post.create"}}
	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Role: "user", Permissions: []string{"auth.oauth.manage"}}
	memberBearer := signBearer(t, s, member)
	opsBearer := signBearer(t, s, ops)

	requests := []struct{ method, path string }{
		{http.MethodGet, "/api/admin/oauth/clients"},
		{http.MethodPost, "/api/admin/oauth/clients"},
		{http.MethodPut, "/api/admin/oauth/clients/demo"},
		{http.MethodPost, "/api/admin/oauth/clients/demo/rotate-secret"},
		{http.MethodDelete, "/api/admin/oauth/clients/demo"},
		{http.MethodPost, "/api/admin/oauth/clients/demo/revoke-tokens"},
		{http.MethodPost, "/api/admin/users/99999999-9999-9999-9999-999999999999/revoke-oauth-tokens"},
		{http.MethodGet, "/api/admin/oauth/audits"},
	}
	for _, req := range requests {
		if w := doJSON(t, r, req.method, req.path, "", "{}"); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 匿名应 401，实际 %d", req.method, req.path, w.Code)
		}
		if w := doJSON(t, r, req.method, req.path, memberBearer, "{}"); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s 无码成员应 403，实际 %d", req.method, req.path, w.Code)
		}
	}
	// 持 auth.oauth.manage 即可管理（不需要 role=admin）
	if w := doJSON(t, r, http.MethodGet, "/api/admin/oauth/clients", opsBearer, ""); w.Code != http.StatusOK {
		t.Fatalf("持码者读列表应 200，实际 %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, r, http.MethodGet, "/api/admin/oauth/audits", opsBearer, ""); w.Code != http.StatusOK {
		t.Fatalf("持码者读审计应 200，实际 %d %s", w.Code, w.Body.String())
	}
}

// 创建客户端：明文密钥只返回一次，之后的列表接口里既没有明文也没有哈希；非法输入逐项拒绝。
func TestOAuthClientCreateReturnsSecretOnce(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Role: "user", Permissions: []string{"auth.oauth.manage"}}
	opsBearer := signBearer(t, s, ops)

	body := `{"client_id":"mfc-demo-1","name":"演示第三方站点","redirect_uris":["https://client.example/auth/callback"],"scopes":["openid","profile"],"trusted":false}`
	w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients", opsBearer, body)
	if w.Code != http.StatusOK {
		t.Fatalf("创建状态码 = %d：%s", w.Code, w.Body.String())
	}
	var created struct {
		Client struct {
			ID           string   `json:"client_id"`
			Name         string   `json:"name"`
			RedirectURIs []string `json:"redirect_uris"`
			Scopes       []string `json:"scopes"`
			Trusted      bool     `json:"trusted"`
		} `json:"client"`
		ClientSecret string `json:"client_secret"`
	}
	decodeInto(t, w, &created)
	if created.Client.ID != "mfc-demo-1" || created.Client.Name != "演示第三方站点" || created.Client.Trusted {
		t.Fatalf("创建结果不符: %+v", created.Client)
	}
	if len(created.ClientSecret) != 43 {
		t.Fatalf("明文密钥长度 = %d，期望 43：%q", len(created.ClientSecret), created.ClientSecret)
	}
	// 列表接口（管理面与既有登录后列表）都不得出现明文或哈希。
	for _, path := range []string{"/api/admin/oauth/clients", "/api/oauth/clients"} {
		w = doJSON(t, r, http.MethodGet, path, opsBearer, "")
		if w.Code != http.StatusOK {
			t.Fatalf("读 %s 失败: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), created.ClientSecret) {
			t.Fatalf("%s 泄露了明文密钥", path)
		}
		if strings.Contains(w.Body.String(), "$2") || strings.Contains(w.Body.String(), "secret_hash") {
			t.Fatalf("%s 泄露了密钥哈希", path)
		}
	}
	// 非法输入：通配回调、越权 scope、重名 id、非法 id、空名
	for _, tc := range []struct{ name, body, wantErr string }{
		{"通配回调", `{"client_id":"mfc-bad-1","name":"通配","redirect_uris":["https://*.client.example/cb"]}`, "invalid_redirect_uri"},
		{"相对回调", `{"client_id":"mfc-bad-2","name":"相对","redirect_uris":["/cb"]}`, "invalid_redirect_uri"},
		{"越权 scope", `{"client_id":"mfc-bad-3","name":"越权","redirect_uris":["https://client.example/cb"],"scopes":["openid","phone"]}`, "invalid_scope"},
		{"空白名单 scope", `{"client_id":"mfc-bad-4","name":"空","redirect_uris":["https://client.example/cb"],"scopes":[]}`, "invalid_scopes"},
		{"重复 id", `{"client_id":"mfc-demo-1","name":"重复","redirect_uris":["https://client.example/cb"]}`, "client_exists"},
		{"非法 id", `{"client_id":"mfc/../etc","name":"非法","redirect_uris":["https://client.example/cb"]}`, "invalid_client_id"},
		{"空名", `{"client_id":"mfc-bad-5","redirect_uris":["https://client.example/cb"]}`, "invalid_client_name"},
	} {
		w = doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients", opsBearer, tc.body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.wantErr) {
			t.Fatalf("%s 应 400 %s，实际 %d %s", tc.name, tc.wantErr, w.Code, w.Body.String())
		}
	}
	if len(fake.clients) != 1 {
		t.Fatalf("只应有 1 个客户端被创建，实际 %d", len(fake.clients))
	}
}

// 更新客户端：改名/白名单/scope/trusted/启停都生效，且 trusted=true 之后跳过同意页。
func TestOAuthClientUpdateAndTrustedSkipsConsent(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile"}, false, "s3cret-value")
	user := store.User{ID: "99999999-1111-1111-1111-111111111111", Username: "kana", Role: "user"}
	fake.addUser(user)
	userBearer := signBearer(t, s, user)
	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Role: "user", Permissions: []string{"auth.oauth.manage"}}
	opsBearer := signBearer(t, s, ops)

	// 未受信：要先过同意页
	authQuery := "client_id=third-party&redirect_uri=" + url.QueryEscape(chainCallback) + "&response_type=code&scope=profile"
	if w := authorize(t, r, userBearer, authQuery); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<!doctype html>") {
		t.Fatalf("未受信客户端应先出同意页，实际 %d", w.Code)
	}

	// 改成受信 + 改名 + 换 scope 白名单
	w := doJSON(t, r, http.MethodPut, "/api/admin/oauth/clients/third-party", opsBearer,
		`{"name":"改名后的站点","trusted":true,"scopes":["profile","email"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("更新失败: %d %s", w.Code, w.Body.String())
	}
	var updated struct {
		Client store.OAuthClient `json:"client"`
	}
	decodeInto(t, w, &updated)
	if updated.Client.Name != "改名后的站点" || !updated.Client.Trusted {
		t.Fatalf("更新结果不符: %+v", updated.Client)
	}
	// 受信后直接回码（不再渲染同意页），且 scope 收敛按新白名单
	loc := authorize(t, r, userBearer, authQuery).Header().Get("Location")
	if strings.Contains(loc, "<html") {
		t.Fatalf("受信客户端不应渲染同意页: %s", loc)
	}
	code := codeFromRedirect(t, authorize(t, r, userBearer, authQuery), chainCallback)
	resp := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"third-party"}, "client_secret": {"s3cret-value"}})
	if resp.Code != http.StatusOK {
		t.Fatalf("换码失败: %d %s", resp.Code, resp.Body.String())
	}
	// 非法更新逐项拒绝；不存在的客户端 404
	for _, tc := range []struct{ name, path, body, want string }{
		{"通配回调", "/api/admin/oauth/clients/third-party", `{"redirect_uris":["https://*.client.example/cb"]}`, "invalid_redirect_uri"},
		{"空名", "/api/admin/oauth/clients/third-party", `{"name":"  "}`, "invalid_client_name"},
		{"空 scope", "/api/admin/oauth/clients/third-party", `{"scopes":[]}`, "invalid_scopes"},
	} {
		if w := doJSON(t, r, http.MethodPut, tc.path, opsBearer, tc.body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s 应 400 %s，实际 %d %s", tc.name, tc.want, w.Code, w.Body.String())
		}
	}
	if w := doJSON(t, r, http.MethodPut, "/api/admin/oauth/clients/nope", opsBearer, `{"name":"x"}`); w.Code != http.StatusNotFound {
		t.Fatalf("不存在的客户端应 404，实际 %d %s", w.Code, w.Body.String())
	}
}

// 密钥轮换：返回新明文一次，老密钥立刻失效。
func TestRotateSecretInvalidatesOldSecret(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	user := store.User{ID: "99999999-2222-2222-2222-222222222222", Username: "kana", Role: "user"}
	fake.addUser(user)
	userBearer := signBearer(t, s, user)
	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Role: "user", Permissions: []string{"auth.oauth.manage"}}
	opsBearer := signBearer(t, s, ops)

	w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients", opsBearer,
		`{"client_id":"mfc-rotate-1","name":"轮换站点","redirect_uris":["`+chainCallback+`"],"scopes":["openid"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("创建失败: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ClientSecret string `json:"client_secret"`
	}
	decodeInto(t, w, &created)
	authQuery := "client_id=mfc-rotate-1&redirect_uri=" + url.QueryEscape(chainCallback) + "&response_type=code&scope=openid&consent=allow"

	w = doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients/mfc-rotate-1/rotate-secret", opsBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("轮换失败: %d %s", w.Code, w.Body.String())
	}
	var rotated struct {
		ClientSecret string `json:"client_secret"`
	}
	decodeInto(t, w, &rotated)
	if rotated.ClientSecret == "" || rotated.ClientSecret == created.ClientSecret {
		t.Fatalf("轮换必须换出新的明文密钥: %q", rotated.ClientSecret)
	}

	code := codeFromRedirect(t, authorize(t, r, userBearer, authQuery), chainCallback)
	old := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"mfc-rotate-1"}, "client_secret": {created.ClientSecret}})
	if old.Code != http.StatusBadRequest || !strings.Contains(old.Body.String(), "invalid_client_secret") {
		t.Fatalf("轮换后老密钥必须失效，实际 %d %s", old.Code, old.Body.String())
	}
	// 失败不消耗授权码：新密钥仍能换到令牌
	fresh := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"mfc-rotate-1"}, "client_secret": {rotated.ClientSecret}})
	if fresh.Code != http.StatusOK {
		t.Fatalf("新密钥应可用: %d %s", fresh.Code, fresh.Body.String())
	}
	if w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients/nope/rotate-secret", opsBearer, ""); w.Code != http.StatusNotFound {
		t.Fatalf("轮换不存在的客户端应 404，实际 %d", w.Code)
	}
}

// 删除：第一方种子客户端不可删（会被启动时种子复活），普通客户端删除后立刻不能再用。
func TestDeleteClientAndSeededGuard(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("metafusion-forum", "MetaFusion 社区论坛", []string{chainCallback}, []string{"profile"}, true, "")
	user := store.User{ID: "99999999-3333-3333-3333-333333333333", Username: "kana", Role: "user"}
	fake.addUser(user)
	userBearer := signBearer(t, s, user)
	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Role: "user", Permissions: []string{"auth.oauth.manage"}}
	opsBearer := signBearer(t, s, ops)

	if w := doJSON(t, r, http.MethodDelete, "/api/admin/oauth/clients/metafusion-forum", opsBearer, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "seeded_client_immutable") {
		t.Fatalf("种子客户端不可删，实际 %d %s", w.Code, w.Body.String())
	}
	w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients", opsBearer,
		`{"client_id":"mfc-drop-1","name":"待删站点","redirect_uris":["`+chainCallback+`"],"scopes":["profile"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("创建失败: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, r, http.MethodDelete, "/api/admin/oauth/clients/mfc-drop-1", opsBearer, ""); w.Code != http.StatusOK {
		t.Fatalf("删除失败: %d %s", w.Code, w.Body.String())
	}
	if w := authorize(t, r, userBearer, "client_id=mfc-drop-1&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=profile"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_client") {
		t.Fatalf("删除后的客户端不能再发起授权，实际 %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, r, http.MethodDelete, "/api/admin/oauth/clients/mfc-drop-1", opsBearer, ""); w.Code != http.StatusNotFound {
		t.Fatalf("重复删除应 404，实际 %d", w.Code)
	}
}

// 吊销：按客户端与按用户吊销之后，userinfo 立刻拒绝；停用同样让已有令牌失效。
func TestRevokeTokensRejectsUserinfo(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("first-party", "第一方站点", []string{chainCallback}, []string{"profile"}, true, "")
	user := store.User{ID: "99999999-4444-4444-4444-444444444444", Username: "kana", Email: "kana@example.test", Role: "user"}
	fake.addUser(user)
	userBearer := signBearer(t, s, user)
	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Role: "user", Permissions: []string{"auth.oauth.manage"}}
	opsBearer := signBearer(t, s, ops)
	authQuery := "client_id=first-party&redirect_uri=" + url.QueryEscape(chainCallback) + "&response_type=code&scope=profile"

	issue := func(t *testing.T) string {
		t.Helper()
		code := codeFromRedirect(t, authorize(t, r, userBearer, authQuery), chainCallback)
		resp := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"first-party"}})
		if resp.Code != http.StatusOK {
			t.Fatalf("换码失败: %d %s", resp.Code, resp.Body.String())
		}
		var body struct {
			AccessToken string `json:"access_token"`
		}
		decodeInto(t, resp, &body)
		return body.AccessToken
	}

	tokenA, tokenB := issue(t), issue(t)
	if w := userinfo(t, r, tokenA); w.Code != http.StatusOK {
		t.Fatalf("吊销前 userinfo 应可用: %d", w.Code)
	}
	// 按客户端吊销：两枚都失效
	w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients/first-party/revoke-tokens", opsBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("按客户端吊销失败: %d %s", w.Code, w.Body.String())
	}
	var revoked struct {
		Revoked int `json:"revoked"`
	}
	decodeInto(t, w, &revoked)
	if revoked.Revoked != 2 {
		t.Fatalf("应按客户端吊销 2 枚，实际 %d", revoked.Revoked)
	}
	for _, token := range []string{tokenA, tokenB} {
		if w := userinfo(t, r, token); w.Code != http.StatusUnauthorized {
			t.Fatalf("吊销后 userinfo 必须 401，实际 %d", w.Code)
		}
	}
	// 按用户吊销：新令牌也失效
	tokenC := issue(t)
	w = doJSON(t, r, http.MethodPost, "/api/admin/users/"+user.ID+"/revoke-oauth-tokens", opsBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("按用户吊销失败: %d %s", w.Code, w.Body.String())
	}
	decodeInto(t, w, &revoked)
	if revoked.Revoked < 1 {
		t.Fatalf("按用户吊销至少 1 枚，实际 %d", revoked.Revoked)
	}
	if w := userinfo(t, r, tokenC); w.Code != http.StatusUnauthorized {
		t.Fatalf("按用户吊销后 userinfo 必须 401，实际 %d", w.Code)
	}
	// 停用客户端：新令牌也取不到 userinfo
	tokenD := issue(t)
	body := `{"disabled":true}`
	if w := doJSON(t, r, http.MethodPut, "/api/admin/oauth/clients/first-party", opsBearer, body); w.Code != http.StatusOK {
		t.Fatalf("停用失败: %d %s", w.Code, w.Body.String())
	}
	if w := userinfo(t, r, tokenD); w.Code != http.StatusUnauthorized {
		t.Fatalf("停用后 userinfo 必须 401，实际 %d", w.Code)
	}
	if w := authorize(t, r, userBearer, authQuery); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_client") {
		t.Fatalf("停用后不能再发起授权，实际 %d %s", w.Code, w.Body.String())
	}
}

// 审计接口：同意 / 拒绝都能查到（谁、哪个 client、哪些 scope）。
func TestOAuthAuditsEndpointListsConsentDecisions(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile"}, false, "s3cret-value")
	user := store.User{ID: "99999999-5555-5555-5555-555555555555", Username: "kana", Role: "user"}
	fake.addUser(user)
	userBearer := signBearer(t, s, user)
	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Role: "user", Permissions: []string{"auth.oauth.manage"}}
	opsBearer := signBearer(t, s, ops)
	authQuery := "client_id=third-party&redirect_uri=" + url.QueryEscape(chainCallback) + "&response_type=code&scope=openid+profile"

	authorize(t, r, userBearer, authQuery+"&consent=allow")
	authorize(t, r, userBearer, authQuery+"&consent=deny")

	w := doJSON(t, r, http.MethodGet, "/api/admin/oauth/audits?client_id=third-party", opsBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("审计接口应 200，实际 %d %s", w.Code, w.Body.String())
	}
	var payload struct {
		Items []store.OAuthAuditEntry `json:"items"`
	}
	decodeInto(t, w, &payload)
	if len(payload.Items) != 2 {
		t.Fatalf("应有 2 条审计，实际 %d", len(payload.Items))
	}
	actions := map[string]store.OAuthAuditEntry{}
	for _, item := range payload.Items {
		actions[item.Action] = item
	}
	allow, ok := actions[store.OAuthActionConsentAllow]
	if !ok || allow.SubjectID != user.ID || allow.ActorID != user.ID || len(allow.Scopes) != 2 {
		t.Fatalf("同意审计内容不符: %+v", allow)
	}
	if _, ok := actions[store.OAuthActionConsentDeny]; !ok {
		t.Fatalf("拒绝也必须留痕: %+v", payload.Items)
	}
}
