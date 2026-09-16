package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// 这一组用例用 httptest 真跑一遍授权链路（authorize → 同意页 → 授权码 → 令牌 → userinfo），
// OAuth 数据操作走内存实现（判定逻辑仍是 store 的导出函数），身份仍由真实 RS256 签发器判定。
// 需要真实数据库的同一链路见 TestOAuthChainAgainstPostgres。

const chainCallback = "https://client.example/auth/callback"

func newOAuthTestServer(t *testing.T) (*gin.Engine, *store.Store, *fakeOAuth) {
	t.Helper()
	_, s := newTestServer(t) // 复用进程内 RSA 密钥与签发器
	fake := newFakeOAuth(s.Tokens)
	r := gin.New()
	(&Handler{store: s, oauth: fake}).Register(r)
	return r, s, fake
}

func signBearer(t *testing.T, s *store.Store, u store.User) string {
	t.Helper()
	token, _, _, err := s.Tokens.Sign(u)
	if err != nil {
		t.Fatalf("签身份令牌: %v", err)
	}
	return token
}

// authorize 默认用 zh-CN 访问同意页：用例断言中文文案，语言回退单独由
// TestConsentPageLanguageAndEscaping 覆盖。
func authorize(t *testing.T, r *gin.Engine, bearer, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/oauth/authorize?"+query, nil)
	req.Header.Set("Accept-Language", "zh-CN")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func postToken(t *testing.T, r *gin.Engine, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func userinfo(t *testing.T, r *gin.Engine, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/oauth/userinfo", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func codeFromRedirect(t *testing.T, w *httptest.ResponseRecorder, wantCallback string) string {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("应回跳（302），实际 %d：%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, wantCallback) {
		t.Fatalf("回跳目标不是白名单地址: %s", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location 不是合法 URL: %v", err)
	}
	if got := parsed.Query().Get("error"); got != "" {
		t.Fatalf("回跳带了错误: %s", got)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("回跳没有授权码: %s", loc)
	}
	return code
}

func decodeJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("响应不是 JSON: %v / %s", err, string(body))
	}
}

// 主链路：已登录的第三方请求 → 同意页 → 同意 → 授权码 → 令牌（含 scope/id_token/expires_in）
// → userinfo 拿到身份；同时校验"未表态前不发码"与审计留痕。
func TestAuthorizationCodeChainWithConsent(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile", "email"}, false, "s3cret-value")
	user := store.User{ID: "11111111-1111-1111-1111-111111111111", Username: "kana", Email: "kana@example.test", Role: "user"}
	fake.addUser(user)
	bearer := signBearer(t, s, user)
	authQuery := "client_id=third-party&redirect_uri=" + url.QueryEscape(chainCallback) +
		"&response_type=code&state=st-1&scope=" + url.QueryEscape("openid profile email")

	// 1) 已登录但没表态：渲染同意页，而不是直接发码。
	w := authorize(t, r, bearer, authQuery)
	if w.Code != http.StatusOK {
		t.Fatalf("同意页状态码 = %d，期望 200：%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("同意页必须是 HTML，实际 %s", ct)
	}
	page := w.Body.String()
	for _, want := range []string{"示例第三方站点", "third-party", "确认你的身份", "读取基本资料", "读取邮箱", chainCallback, "consent=allow", "consent=deny"} {
		if !strings.Contains(page, want) {
			t.Fatalf("同意页缺少 %q", want)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("同意页必须禁止缓存与 iframe 嵌套: %v", w.Header())
	}
	if fake.pendingCodeCount() != 0 {
		t.Fatal("用户同意前不得签发授权码")
	}

	// 2) 点「同意并继续」：回跳带码，state 原样带回。
	loc := authorize(t, r, bearer, authQuery+"&consent=allow").Header().Get("Location")
	if !strings.Contains(loc, "state=st-1") {
		t.Fatalf("回跳必须带 state: %s", loc)
	}
	code := codeFromRedirect(t, authorize(t, r, bearer, authQuery+"&consent=allow"), chainCallback)

	// 3) 换令牌：scope 是收敛后的集合，expires_in 是真实 TTL，另附 id_token。
	w = postToken(t, r, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"third-party"},
		"client_secret": {"s3cret-value"}, "redirect_uri": {chainCallback},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("换令牌状态码 = %d：%s", w.Code, w.Body.String())
	}
	var tokenResp struct {
		AccessToken string         `json:"access_token"`
		TokenType   string         `json:"token_type"`
		ExpiresIn   int            `json:"expires_in"`
		Scope       string         `json:"scope"`
		User        map[string]any `json:"user"`
		IDToken     string         `json:"id_token"`
	}
	decodeJSON(t, w.Body.Bytes(), &tokenResp)
	if tokenResp.AccessToken == "" || tokenResp.TokenType != "Bearer" {
		t.Fatalf("令牌响应不符: %+v", tokenResp)
	}
	if tokenResp.Scope != "openid profile email" {
		t.Fatalf("scope = %q，期望收敛后的全部三项", tokenResp.Scope)
	}
	if tokenResp.ExpiresIn != int(store.AccessTokenTTL.Seconds()) {
		t.Fatalf("expires_in = %d，期望真实 TTL %d", tokenResp.ExpiresIn, int(store.AccessTokenTTL.Seconds()))
	}
	if tokenResp.User["id"] != user.ID || tokenResp.IDToken == "" {
		t.Fatalf("响应缺少身份或 id_token: %+v", tokenResp)
	}

	// 4) userinfo
	w = userinfo(t, r, tokenResp.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo 状态码 = %d：%s", w.Code, w.Body.String())
	}
	var info struct {
		Sub      string `json:"sub"`
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	decodeJSON(t, w.Body.Bytes(), &info)
	if info.Sub != user.ID || info.ID != user.ID || info.Username != "kana" || info.Email != "kana@example.test" || info.Role != "user" {
		t.Fatalf("userinfo 内容不符: %+v", info)
	}

	// 5) 审计：同意动作必须留痕（谁、给哪个 client、授了哪些 scope）
	actions := fake.auditActions()
	if len(actions) == 0 || actions[len(actions)-1] != store.OAuthActionConsentAllow {
		t.Fatalf("同意动作未落审计: %v", actions)
	}
}

// 受信第一方跳过同意页：请求进来直接回码（自动化流程不能被同意页打断），审计记为 trusted_allow。
func TestTrustedClientSkipsConsentPage(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("metafusion-forum", "MetaFusion 社区论坛", []string{chainCallback}, []string{"profile"}, true, "")
	user := store.User{ID: "22222222-2222-2222-2222-222222222222", Username: "member", Role: "user"}
	fake.addUser(user)
	bearer := signBearer(t, s, user)

	w := authorize(t, r, bearer, "client_id=metafusion-forum&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=profile")
	code := codeFromRedirect(t, w, chainCallback)
	// 无密钥的第一方：换码不带 client_secret。
	resp := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"metafusion-forum"}})
	if resp.Code != http.StatusOK {
		t.Fatalf("受信第一方换码失败: %d %s", resp.Code, resp.Body.String())
	}
	actions := fake.auditActions()
	if len(actions) != 1 || actions[0] != store.OAuthActionTrustedAllow {
		t.Fatalf("审计应为 trusted_allow，实际 %v", actions)
	}
}

// 拒绝：带 error=access_denied 回回调地址、不发码、留审计。
func TestConsentDeniedReturnsAccessDenied(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile"}, false, "s3cret-value")
	user := store.User{ID: "33333333-3333-3333-3333-333333333333", Username: "kana", Role: "user"}
	fake.addUser(user)
	bearer := signBearer(t, s, user)

	w := authorize(t, r, bearer, "client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&state=st-9&scope=openid&consent=deny")
	if w.Code != http.StatusFound {
		t.Fatalf("拒绝后应回跳，实际 %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, chainCallback) || !strings.Contains(loc, "error=access_denied") || !strings.Contains(loc, "state=st-9") {
		t.Fatalf("拒绝回跳不符: %s", loc)
	}
	if strings.Contains(loc, "code=") {
		t.Fatalf("拒绝不应带授权码: %s", loc)
	}
	if fake.pendingCodeCount() != 0 {
		t.Fatal("拒绝不得签发授权码")
	}
	actions := fake.auditActions()
	if len(actions) != 1 || actions[0] != store.OAuthActionConsentDeny {
		t.Fatalf("拒绝未落审计: %v", actions)
	}
}

// scope 收敛：客户端白名单里没有的 scope 一律不给；与白名单完全无交集时报 invalid_scope。
func TestScopeConvergenceOnAuthorization(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile"}, false, "s3cret-value")
	fake.addClient("email-only", "只要邮箱的站点", []string{chainCallback}, []string{"email"}, false, "s3cret-value")
	user := store.User{ID: "44444444-4444-4444-4444-444444444444", Username: "kana", Role: "user"}
	fake.addUser(user)
	bearer := signBearer(t, s, user)

	// 请求三项、白名单两项 → 码里只有两项，令牌响应也只能是两项。
	code := codeFromRedirect(t, authorize(t, r, bearer,
		"client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope="+url.QueryEscape("openid profile email")+"&consent=allow"), chainCallback)
	resp := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"third-party"}, "client_secret": {"s3cret-value"}})
	if resp.Code != http.StatusOK {
		t.Fatalf("换码失败: %d %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Scope string `json:"scope"`
	}
	decodeJSON(t, resp.Body.Bytes(), &body)
	if body.Scope != "openid profile" {
		t.Fatalf("scope = %q，期望白名单内的交集 openid profile", body.Scope)
	}

	// 不受支持的 scope：直接 400 invalid_scope（不进入同意页）。
	w := authorize(t, r, bearer, "client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=openid+phone")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_scope") {
		t.Fatalf("不支持的 scope 应 400 invalid_scope，实际 %d %s", w.Code, w.Body.String())
	}
	// 与白名单无交集：也是 invalid_scope（只是没有可授予的项）。
	w = authorize(t, r, bearer, "client_id=email-only&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=openid")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_scope") {
		t.Fatalf("空交集应 400 invalid_scope，实际 %d %s", w.Code, w.Body.String())
	}
}

// PKCE 校验失败不消耗授权码；回调不一致与二次兑换都要被拒。
func TestPKCEAndRedirectGuards(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid", "profile"}, false, "s3cret-value")
	user := store.User{ID: "55555555-5555-5555-5555-555555555555", Username: "kana", Role: "user"}
	fake.addUser(user)
	bearer := signBearer(t, s, user)

	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFG"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	code := codeFromRedirect(t, authorize(t, r, bearer,
		"client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=openid"+
			"&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&consent=allow"), chainCallback)

	w := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"third-party"}, "client_secret": {"s3cret-value"}, "code_verifier": {"wrong-verifier"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_code_verifier") {
		t.Fatalf("错误 verifier 应 400 invalid_code_verifier，实际 %d %s", w.Code, w.Body.String())
	}
	w = postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"third-party"}, "client_secret": {"s3cret-value"}, "redirect_uri": {"https://client.example/other"}, "code_verifier": {verifier}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "redirect_uri_mismatch") {
		t.Fatalf("回调不一致应 400 redirect_uri_mismatch，实际 %d %s", w.Code, w.Body.String())
	}
	// 码还没被消耗：正确的 verifier 仍能换到令牌。
	resp := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"third-party"}, "client_secret": {"s3cret-value"}, "redirect_uri": {chainCallback}, "code_verifier": {verifier}})
	if resp.Code != http.StatusOK {
		t.Fatalf("校验失败不得消耗授权码，实际 %d %s", resp.Code, resp.Body.String())
	}
	// 已兑换过的码不能再换第二次。
	again := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"third-party"}, "client_secret": {"s3cret-value"}, "redirect_uri": {chainCallback}, "code_verifier": {verifier}})
	if again.Code != http.StatusBadRequest || !strings.Contains(again.Body.String(), "expired_or_used_code") {
		t.Fatalf("授权码必须一次性，实际 %d %s", again.Code, again.Body.String())
	}
	// 回调地址不在白名单：连同意页都不该出现。
	w = authorize(t, r, bearer, "client_id=third-party&redirect_uri="+url.QueryEscape("https://evil.example/cb")+"&response_type=code&scope=openid")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_redirect_uri") {
		t.Fatalf("非白名单回调应 400 invalid_redirect_uri，实际 %d %s", w.Code, w.Body.String())
	}
	// JSON 提交的兼容路径（OIDC 客户端常用）
	code = codeFromRedirect(t, authorize(t, r, bearer, "client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=openid&consent=allow"), chainCallback)
	jsonBody := `{"grant_type":"authorization_code","code":"` + code + `","client_id":"third-party","client_secret":"s3cret-value","redirect_uri":"` + chainCallback + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth/token", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON 提交换码失败: %d %s", rec.Code, rec.Body.String())
	}
}

// 匿名用户不能进同意页，先被送去登录页并带 return_to；未登录不产生任何审计。
func TestAuthorizeRedirectsAnonymousToLogin(t *testing.T) {
	r, _, fake := newOAuthTestServer(t)
	fake.addClient("third-party", "示例第三方站点", []string{chainCallback}, []string{"openid"}, false, "s3cret-value")
	w := authorize(t, r, "", "client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=openid")
	if w.Code != http.StatusFound {
		t.Fatalf("未登录应回跳登录页，实际 %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "return_to=") {
		t.Fatalf("登录回跳必须带 return_to: %s", loc)
	}
	if len(fake.auditActions()) != 0 {
		t.Fatal("未登录不得产生审计")
	}
}

// 同意页按 Accept-Language 出四语，且客户端名称等用户可控内容必须转义。
func TestConsentPageLanguageAndEscaping(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("third-party", `可疑站点 <script>alert(1)</script>`, []string{chainCallback}, []string{"email"}, false, "s3cret-value")
	user := store.User{ID: "66666666-6666-6666-6666-666666666666", Username: "kana", Role: "user"}
	fake.addUser(user)
	bearer := signBearer(t, s, user)

	cases := []struct {
		acceptLang string
		want       string
	}{
		{"zh-CN,zh;q=0.9", "授权访问你的 MetaFusion 账号"},
		{"zh-TW", "授權存取你的 MetaFusion 帳號"},
		{"zh-Hant-HK", "授權存取你的 MetaFusion 帳號"},
		{"ja-JP,ja;q=0.9", "MetaFusion アカウントへのアクセスを許可"},
		{"en-GB,en;q=0.9", "Authorize access to your MetaFusion account"},
		{"fr-FR", "Authorize access to your MetaFusion account"}, // 匹配不到回落 en-US，不拿中文兜底
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/oauth/authorize?client_id=third-party&redirect_uri="+url.QueryEscape(chainCallback)+"&response_type=code&scope=email", nil)
		req.Header.Set("Accept-Language", tc.acceptLang)
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("Accept-Language=%s 未拿到对应文案（%d）", tc.acceptLang, w.Code)
		}
		if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
			t.Fatalf("客户端名称必须转义，页面里出现了原始脚本: %s", tc.acceptLang)
		}
		if !strings.Contains(w.Body.String(), "&lt;script&gt;") {
			t.Fatalf("客户端名称应以转义形式出现: %s", tc.acceptLang)
		}
	}
}

// 四语文案必须覆盖全部受支持的 scope：漏一项就会在同意页上显示空说明。
func TestConsentTextsCoverSupportedScopes(t *testing.T) {
	for lang, text := range consentTexts {
		for _, code := range store.SupportedScopes {
			item, ok := text.Scopes[code]
			if !ok || strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Desc) == "" {
				t.Fatalf("%s 缺少 scope %q 的同意页文案", lang, code)
			}
		}
		for field, value := range map[string]string{
			"heading": text.Heading, "client_label": text.ClientLbl, "redirect_label": text.RedirectLbl,
			"allow": text.AllowLbl, "deny": text.DenyLbl, "footnote": text.Footnote,
		} {
			if strings.TrimSpace(value) == "" {
				t.Fatalf("%s 的 %s 文案为空", lang, field)
			}
		}
	}
	if len(consentTexts) != 4 {
		t.Fatalf("同意页文案应为四语（与前端字典一致），实际 %d 种", len(consentTexts))
	}
}
