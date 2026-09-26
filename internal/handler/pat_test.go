package handler

// PAT 端点的无数据库用例：校验逻辑走 store 的导出函数（scopes 归一、哈希），
// 只有"落库/查库"被内存替身换掉；身份仍由真实 RS256 签发器判定。
// 需要真实数据库的同一链路见 TestPersonalAccessTokenHTTPAgainstPostgres。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

const testPATID = "11111111-1111-7111-8111-111111111111"

// testPATPlain 是替身返回的明文：与真实格式同形（mfp_ + 43 位 base62）。
var testPATPlain = "mfp_" + strings.Repeat("aZ3", 14) + "q"

// fakePATs 是 PAT 端点的内存替身：principal 为 nil 表示内省一律 invalid_token。
type fakePATs struct {
	principal *store.PATPrincipal
	plain     string
	items     []store.PersonalAccessToken
}

func (f *fakePATs) CreatePersonalAccessToken(_ context.Context, actor *store.User, name string, scopes []string, expiresIn time.Duration) (store.PersonalAccessToken, string, error) {
	if strings.TrimSpace(name) == "" {
		return store.PersonalAccessToken{}, "", errors.New("invalid_token_name")
	}
	norm, err := store.NormalizePATScopes(scopes, actor)
	if err != nil {
		return store.PersonalAccessToken{}, "", err
	}
	item := store.PersonalAccessToken{ID: testPATID, Name: name, TokenPrefix: f.plain[:12], Scopes: norm, CreatedAt: time.Now(), Active: true}
	if expiresIn > 0 {
		exp := item.CreatedAt.Add(expiresIn)
		item.ExpiresAt = &exp
	}
	f.items = append(f.items, item)
	return item, f.plain, nil
}

func (f *fakePATs) ListPersonalAccessTokens(context.Context, string) ([]store.PersonalAccessToken, error) {
	return f.items, nil
}

func (f *fakePATs) RevokePersonalAccessToken(context.Context, string, string) error { return nil }

func (f *fakePATs) IntrospectPersonalAccessToken(_ context.Context, token string) (*store.PATPrincipal, error) {
	if f.principal != nil && token == f.plain {
		return f.principal, nil
	}
	return nil, store.ErrInvalidPAT
}

func newPATTestServer(t *testing.T, fake *fakePATs) (*gin.Engine, *store.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := &store.Store{Tokens: newTestIssuer(t)}
	h := New(s)
	h.tokens = fake
	r := gin.New()
	h.Register(r)
	return r, s
}

// assertNoSessionCookie：PAT 相关的请求不得产出 mf_session——内省是给下游用的无凭据调用，
// 明文也不是登录态，一旦下发 Cookie，浏览器就会把"机器令牌"当成一次登录。
func assertNoSessionCookie(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "mf_session" {
			t.Fatal("PAT 请求不得下发 mf_session Cookie")
		}
	}
}

func TestTokenEndpointsRequireLogin(t *testing.T) {
	r, _ := newPATTestServer(t, &fakePATs{plain: testPATPlain})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/auth/tokens"},
		{http.MethodPost, "/api/auth/tokens"},
		{http.MethodDelete, "/api/auth/tokens/" + testPATID},
	} {
		w := doJSON(t, r, tc.method, tc.path, "", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("匿名 %s %s 应 401，实际 %d：%s", tc.method, tc.path, w.Code, w.Body.String())
		}
		var body struct {
			Error string `json:"error"`
		}
		decodeInto(t, w, &body)
		if body.Error != "authentication_required" {
			t.Fatalf("错误码应为 authentication_required，实际 %q", body.Error)
		}
	}
}

func TestTokenCreateValidatesScopesAgainstActor(t *testing.T) {
	fake := &fakePATs{plain: testPATPlain}
	r, s := newPATTestServer(t, fake)
	member := store.User{ID: "77777777-7777-7777-7777-777777777777", Username: "member", Permissions: []string{"catalog.entity.edit"}}
	bearer := signBearer(t, s, member)

	// 超出本人权限、格式非法、有效期非法：都是 400 + 稳定机器码，且一个都不该落库。
	for _, tc := range []struct{ label, body, wantCode string }{
		{"超出本人权限", `{"name":"提权","scopes":["auth.users.manage"]}`, "scope_not_granted: auth.users.manage"},
		{"格式非法", `{"name":"词表","scopes":["read","write"]}`, "invalid_scope: read"},
		{"有效期为负", `{"name":"短命","scopes":["catalog.entity.edit"],"expires_in_days":-1}`, "invalid_expiry"},
		{"有效期超上限", `{"name":"长生","scopes":["catalog.entity.edit"],"expires_in_days":99999}`, "invalid_expiry"},
		{"缺少名称", `{"scopes":["catalog.entity.edit"]}`, "invalid_token_name"},
		{"空 scopes", `{"name":"无权限","scopes":[]}`, "invalid_scope: empty"},
		{"缺 scopes 字段", `{"name":"无权限"}`, "invalid_scope: empty"},
		{"全空白 scopes", `{"name":"无权限","scopes":["","  "]}`, "invalid_scope: empty"},
	} {
		w := doJSON(t, r, http.MethodPost, "/api/auth/tokens", bearer, tc.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d：%s", tc.label, w.Code, w.Body.String())
		}
		var body struct {
			Error string `json:"error"`
		}
		decodeInto(t, w, &body)
		if body.Error != tc.wantCode {
			t.Fatalf("%s 的错误码应为 %q，实际 %q", tc.label, tc.wantCode, body.Error)
		}
	}

	// 空 scopes 不再是合法语义：没有权限的令牌在既有判定下会变成全权令牌（Can 的 role 兜底），
	// 上面那张 400 表已经覆盖；这里断言"被拒之后一张都没落库"。
	if len(fake.items) != 0 {
		t.Fatal("被拒的创建不得落库")
	}

	// 本人持有的码：201，且去重后只留一份。
	w := doJSON(t, r, http.MethodPost, "/api/auth/tokens", bearer, `{"name":"CI 编目","scopes":["catalog.entity.edit","catalog.entity.edit"],"expires_in_days":30}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("本人权限内的 scope 应可创建，实际 %d：%s", w.Code, w.Body.String())
	}
	var created struct {
		Token string                    `json:"token"`
		Item  store.PersonalAccessToken `json:"item"`
	}
	decodeInto(t, w, &created)
	if created.Token != testPATPlain || !strings.HasPrefix(created.Token, "mfp_") {
		t.Fatalf("创建响应应含明文（mfp_ 前缀）：%q", created.Token)
	}
	if created.Item.ExpiresAt == nil || !created.Item.Active || created.Item.Name != "CI 编目" {
		t.Fatalf("创建响应元数据不符：%+v", created.Item)
	}
}

func TestTokenCreateReturnsPlaintextWithoutHash(t *testing.T) {
	r, s := newPATTestServer(t, &fakePATs{plain: testPATPlain})
	admin := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Permissions: []string{"*"}}
	bearer := signBearer(t, s, admin)

	w := doJSON(t, r, http.MethodPost, "/api/auth/tokens", bearer, `{"name":"批量脚本","scopes":["catalog.entity.edit"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("创建：%d %s", w.Code, w.Body.String())
	}
	var created struct {
		Token string                    `json:"token"`
		Item  store.PersonalAccessToken `json:"item"`
	}
	decodeInto(t, w, &created)
	hash := store.HashPersonalAccessToken(created.Token)
	if hash == created.Token || len(hash) != 64 {
		t.Fatalf("哈希形状不符：%q", hash)
	}
	if strings.Contains(w.Body.String(), hash) {
		t.Fatalf("创建响应绝不能含 token_hash：%s", w.Body.String())
	}
	if created.Item.TokenPrefix != created.Token[:12] {
		t.Fatalf("展示前缀应取自明文前 12 字符：%q", created.Item.TokenPrefix)
	}

	// 列表：既没有明文也没有哈希（明文只出现过一次）。
	w = doJSON(t, r, http.MethodGet, "/api/auth/tokens", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("列表：%d %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, created.Token) || strings.Contains(body, hash) {
		t.Fatalf("列表响应不得含明文或 token_hash：%s", body)
	}
	var listed struct {
		Items []store.PersonalAccessToken `json:"items"`
	}
	decodeInto(t, w, &listed)
	if len(listed.Items) != 1 || listed.Items[0].TokenPrefix != created.Item.TokenPrefix {
		t.Fatalf("列表内容不符：%+v", listed.Items)
	}
}

func TestTokenIntrospectReturnsPrincipal(t *testing.T) {
	principal := &store.PATPrincipal{
		TokenID: testPATID, TokenName: "CI 编目",
		UserID: "77777777-7777-7777-7777-777777777777", Username: "member", Permissions: []string{"catalog.entity.edit"}, Scopes: []string{"catalog.entity.edit"},
		TokenPrefix: testPATPlain[:12],
	}
	r, _ := newPATTestServer(t, &fakePATs{plain: testPATPlain, principal: principal})
	w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", `{"token":"`+testPATPlain+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("内省：%d %s", w.Code, w.Body.String())
	}
	var got struct {
		Valid       bool       `json:"valid"`
		TokenID     string     `json:"token_id"`
		TokenName   string     `json:"token_name"`
		UserID      string     `json:"user_id"`
		Username    string     `json:"username"`
		Role        string     `json:"role"`
		Permissions []string   `json:"permissions"`
		Scopes      []string   `json:"scopes"`
		TokenPrefix string     `json:"token_prefix"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	decodeInto(t, w, &got)
	if !got.Valid || got.UserID != principal.UserID || got.Username != principal.Username {
		t.Fatalf("内省身份不符：%+v", got)
	}
	if got.TokenID != testPATID || got.TokenName != "CI 编目" {
		t.Fatalf("内省应回令牌身份 token_id/token_name：%+v", got)
	}
	if len(got.Permissions) != 1 || got.Permissions[0] != "catalog.entity.edit" || got.TokenPrefix != principal.TokenPrefix {
		t.Fatalf("内省权限/前缀不符：%+v", got)
	}
	if got.ExpiresAt != nil {
		t.Fatalf("永不过期的令牌 expires_at 应为 null：%v", got.ExpiresAt)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("内省结果必须 no-store（中间层缓存会拉长吊销窗口）：%q", w.Header().Get("Cache-Control"))
	}
	assertNoSessionCookie(t, w)
}

func TestTokenIntrospectFailuresAreUndifferentiated(t *testing.T) {
	r, _ := newPATTestServer(t, &fakePATs{plain: testPATPlain}) // principal 为 nil：内省一律失败
	for _, tc := range []struct{ label, body string }{
		{"不存在的令牌", `{"token":"mfp_` + strings.Repeat("a", 43) + `"}`},
		{"空令牌", `{"token":""}`},
		{"会话令牌冒充", `{"token":"8f14e45fceea167a5a36dedd4bea2543"}`},
		{"已吊销或过期", `{"token":"` + testPATPlain + `"}`},
	} {
		w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", tc.body)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s 应 401，实际 %d：%s", tc.label, w.Code, w.Body.String())
		}
		var body map[string]any
		decodeInto(t, w, &body)
		if len(body) != 1 || body["error"] != "invalid_token" {
			t.Fatalf("%s 的错误体只能是单一机器码 invalid_token：%v", tc.label, body)
		}
		assertNoSessionCookie(t, w)
	}
	// 请求体本身不合法是调用方写错了，与"令牌无效"分开（否则下游会把 400 当成令牌过期）。
	if w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", `{"token":123}`); w.Code != http.StatusBadRequest {
		t.Fatalf("非法请求体应 400，实际 %d：%s", w.Code, w.Body.String())
	}
}

func TestTokenIntrospectRateLimitPerToken(t *testing.T) {
	r, _ := newPATTestServer(t, &fakePATs{})
	body := `{"token":"mfp_ratelimited"}`
	for i := 0; i < patIntrospectPerTokenPerMinute; i++ {
		if w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", body); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次应进业务（401），实际 %d", i+1, w.Code)
		}
	}
	w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", body)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("同一令牌超过 %d 次/分钟应 429，实际 %d", patIntrospectPerTokenPerMinute, w.Code)
	}
	if w.Header().Get("Retry-After") != "60" {
		t.Fatalf("429 必须带 Retry-After，实际 %q", w.Header().Get("Retry-After"))
	}
	var body429 struct {
		Error string `json:"error"`
	}
	decodeInto(t, w, &body429)
	if body429.Error != "rate_limited" {
		t.Fatalf("错误码应为 rate_limited，实际 %q", body429.Error)
	}
	// 令牌维度是分桶的：换一张令牌仍然进业务（IP 维度离上限还很远）。
	if w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", `{"token":"mfp_another"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("限流应按令牌分桶，换一张令牌不该被拦：%d %s", w.Code, w.Body.String())
	}
}

func TestTokenIntrospectRateLimitPerIP(t *testing.T) {
	r, _ := newPATTestServer(t, &fakePATs{})
	// 每次换一张令牌（令牌桶各自只记一次），IP 桶才是这里的分母。
	for i := 0; i < patIntrospectPerIPPerMinute; i++ {
		body := `{"token":"mfp_ip` + strconv.Itoa(i) + `"}`
		if w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", body); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次应进业务（401），实际 %d", i+1, w.Code)
		}
	}
	w := doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", `{"token":"mfp_ip_overflow"}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("同一来源超过 %d 次/分钟应 429，实际 %d：%s", patIntrospectPerIPPerMinute, w.Code, w.Body.String())
	}
}
