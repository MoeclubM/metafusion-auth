package handler

// 真实 PostgreSQL 上的开发者中心回归：自助登记 → 同意页（未核验提示）→ 授权码 → 令牌 →
// userinfo → 管理员核验 → 归属隔离 → 删除后令牌立即失效。
//
// 未设置 AUTH_TEST_DSN 时整体跳过（本机与 CI 默认没有数据库）。跑法见 README：
// 把 AUTH_TEST_DSN 指向独立测试库（库名含 _test，testutil 会强制校验），
// 然后 `go test -p 1 ./internal/handler -run TestDeveloperCenterAgainstPostgres -v`。
// 用例自建自清账号与客户端，不读取也不修改既有数据。

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

func TestDeveloperCenterAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	st.Tokens = newTestIssuer(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st).Register(r)

	_, _, adminBearer := insertChainUser(t, ctx, st, "admin")
	memberID, _, memberBearer := insertChainUser(t, ctx, st, "user")
	_, _, otherBearer := insertChainUser(t, ctx, st, "user")

	const callback = "https://developer.example/auth/callback"
	clientID := ""
	t.Cleanup(func() {
		if clientID != "" {
			_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_audit WHERE client_id=$1", clientID)
			_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_clients WHERE id=$1", clientID)
		}
	})

	// 自助登记：请求体里塞 trusted/verified/disabled 会被**明确拒绝**（400 invalid_payload），
	// 而不是静默忽略——这三项只能由管理员在管理面写（口径见 store.OAuthClientInput 的注释）。
	adminFields := `{"name":"开发者中心示例","description":"读取资料","homepage_url":"https://developer.example",` +
		`"redirect_uris":["` + callback + `"],"scopes":["openid","email"],` +
		`"trusted":true,"verified":true,"disabled":true}`
	if w := doJSON(t, r, http.MethodPost, "/api/developer/apps", memberBearer, adminFields); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "invalid_payload") {
		t.Fatalf("带管理面字段的自助登记应 400 invalid_payload，实际 %d：%s", w.Code, w.Body.String())
	}
	var leaked int
	if err := st.DB.QueryRowContext(ctx, "SELECT count(*) FROM auth.oauth_clients WHERE owner_user_id=$1", memberID).Scan(&leaked); err != nil {
		t.Fatalf("统计登记结果: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("被拒绝的登记不得落库，实际 %d 行", leaked)
	}

	// 只带声明字段的同一载荷照旧登记成功（管理面列由服务端置 false）。
	createBody := `{"name":"开发者中心示例","description":"读取资料","homepage_url":"https://developer.example",` +
		`"redirect_uris":["` + callback + `"],"scopes":["openid","email"]}`
	w := doJSON(t, r, http.MethodPost, "/api/developer/apps", memberBearer, createBody)
	if w.Code != http.StatusOK {
		t.Fatalf("自助登记: %d %s", w.Code, w.Body.String())
	}
	var created developerAppResponse
	decodeInto(t, w, &created)
	clientID = created.App.ID
	if clientID == "" || len(created.ClientSecret) != 43 {
		t.Fatalf("登记响应形状不符: id=%q secret_len=%d", clientID, len(created.ClientSecret))
	}
	if created.App.OwnerID != memberID || created.App.FirstParty || created.App.Verified || created.App.Disabled {
		t.Fatalf("自助登记的应用投影不符: %+v", created.App)
	}
	var trusted, disabled, verified bool
	if err := st.DB.QueryRowContext(ctx, "SELECT trusted, disabled, verified FROM auth.oauth_clients WHERE id=$1", clientID).Scan(&trusted, &disabled, &verified); err != nil {
		t.Fatalf("读回客户端行: %v", err)
	}
	if trusted || disabled || verified {
		t.Fatalf("开发者路径不得写入管理面列: trusted=%v disabled=%v verified=%v", trusted, disabled, verified)
	}

	// 授权链路：未核验的第三方应用必须在同意页上被点出来。
	authQuery := "client_id=" + clientID + "&redirect_uri=" + url.QueryEscape(callback) +
		"&response_type=code&state=st-dev&scope=" + url.QueryEscape("openid email")
	w = authorize(t, r, memberBearer, authQuery)
	if w.Code != http.StatusOK {
		t.Fatalf("未核验应用应出同意页，实际 %d：%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "该应用尚未通过核验") || !strings.Contains(body, "开发者中心示例") {
		t.Fatalf("同意页应展示未核验提示与客户端名称: %s", body)
	}
	code := codeFromRedirect(t, authorize(t, r, memberBearer, authQuery+"&consent=allow"), callback)

	w = postToken(t, r, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {created.ClientSecret},
		"redirect_uri":  {callback},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("换令牌: %d %s", w.Code, w.Body.String())
	}
	var grant struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	decodeInto(t, w, &grant)
	if grant.AccessToken == "" || grant.Scope != "openid email" {
		t.Fatalf("令牌响应不符: scope=%q token_len=%d", grant.Scope, len(grant.AccessToken))
	}
	w = userinfo(t, r, grant.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body.String())
	}
	var info struct {
		Sub string `json:"sub"`
	}
	decodeInto(t, w, &info)
	if info.Sub != memberID {
		t.Fatalf("userinfo 的 sub 应为登记人: %q != %q", info.Sub, memberID)
	}

	// 归属隔离：别人的读/改/轮换/删一律按"应用不存在"处理。
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/developer/apps/" + clientID, ""},
		{http.MethodPut, "/api/developer/apps/" + clientID, `{"name":"被改名"}`},
		{http.MethodPost, "/api/developer/apps/" + clientID + "/rotate-secret", ""},
		{http.MethodDelete, "/api/developer/apps/" + clientID, ""},
	} {
		if w := doJSON(t, r, tc.method, tc.path, otherBearer, tc.body); w.Code != http.StatusNotFound {
			t.Fatalf("%s %s 越权应 404，实际 %d：%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	// 管理员在开发者面**不是例外**：读 / 改 / 轮换 / 删一律按"不存在"，且库里的行一字未动
	// （含密钥哈希——轮换若能过，哈希必然变）。全量治理在管理面，见本节末尾的对照。
	beforeProbe, err := st.GetOAuthClient(ctx, clientID)
	if err != nil {
		t.Fatalf("读探测前快照: %v", err)
	}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/developer/apps/" + clientID, ""},
		{http.MethodPut, "/api/developer/apps/" + clientID, "{\"name\":\"管理员改名\"}"},
		{http.MethodPost, "/api/developer/apps/" + clientID + "/rotate-secret", ""},
		{http.MethodDelete, "/api/developer/apps/" + clientID, ""},
	} {
		if w := doJSON(t, r, tc.method, tc.path, adminBearer, tc.body); w.Code != http.StatusNotFound {
			t.Fatalf("管理员 %s %s 也应 404，实际 %d：%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	afterProbe, err := st.GetOAuthClient(ctx, clientID)
	if err != nil {
		t.Fatalf("读探测后快照: %v", err)
	}
	if afterProbe.Name != beforeProbe.Name || afterProbe.SecretHash != beforeProbe.SecretHash ||
		afterProbe.Verified != beforeProbe.Verified || afterProbe.Disabled != beforeProbe.Disabled ||
		afterProbe.OwnerID != beforeProbe.OwnerID {
		t.Fatalf("管理员的越权请求不得改动任何字段: before=%+v after=%+v", beforeProbe, afterProbe)
	}

	// 开发者面的列表对管理员同样只回自己的应用：他没有登记过，所以是空的——
	// 系统应用（归属为空，含三个种子客户端）与别人登记的应用都不出现。
	w = doJSON(t, r, http.MethodGet, "/api/developer/apps", adminBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("管理员读开发者面列表: %d %s", w.Code, w.Body.String())
	}
	var adminList struct {
		Items []store.DeveloperApp `json:"items"`
	}
	decodeInto(t, w, &adminList)
	if len(adminList.Items) != 0 {
		t.Fatalf("管理员在开发者中心不该看到任何应用，实际 %+v", adminList.Items)
	}

	// 管理面（/api/admin/oauth/clients*）对同一个应用仍然能读能改：收口没误伤管理能力。
	w = doJSON(t, r, http.MethodGet, "/api/admin/oauth/clients", adminBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("管理面列表: %d %s", w.Code, w.Body.String())
	}
	var clients struct {
		Items []store.OAuthClient `json:"items"`
	}
	decodeInto(t, w, &clients)
	seenInAdminList := false
	for _, item := range clients.Items {
		if item.ID == clientID {
			seenInAdminList = true
		}
	}
	if !seenInAdminList {
		t.Fatalf("管理面列表必须仍能看到这个应用: %+v", clients.Items)
	}

	// 管理员核验：管理台那条路径（PUT /api/admin/oauth/clients/{id}）置 verified 之后，
	// 同意页不再显示未核验提示。
	w = doJSON(t, r, http.MethodPut, "/api/admin/oauth/clients/"+clientID, adminBearer, `{"verified":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("管理员核验: %d %s", w.Code, w.Body.String())
	}
	w = doJSON(t, r, http.MethodGet, "/api/developer/apps/"+clientID, memberBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("本人读自己的应用: %d %s", w.Code, w.Body.String())
	}
	var afterVerify developerAppResponse
	decodeInto(t, w, &afterVerify)
	if !afterVerify.App.Verified || afterVerify.App.FirstParty {
		t.Fatalf("核验后应已核验、但仍不是自有平台: %+v", afterVerify.App)
	}
	w = authorize(t, r, memberBearer, authQuery)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "尚未通过核验") {
		t.Fatalf("已核验应用的同意页不应再有未核验提示: %d %s", w.Code, w.Body.String())
	}

	// 删除自己的应用：授权码与令牌随外键级联删除，已签发的令牌立即失效。
	if w := doJSON(t, r, http.MethodDelete, "/api/developer/apps/"+clientID, memberBearer, ""); w.Code != http.StatusOK {
		t.Fatalf("本人删除: %d %s", w.Code, w.Body.String())
	}
	w = userinfo(t, r, grant.AccessToken)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("删除后令牌应立即失效（401），实际 %d：%s", w.Code, w.Body.String())
	}
	clientID = "" // 行已经删掉，收尾不必再删
}
