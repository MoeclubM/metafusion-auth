package handler

// 开发者中心端点的 HTTP 契约（内存替身）：路由鉴权、自助登记、归属隔离与接入配置。
// 真实库上的同一链路（同意页 → 授权码 → 令牌 → userinfo）见 developer_postgres_test.go。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

type developerAppResponse struct {
	App          store.DeveloperApp `json:"app"`
	ClientSecret string             `json:"client_secret"`
}

func TestDeveloperAppRegistrationAndOwnership(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	owner := store.User{ID: "aaaaaaaa-1111-1111-1111-111111111111", Username: "dev-owner", Role: "user"}
	other := store.User{ID: "bbbbbbbb-2222-2222-2222-222222222222", Username: "dev-other", Role: "user"}
	admin := store.User{ID: "cccccccc-3333-3333-3333-333333333333", Username: "dev-admin", Role: "admin", Permissions: []string{"*"}}
	for _, u := range []store.User{owner, other, admin} {
		fake.addUser(u)
	}
	ownerBearer := signBearer(t, s, owner)
	otherBearer := signBearer(t, s, other)
	adminBearer := signBearer(t, s, admin)

	// 匿名一律 401：登记、列表、接入配置三条入口口径一致。
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/developer/apps", ""},
		{http.MethodGet, "/api/developer/overview", ""},
		{http.MethodPost, "/api/developer/apps", `{"name":"x","redirect_uris":["https://x.example/cb"]}`},
	} {
		if w := doJSON(t, r, tc.method, tc.path, "", tc.body); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 匿名应 401，实际 %d", tc.method, tc.path, w.Code)
		}
	}

	// 登记：请求体里塞 trusted/verified/disabled 也必须无效——这三项不在这条路径的写入形状里，
	// 能不能成为"自有平台"由管理员决定，不由请求方声明。
	body := `{"name":"第三方示例","description":"读取资料","homepage_url":"https://third.example",` +
		`"redirect_uris":["https://third.example/cb"],"scopes":["openid","email"],` +
		`"trusted":true,"verified":true,"disabled":true}`
	w := doJSON(t, r, http.MethodPost, "/api/developer/apps", ownerBearer, body)
	if w.Code != http.StatusOK {
		t.Fatalf("登记应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	var created developerAppResponse
	decodeInto(t, w, &created)
	if created.App.ID == "" || len(created.ClientSecret) != 43 {
		t.Fatalf("登记响应形状不符: id=%q secret_len=%d", created.App.ID, len(created.ClientSecret))
	}
	if created.App.OwnerID != owner.ID || created.App.FirstParty || created.App.Verified || created.App.Disabled || !created.App.HasSecret {
		t.Fatalf("自助登记的应用投影不符: %+v", created.App)
	}
	if strings.Join(created.App.Scopes, " ") != "openid email" {
		t.Fatalf("scope 应按请求落库: %v", created.App.Scopes)
	}
	stored, err := fake.GetOAuthClient(context.Background(), created.App.ID)
	if err != nil {
		t.Fatalf("读回客户端: %v", err)
	}
	if stored.Trusted || stored.Verified || stored.Disabled {
		t.Fatalf("请求体里的管理面字段不得生效: trusted=%v verified=%v disabled=%v", stored.Trusted, stored.Verified, stored.Disabled)
	}

	// 详情：只有创建/轮换那一次响应带明文密钥，之后无处可取。
	w = doJSON(t, r, http.MethodGet, "/api/developer/apps/"+created.App.ID, ownerBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("详情应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), created.ClientSecret) || strings.Contains(w.Body.String(), "secret_hash") {
		t.Fatalf("详情响应泄露了密钥材料: %s", w.Body.String())
	}

	// 归属隔离：别人的应用按"不存在"处理（不是 403），四条路径同一口径。
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/developer/apps/" + created.App.ID, ""},
		{http.MethodPut, "/api/developer/apps/" + created.App.ID, `{"name":"被改名"}`},
		{http.MethodPost, "/api/developer/apps/" + created.App.ID + "/rotate-secret", ""},
		{http.MethodDelete, "/api/developer/apps/" + created.App.ID, ""},
	} {
		if w := doJSON(t, r, tc.method, tc.path, otherBearer, tc.body); w.Code != http.StatusNotFound {
			t.Fatalf("%s %s 越权应 404，实际 %d：%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if name := fake.clients[created.App.ID].Name; name != "第三方示例" {
		t.Fatalf("越权改名不得生效: %q", name)
	}

	// 管理员在开发者面**不是例外**：别人的应用读 / 改 / 轮换 / 删一律按"不存在"，
	// 且内存里的行一字未动（密钥哈希也没变——轮换若能过，哈希必然变）。
	// 他的全量治理能力在管理面（/api/admin/oauth/clients*），本节末尾就是同一批断言的对照。
	beforeProbe := fake.clients[created.App.ID]
	beforeSecret := fake.secrets[created.App.ID]
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/developer/apps/" + created.App.ID, ""},
		{http.MethodPut, "/api/developer/apps/" + created.App.ID, "{\"name\":\"管理员改名\"}"},
		{http.MethodPost, "/api/developer/apps/" + created.App.ID + "/rotate-secret", ""},
		{http.MethodDelete, "/api/developer/apps/" + created.App.ID, ""},
	} {
		if w := doJSON(t, r, tc.method, tc.path, adminBearer, tc.body); w.Code != http.StatusNotFound {
			t.Fatalf("管理员 %s %s 也应 404，实际 %d：%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if after := fake.clients[created.App.ID]; after.Name != beforeProbe.Name || fake.secrets[created.App.ID] != beforeSecret {
		t.Fatalf("管理员的越权请求不得改动任何字段: before=%+v after=%+v", beforeProbe, after)
	}

	// 管理面（auth.oauth.manage）仍然能读能改同一个应用：收口没有误伤管理能力。
	if w := doJSON(t, r, http.MethodGet, "/api/admin/oauth/clients", adminBearer, ""); w.Code != http.StatusOK {
		t.Fatalf("管理面列表应 200，实际 %d：%s", w.Code, w.Body.String())
	} else if !strings.Contains(w.Body.String(), created.App.ID) {
		t.Fatalf("管理面列表必须仍能看到这个应用：%s", w.Body.String())
	}
	if w := doJSON(t, r, http.MethodPut, "/api/admin/oauth/clients/"+created.App.ID, adminBearer, "{\"verified\":true}"); w.Code != http.StatusOK {
		t.Fatalf("管理面核验应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	if !fake.clients[created.App.ID].Verified {
		t.Fatal("管理面核验必须落到客户端上")
	}

	// 本人的合法更新与非法主页。
	w = doJSON(t, r, http.MethodPut, "/api/developer/apps/"+created.App.ID, ownerBearer, `{"name":"改名后","homepage_url":"https://new.example"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("本人更新应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	var updated developerAppResponse
	decodeInto(t, w, &updated)
	if updated.App.Name != "改名后" || updated.App.HomepageURL != "https://new.example" {
		t.Fatalf("更新未生效: %+v", updated.App)
	}
	w = doJSON(t, r, http.MethodPut, "/api/developer/apps/"+created.App.ID, ownerBearer, `{"homepage_url":"javascript:alert(1)"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_homepage_url") {
		t.Fatalf("非法主页应 400 invalid_homepage_url，实际 %d：%s", w.Code, w.Body.String())
	}

	// 列表只含自己的应用。先塞一个平台自有客户端（trusted + 无归属）：它在开发者面
	// 对任何人都不可见——系统应用归管理台管。
	fake.addClient("metafusion-catalog", "MetaFusion 目录", []string{"https://findverse.cc/auth/callback"}, []string{"openid"}, true, "")
	w = doJSON(t, r, http.MethodGet, "/api/developer/apps", ownerBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("列表应 200，实际 %d", w.Code)
	}
	var list struct {
		Items []store.DeveloperApp `json:"items"`
	}
	decodeInto(t, w, &list)
	if len(list.Items) != 1 || list.Items[0].ID != created.App.ID {
		t.Fatalf("本人列表应只有自己那一个应用: %+v", list.Items)
	}
	w = doJSON(t, r, http.MethodGet, "/api/developer/apps", otherBearer, "")
	var others struct {
		Items []store.DeveloperApp `json:"items"`
	}
	decodeInto(t, w, &others)
	if len(others.Items) != 0 {
		t.Fatalf("别人的列表不应看到别人的应用: %+v", others.Items)
	}
	// 管理员在开发者面也只有自己的应用；系统应用（无归属）对他同样不可见。
	w = doJSON(t, r, http.MethodGet, "/api/developer/apps", adminBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("管理员列表应 200，实际 %d", w.Code)
	}
	var adminApps struct {
		Items []store.DeveloperApp `json:"items"`
	}
	decodeInto(t, w, &adminApps)
	if len(adminApps.Items) != 0 {
		t.Fatalf("管理员在开发者中心不该看到任何应用（他没登记过，系统应用也不该出现）: %+v", adminApps.Items)
	}
}

// TestDeveloperOverviewServesEndpointsAndPlatforms 覆盖开发者中心的"接入配置"：
// 端点地址、scope 四语说明、以及"哪些站点是自有平台（免同意 + 自动核验）"。
func TestDeveloperOverviewServesEndpointsAndPlatforms(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	fake.addClient("metafusion-catalog", "MetaFusion 元数据知识库", []string{"https://findverse.cc/auth/callback"}, []string{"openid", "profile", "email"}, true, "")
	fake.addClient("third-party", "第三方站点", []string{chainCallback}, []string{"openid"}, false, "s3cret-value")
	member := store.User{ID: "dddddddd-4444-4444-4444-444444444444", Username: "dev-member", Role: "user"}
	fake.addUser(member)
	bearer := signBearer(t, s, member)

	w := doJSON(t, r, http.MethodGet, "/api/developer/overview", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("接入配置应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	var overview struct {
		Issuer     string               `json:"issuer"`
		AccountURL string               `json:"account_url"`
		Endpoints  map[string]string    `json:"endpoints"`
		GrantTypes []string             `json:"grant_types"`
		Scopes     []ScopeInfo          `json:"scopes"`
		Platforms  []store.DeveloperApp `json:"platforms"`
	}
	decodeInto(t, w, &overview)

	if overview.Issuer != s.Tokens.Issuer() {
		t.Fatalf("issuer 应取自签发器: %q != %q", overview.Issuer, s.Tokens.Issuer())
	}
	if overview.Endpoints["authorization"] != overview.Issuer+"/oauth/authorize" ||
		overview.Endpoints["token"] != overview.Issuer+"/oauth/token" ||
		overview.Endpoints["jwks"] != overview.Issuer+"/oidc/jwks" {
		t.Fatalf("接入端点地址不符: %+v", overview.Endpoints)
	}
	if len(overview.GrantTypes) != 1 || overview.GrantTypes[0] != "authorization_code" {
		t.Fatalf("grant_types 不符: %v", overview.GrantTypes)
	}
	// scope 说明与同意页同源：四语齐备，漏一项就会在开发者中心显示空说明。
	if len(overview.Scopes) != len(store.SupportedScopes) {
		t.Fatalf("scope 目录应覆盖全部受支持 scope: %+v", overview.Scopes)
	}
	for _, item := range overview.Scopes {
		for _, lang := range []string{"zh-CN", "zh-TW", "ja-JP", "en-US"} {
			if strings.TrimSpace(item.Names[lang]) == "" || strings.TrimSpace(item.Descriptions[lang]) == "" {
				t.Fatalf("scope %s 缺少 %s 文案: %+v", item.Code, lang, item)
			}
		}
	}
	// 平台清单只含自有平台（免同意 + 已核验 + 无归属），第三方应用不得混进来。
	if len(overview.Platforms) != 1 || overview.Platforms[0].ID != "metafusion-catalog" {
		t.Fatalf("平台清单不符: %+v", overview.Platforms)
	}
	if !overview.Platforms[0].FirstParty || !overview.Platforms[0].Verified || overview.Platforms[0].OwnerID != "" {
		t.Fatalf("自有平台应免同意、已核验、无归属: %+v", overview.Platforms[0])
	}
}

// TestDeveloperAppRotationKeepsOwnershipBoundary 覆盖轮换：明文只回一次、旧密钥立即失效、
// 别人的轮换请求按不存在处理。
func TestDeveloperAppRotationKeepsOwnershipBoundary(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	owner := store.User{ID: "eeeeeeee-5555-5555-5555-555555555555", Username: "dev-rotate", Role: "user"}
	other := store.User{ID: "ffffffff-6666-6666-6666-666666666666", Username: "dev-snoop", Role: "user"}
	fake.addUser(owner)
	fake.addUser(other)
	ownerBearer := signBearer(t, s, owner)
	otherBearer := signBearer(t, s, other)

	w := doJSON(t, r, http.MethodPost, "/api/developer/apps", ownerBearer, `{"name":"轮换用应用","redirect_uris":["https://rotate.example/cb"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("登记应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	var created developerAppResponse
	decodeInto(t, w, &created)

	if w := doJSON(t, r, http.MethodPost, "/api/developer/apps/"+created.App.ID+"/rotate-secret", otherBearer, ""); w.Code != http.StatusNotFound {
		t.Fatalf("别人的轮换应 404，实际 %d", w.Code)
	}
	w = doJSON(t, r, http.MethodPost, "/api/developer/apps/"+created.App.ID+"/rotate-secret", ownerBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("本人轮换应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	var rotated developerAppResponse
	decodeInto(t, w, &rotated)
	if rotated.ClientSecret == "" || rotated.ClientSecret == created.ClientSecret {
		t.Fatalf("轮换应换出新的明文密钥")
	}
	if store.VerifyClientSecret(fake.secrets[created.App.ID], created.ClientSecret) {
		t.Fatal("轮换后旧密钥必须失效")
	}
	if !store.VerifyClientSecret(fake.secrets[created.App.ID], rotated.ClientSecret) {
		t.Fatal("轮换后新密钥应可用")
	}
}
