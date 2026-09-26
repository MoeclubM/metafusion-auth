package handler

// 开发者自助审计的内存用例：归属隔离、client_id 过滤与匿名 401。
// 真库上的同一链路见 TestDeveloperAuditLogsAgainstPostgres。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

func TestDeveloperAuditLogsOnlyOwnApps(t *testing.T) {
	r, s, fake := newOAuthTestServer(t)
	owner := store.User{ID: "aaaaaaaa-1111-1111-1111-111111111111", Username: "audit-owner"}
	other := store.User{ID: "bbbbbbbb-2222-2222-2222-222222222222", Username: "audit-other"}
	fake.addUser(owner)
	fake.addUser(other)
	ownerBearer := signBearer(t, s, owner)
	otherBearer := signBearer(t, s, other)

	// 未登录 401：与其它开发者面入口同一口径。
	if w := doJSON(t, r, http.MethodGet, "/api/developer/audit-logs", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("匿名应 401，实际 %d：%s", w.Code, w.Body.String())
	}

	// 各登记一个应用：登记本身会留一条 client_create 审计。
	w := doJSON(t, r, http.MethodPost, "/api/developer/apps", ownerBearer, `{"name":"我的应用","redirect_uris":["https://own.example/cb"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("登记自己的应用：%d %s", w.Code, w.Body.String())
	}
	var own developerAppResponse
	decodeInto(t, w, &own)
	w = doJSON(t, r, http.MethodPost, "/api/developer/apps", otherBearer, `{"name":"别人的应用","redirect_uris":["https://other.example/cb"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("登记别人的应用：%d %s", w.Code, w.Body.String())
	}
	var theirs developerAppResponse
	decodeInto(t, w, &theirs)

	// 再各补一条同意审计：归属按客户端的 owner 判定，与动作类型无关。
	ctx := context.Background()
	if err := fake.RecordOAuthAudit(ctx, store.OAuthAuditEntry{ActorID: owner.ID, SubjectID: owner.ID, ClientID: own.App.ID, Action: store.OAuthActionConsentAllow, Scopes: []string{"openid"}}); err != nil {
		t.Fatalf("记自己的审计：%v", err)
	}
	if err := fake.RecordOAuthAudit(ctx, store.OAuthAuditEntry{ActorID: other.ID, SubjectID: other.ID, ClientID: theirs.App.ID, Action: store.OAuthActionConsentAllow, Scopes: []string{"openid"}}); err != nil {
		t.Fatalf("记别人的审计：%v", err)
	}

	// 本人只看到自己应用的行：client_create + consent_allow，且看不到别人的。
	w = doJSON(t, r, http.MethodGet, "/api/developer/audit-logs", ownerBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("读自己的审计：%d %s", w.Code, w.Body.String())
	}
	var got struct {
		Items []store.OwnAppAuditEntry `json:"items"`
	}
	decodeInto(t, w, &got)
	if len(got.Items) != 2 {
		t.Fatalf("应只看到自己应用的 2 条，实际 %+v", got.Items)
	}
	for _, item := range got.Items {
		if item.ClientID != own.App.ID {
			t.Fatalf("混入了别人的审计行：%+v", item)
		}
		if item.ClientName != "我的应用" {
			t.Fatalf("应带客户端名称：%+v", item)
		}
		if item.Actor != owner.Username || item.ActorID != owner.ID {
			t.Fatalf("应带操作者身份：%+v", item)
		}
		if item.Action == "" {
			t.Fatalf("审计行缺动作：%+v", item)
		}
		// CreatedAt 只在真库断言：内存替身不写库时间（见 TestDeveloperAuditLogsAgainstPostgres）。
	}
	if body := w.Body.String(); !strings.Contains(body, "client_name") || !strings.Contains(body, "actor_username") {
		t.Fatalf("响应应含 client_name 与 actor_username：%s", body)
	}

	// client_id 过滤：自己的应用按出 2 条；别人的应用回空列表而不 404。
	w = doJSON(t, r, http.MethodGet, "/api/developer/audit-logs?client_id="+own.App.ID, ownerBearer, "")
	decodeInto(t, w, &got)
	if w.Code != http.StatusOK || len(got.Items) != 2 {
		t.Fatalf("按自己应用过滤应回 2 条，实际 %d：%+v", w.Code, got.Items)
	}
	w = doJSON(t, r, http.MethodGet, "/api/developer/audit-logs?client_id="+theirs.App.ID, ownerBearer, "")
	decodeInto(t, w, &got)
	if w.Code != http.StatusOK || len(got.Items) != 0 {
		t.Fatalf("按别人应用过滤应回空列表（不 404），实际 %d：%+v", w.Code, got.Items)
	}

	// 对面也只能看到自己的：互相不可见。
	w = doJSON(t, r, http.MethodGet, "/api/developer/audit-logs", otherBearer, "")
	decodeInto(t, w, &got)
	if w.Code != http.StatusOK || len(got.Items) != 2 {
		t.Fatalf("对面应只看到自己的 2 条，实际 %d：%+v", w.Code, got.Items)
	}
	for _, item := range got.Items {
		if item.ClientID != theirs.App.ID {
			t.Fatalf("对面看到了不属于他的行：%+v", item)
		}
	}

	// limit 生效：只要最新 1 条。
	w = doJSON(t, r, http.MethodGet, "/api/developer/audit-logs?limit=1", ownerBearer, "")
	decodeInto(t, w, &got)
	if w.Code != http.StatusOK || len(got.Items) != 1 {
		t.Fatalf("limit=1 应只回 1 条，实际 %d：%+v", w.Code, got.Items)
	}
}
