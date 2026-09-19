package handler

// 真库上的开发者自助审计：归属隔离、client_id 过滤与匿名 401。
// 未设置 AUTH_TEST_DSN 时跳过；用例自建自清账号、应用与审计行。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

func TestDeveloperAuditLogsAgainstPostgres(t *testing.T) {
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

	ownerID, _, ownerBearer := insertChainUser(t, ctx, st, "user")
	_, _, otherBearer := insertChainUser(t, ctx, st, "user")

	const callback = "https://auditlog.example/auth/callback"
	ownID, otherID := "", ""
	t.Cleanup(func() {
		bg := context.Background()
		for _, id := range []string{ownID, otherID} {
			if id == "" {
				continue
			}
			_, _ = st.DB.ExecContext(bg, "DELETE FROM auth.oauth_audit WHERE client_id=$1", id)
			_, _ = st.DB.ExecContext(bg, "DELETE FROM auth.oauth_clients WHERE id=$1", id)
		}
	})

	register := func(bearer, name string) string {
		t.Helper()
		w := doJSON(t, r, http.MethodPost, "/api/developer/apps", bearer, `{"name":"`+name+`","redirect_uris":["`+callback+`"]}`)
		if w.Code != http.StatusOK {
			t.Fatalf("登记应用 %s: %d %s", name, w.Code, w.Body.String())
		}
		var created developerAppResponse
		decodeInto(t, w, &created)
		if created.App.ID == "" {
			t.Fatalf("登记响应缺应用 id: %s", w.Body.String())
		}
		return created.App.ID
	}
	ownID = register(ownerBearer, "审计看法")
	otherID = register(otherBearer, "别人看法")

	// 各补一条同意审计：归属按客户端的 owner 判定。
	if err := st.RecordOAuthAudit(ctx, store.OAuthAuditEntry{ActorID: ownerID, SubjectID: ownerID, ClientID: ownID, Action: store.OAuthActionConsentAllow, Scopes: []string{"openid"}}); err != nil {
		t.Fatalf("记自己的审计: %v", err)
	}
	var otherUID string
	if err := st.DB.QueryRowContext(ctx, "SELECT owner_user_id::text FROM auth.oauth_clients WHERE id=$1", otherID).Scan(&otherUID); err != nil {
		t.Fatalf("读对面应用归属: %v", err)
	}
	if err := st.RecordOAuthAudit(ctx, store.OAuthAuditEntry{ActorID: otherUID, SubjectID: otherUID, ClientID: otherID, Action: store.OAuthActionConsentAllow, Scopes: []string{"openid"}}); err != nil {
		t.Fatalf("记别人的审计: %v", err)
	}

	// 匿名 401。
	if w := doJSON(t, r, http.MethodGet, "/api/developer/audit-logs", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("匿名应 401，实际 %d：%s", w.Code, w.Body.String())
	}

	// 本人只看到自己应用的行（登记审计 + 同意审计），且带 client_name 与操作者名。
	w := doJSON(t, r, http.MethodGet, "/api/developer/audit-logs", ownerBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("读自己的审计: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Items []store.OwnAppAuditEntry `json:"items"`
	}
	decodeInto(t, w, &got)
	if len(got.Items) != 2 {
		t.Fatalf("应只看到自己应用的 2 条，实际 %+v", got.Items)
	}
	for _, item := range got.Items {
		if item.ClientID != ownID || item.ClientName != "审计看法" {
			t.Fatalf("行归属或名称不符: %+v", item)
		}
		if item.ActorID == "" || item.Actor == "" {
			t.Fatalf("行应带操作者身份: %+v", item)
		}
	}
	if body := w.Body.String(); !strings.Contains(body, "client_name") || !strings.Contains(body, "actor_username") {
		t.Fatalf("响应应含 client_name 与 actor_username：%s", body)
	}

	// client_id 过滤：自己的按出 2 条；别人的回空列表而不 404。
	w = doJSON(t, r, http.MethodGet, "/api/developer/audit-logs?client_id="+ownID, ownerBearer, "")
	decodeInto(t, w, &got)
	if w.Code != http.StatusOK || len(got.Items) != 2 {
		t.Fatalf("按自己应用过滤应回 2 条，实际 %d：%+v", w.Code, got.Items)
	}
	w = doJSON(t, r, http.MethodGet, "/api/developer/audit-logs?client_id="+otherID, ownerBearer, "")
	decodeInto(t, w, &got)
	if w.Code != http.StatusOK || len(got.Items) != 0 {
		t.Fatalf("按别人应用过滤应回空列表，实际 %d：%+v", w.Code, got.Items)
	}
}
