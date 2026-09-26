package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 新增端点的准入门槛（不建库）：自助授权端点只认登录身份，封禁端点要权限码；
// banned 字段缺失按非法载荷拒绝——把"没传"当成解封会让一次误请求悄悄放人进来。
func TestBanAndGrantEndpointGates(t *testing.T) {
	r, s, _ := newOAuthTestServer(t)
	const other = "99999999-9999-9999-9999-999999999999"

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/api/auth/oauth-grants"},
		{http.MethodDelete, "/api/auth/oauth-grants/mfc-demo"},
		{http.MethodPut, "/api/admin/users/" + other + "/ban"},
	} {
		if w := doJSON(t, r, req.method, req.path, "", "{}"); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 匿名应 401，实际 %d", req.method, req.path, w.Code)
		}
	}

	member := store.User{ID: "77777777-7777-7777-7777-777777777777", Username: "member", Permissions: []string{"community.post.create"}}
	memberBearer := signBearer(t, s, member)
	if w := doJSON(t, r, http.MethodPut, "/api/admin/users/"+other+"/ban", memberBearer, "{\"banned\":true}"); w.Code != http.StatusForbidden {
		t.Fatalf("无 auth.users.manage 应 403，实际 %d", w.Code)
	}

	ops := store.User{ID: "88888888-8888-8888-8888-888888888888", Username: "ops", Permissions: []string{"auth.users.manage"}}
	opsBearer := signBearer(t, s, ops)
	if w := doJSON(t, r, http.MethodPut, "/api/admin/users/"+other+"/ban", opsBearer, "{}"); w.Code != http.StatusBadRequest {
		t.Fatalf("缺 banned 字段应 400，实际 %d / %s", w.Code, w.Body.String())
	}
}

// 封禁的端到端回归（真库）：管理员封禁 → 该账号登录 403 account_banned、手里的旧令牌立刻 401；
// 解封后恢复登录。未设置 AUTH_TEST_DSN 时跳过。
func TestBanEndToEndAgainstPostgres(t *testing.T) {
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

	memberID, memberName, memberBearer := insertChainUser(t, ctx, st, "user")
	_, _, adminBearer := insertChainUser(t, ctx, st, "admin")

	if w := do(t, r, http.MethodGet, "/api/auth/me", memberBearer); w.Code != http.StatusOK {
		t.Fatalf("封禁前 /auth/me 应 200，实际 %d", w.Code)
	}
	if w := doJSON(t, r, http.MethodPut, "/api/admin/users/"+memberID+"/ban", adminBearer, "{\"banned\":true}"); w.Code != http.StatusOK {
		t.Fatalf("封禁应 200，实际 %d / %s", w.Code, w.Body.String())
	}

	w := doJSON(t, r, http.MethodPost, "/api/auth/login", "", "{\"username\":\""+memberName+"\",\"password\":\""+chainTestPassword+"\"}")
	if w.Code != http.StatusForbidden {
		t.Fatalf("被封禁账号登录应 403，实际 %d / %s", w.Code, w.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	decodeInto(t, w, &body)
	if body.Error != "account_banned" {
		t.Fatalf("错误码应为 account_banned，实际 %q", body.Error)
	}
	if w := do(t, r, http.MethodGet, "/api/auth/me", memberBearer); w.Code != http.StatusUnauthorized {
		t.Fatalf("封禁后旧令牌应 401，实际 %d", w.Code)
	}

	if w := doJSON(t, r, http.MethodPut, "/api/admin/users/"+memberID+"/ban", adminBearer, "{\"banned\":false}"); w.Code != http.StatusOK {
		t.Fatalf("解封应 200，实际 %d / %s", w.Code, w.Body.String())
	}
	w = doJSON(t, r, http.MethodPost, "/api/auth/login", "", "{\"username\":\""+memberName+"\",\"password\":\""+chainTestPassword+"\"}")
	if w.Code != http.StatusOK {
		t.Fatalf("解封后应能登录，实际 %d / %s", w.Code, w.Body.String())
	}
}
