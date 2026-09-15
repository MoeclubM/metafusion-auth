package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// 账号生命周期端点必须在路由表里：前端注册页签、个人邀请页、管理台设置与权限组都按这些路径调用。
// 这里只验证"路由存在 + 鉴权边界先于业务"，不需要数据库。
func TestAccessRoutesExistAndEnforceAuth(t *testing.T) {
	r, s := newTestServer(t)
	public := []struct{ method, path string }{
		{http.MethodPost, "/api/auth/register"},
		{http.MethodGet, "/api/auth/invite"},
		{http.MethodPost, "/api/auth/invite"},
		{http.MethodGet, "/api/auth/settings"},
	}
	for _, p := range public {
		w := do(t, r, p.method, p.path, "")
		if w.Code == http.StatusNotFound {
			t.Errorf("%s %s 不存在", p.method, p.path)
		}
	}
	admin := []struct{ method, path string }{
		{http.MethodGet, "/api/admin/settings"},
		{http.MethodPut, "/api/admin/settings"},
		{http.MethodGet, "/api/admin/groups"},
		{http.MethodPost, "/api/admin/groups"},
		{http.MethodGet, "/api/admin/permissions"},
		{http.MethodGet, "/api/admin/invites"},
		{http.MethodPost, "/api/admin/invites"},
	}
	for _, p := range admin {
		if w := do(t, r, p.method, p.path, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 匿名应 401，实际 %d", p.method, p.path, w.Code)
		}
	}

	// 权限组模型下不再"role==admin 一刀切"：普通成员访问管理端点必须 403。
	member := store.User{ID: "22222222-2222-2222-2222-222222222222", Username: "member", Role: "user", Groups: []string{"member"}, Permissions: []string{"community.post.create"}}
	memberToken, _, _, err := s.Tokens.Sign(member)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, p := range admin {
		if w := do(t, r, p.method, p.path, memberToken); w.Code != http.StatusForbidden {
			t.Errorf("%s %s 普通成员应 403，实际 %d", p.method, p.path, w.Code)
		}
	}
	// 持有对应权限码的自定义组应当通过闸门（/admin/permissions 是纯内存端点，不依赖数据库）。
	manager := store.User{ID: "33333333-3333-3333-3333-333333333333", Username: "ops", Role: "user", Groups: []string{"custom_ops"}, Permissions: []string{"auth.groups.manage"}}
	managerToken, _, _, err := s.Tokens.Sign(manager)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if w := do(t, r, http.MethodGet, "/api/admin/permissions", managerToken); w.Code != http.StatusOK {
		t.Errorf("持有 auth.groups.manage 的成员应可读权限码清单，实际 %d", w.Code)
	}
	if w := do(t, r, http.MethodGet, "/api/admin/permissions", memberToken); w.Code != http.StatusForbidden {
		t.Errorf("普通成员读权限码清单应 403，实际 %d", w.Code)
	}
	// 权限码清单必须包含各子系统声明的码，且全部格式合法（管理台据此渲染可选项）。
	var payload struct {
		Items []store.PermissionCode `json:"items"`
	}
	body := do(t, r, http.MethodGet, "/api/admin/permissions", managerToken)
	if err := json.Unmarshal(body.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析权限码清单失败: %v", err)
	}
	seen := map[string]bool{}
	for _, it := range payload.Items {
		if !store.ValidPermissionCode(it.Code) {
			t.Errorf("内置权限码格式非法: %s", it.Code)
		}
		seen[it.Code] = true
	}
	for _, code := range []string{"catalog.entity.edit", "community.post.moderate", "auth.groups.manage"} {
		if !seen[code] {
			t.Errorf("权限码清单缺少 %s", code)
		}
	}
}
