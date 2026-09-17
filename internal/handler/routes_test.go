package handler

import (
	"sort"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// frozenRoutes 是账号服务的路由契约。账号服务拆出后自有其账号生命周期端点
// （注册 / 邀请码 / 权限组 / 实例设置），与目录服务不再是同一份路由表；
// 改动路由会在这里失败，而不是等线上 404 才发现。
// 另外按 OIDC 标准在根路径提供发现文档与 JWKS（发现文档里的地址取自 issuer，
// 两个入口内容完全相同）。改动路由会在这里失败，而不是等线上 404 才发现。
var frozenRoutes = []string{
	"DELETE /api/admin/groups/:code",
	"DELETE /api/auth/oauth-grants/:client_id",
	"DELETE /api/admin/oauth/clients/:id",
	"GET /.well-known/jwks.json",
	"GET /.well-known/openid-configuration",
	"GET /api/.well-known/openid-configuration",
	"GET /api/admin/groups",
	"GET /api/admin/invites",
	"GET /api/admin/oauth/audits",
	"GET /api/admin/oauth/clients",
	"GET /api/admin/permissions",
	"GET /api/admin/settings",
	"GET /api/admin/users",
	"GET /api/auth/invite",
	"GET /api/auth/me",
	"GET /api/auth/oauth-grants",
	"GET /api/auth/settings",
	"GET /api/developer/apps",
	"GET /api/developer/apps/:id",
	"GET /api/developer/overview",
	"DELETE /api/developer/apps/:id",
	"GET /api/oauth/authorize",
	"GET /api/oauth/userinfo",
	"GET /api/oidc/jwks",
	"GET /api/setup",
	"GET /api/users/:id",
	"POST /api/admin/groups",
	"POST /api/admin/invites",
	"POST /api/admin/invites/:code/revoke",
	"POST /api/admin/oauth/clients",
	"POST /api/admin/oauth/clients/:id/rotate-secret",
	"POST /api/admin/oauth/clients/:id/revoke-tokens",
	"POST /api/admin/users",
	"POST /api/admin/users/:id/revoke-oauth-tokens",
	"POST /api/auth/invite",
	"POST /api/auth/login",
	"POST /api/auth/logout",
	"POST /api/auth/logout-all",
	"POST /api/auth/refresh",
	"POST /api/auth/register",
	"POST /api/developer/apps",
	"POST /api/developer/apps/:id/rotate-secret",
	"POST /api/oauth/token",
	"POST /api/setup",
	"PUT /api/admin/groups/:code",
	"PUT /api/admin/oauth/clients/:id",
	"PUT /api/admin/settings",
	"PUT /api/admin/users/:id/groups",
	"PUT /api/admin/users/:id/password",
	"PUT /api/admin/users/:id/ban",
	"PUT /api/admin/users/:id/role",
	"PUT /api/developer/apps/:id",
	"PUT /api/auth/password",
}

func TestRoutesMatchFrozenContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(&store.Store{}).Register(r)
	got := []string{}
	for _, route := range r.Routes() {
		got = append(got, route.Method+" "+route.Path)
	}
	sort.Strings(got)
	want := append([]string{}, frozenRoutes...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("路由数量 = %d, 期望 %d\n实际:\n%s", len(got), len(want), join(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 条不一致：实际 %s / 期望 %s\n实际全集:\n%s", i, got[i], want[i], join(got))
		}
	}
}

func join(items []string) string {
	out := ""
	for _, s := range items {
		out += s + "\n"
	}
	return out
}
