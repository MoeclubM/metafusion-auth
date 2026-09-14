package handler

import (
	"sort"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// frozenRoutes 是账号服务的切流契约：与主仓库 catalog 包的路由**逐字一致**，
// 另外按 OIDC 标准在根路径提供发现文档与 JWKS（发现文档里的地址取自 issuer，
// 两个入口内容完全相同）。改动路由会在这里失败，而不是等线上 404 才发现。
var frozenRoutes = []string{
	"GET /.well-known/jwks.json",
	"GET /.well-known/openid-configuration",
	"GET /api/.well-known/openid-configuration",
	"GET /api/admin/users",
	"GET /api/auth/me",
	"GET /api/auth/settings",
	"GET /api/oauth/authorize",
	"GET /api/oauth/clients",
	"GET /api/oauth/userinfo",
	"GET /api/oidc/jwks",
	"GET /api/setup",
	"POST /api/admin/users",
	"POST /api/auth/change-password",
	"POST /api/auth/login",
	"POST /api/auth/logout",
	"POST /api/auth/logout-all",
	"POST /api/auth/refresh",
	"POST /api/oauth/token",
	"POST /api/setup",
	"PUT /api/admin/users/:id/password",
	"PUT /api/admin/users/:id/role",
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
