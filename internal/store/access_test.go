package store

import "testing"

// 授权断言的唯一口径：令牌带 permissions 时一律以码为准，只有完全没有 permissions
// 声明时（老令牌 / 尚未配置权限组的实例）才按历史 role 兜底。
//
// 这条用例钉住"持一个 auth.* 码 ≠ 管理员"：曾经的 handler.isAdmin 把任意 auth.*
// 前缀当成管理员，持 auth.invites.manage 的成员因此能通过其它管理域的闸门。
func TestCanPrefersPermissionCodesOverRole(t *testing.T) {
	invites := &User{ID: "u-invites", Username: "inviter", Role: "user", Permissions: []string{"auth.invites.manage"}}
	cases := []struct {
		name string
		u    *User
		code string
		want bool
	}{
		{"持码自身放行", invites, "auth.invites.manage", true},
		{"持码不放行其它账号管理码", invites, "auth.users.manage", false},
		{"持码不放行权限组管理码", invites, "auth.groups.manage", false},
		{"持码不放行实例设置码", invites, "auth.settings.manage", false},
		{"持码不放行目录码", invites, "catalog.entity.edit", false},
		{"通配全放行", &User{Role: "user", Permissions: []string{"*"}}, "catalog.entity.edit", true},
		{"通配即管理员", &User{Role: "user", Permissions: []string{"*"}}, WildcardPermission, true},
		{"老令牌 role=admin 兜底", &User{Role: "admin"}, "auth.users.manage", true},
		{"老令牌 role=admin 即管理员", &User{Role: "admin"}, WildcardPermission, true},
		{"老令牌 role=user 不放行", &User{Role: "user"}, "auth.users.manage", false},
		{"老令牌 role=editor 不放行管理码", &User{Role: "editor"}, "auth.users.manage", false},
		{"带上权限声明后角色不再兜底", &User{Role: "admin", Permissions: []string{"catalog.entity.edit"}}, "auth.groups.manage", false},
		{"空身份", nil, "auth.users.manage", false},
	}
	for _, tc := range cases {
		if got := Can(tc.u, tc.code); got != tc.want {
			t.Errorf("%s: Can(%q) = %v，期望 %v", tc.name, tc.code, got, tc.want)
		}
	}
}

// ExpandPermissions 的展开口径：按组顺序去重、遇 * 短路成全权。
// 前端 src/app/admin/components/tabs/accountAccess/api.ts 的 expandPermissions 是它的镜像
// （用于保存前的权限预览），两边必须同口径，否则预览与保存结果不一致。
func TestExpandPermissionsOrderDedupAndWildcard(t *testing.T) {
	groups := []Group{
		{Code: "catalog_editor", Permissions: []string{"catalog.entity.edit", "catalog.relation.edit"}},
		{Code: "member", Permissions: []string{"community.post.create", "catalog.entity.edit"}},
	}
	got := ExpandPermissions(groups)
	want := []string{"catalog.entity.edit", "catalog.relation.edit", "community.post.create"}
	if len(got) != len(want) {
		t.Fatalf("展开结果 %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("展开结果 %v，期望 %v", got, want)
		}
	}
	if wild := ExpandPermissions([]Group{{Code: "member", Permissions: []string{"community.post.create"}}, {Code: "admin", Permissions: []string{"*"}}}); len(wild) != 1 || wild[0] != "*" {
		t.Fatalf("含 * 时应短路为 [*]，实际 %v", wild)
	}
	if empty := ExpandPermissions(nil); len(empty) != 0 {
		t.Fatalf("无组时应为空集合，实际 %v", empty)
	}
}
