package store

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// scope 是「第三方到底能拿到什么」的唯一判据。这三条规则写错不会编译失败，
// 只会以"多给了一个 scope"或"合法的 scope 被拒"的形式暴露。
func TestParseScopesDefaultsAndRejectsUnknown(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
		bad  bool
	}{
		{"", []string{"profile"}, false}, // 不传 scope 的老客户端仍然拿到 profile（与拆分前一致）
		{"profile", []string{"profile"}, false},
		{"openid profile email", []string{"openid", "profile", "email"}, false},
		{"profile profile", []string{"profile"}, false}, // 重复项去重
		{"  email   profile ", []string{"email", "profile"}, false},
		{"phone", nil, true}, // 不支持的 scope 报错，不静默丢弃
		{"openid phone", nil, true},
	}
	for _, tc := range cases {
		got, err := ParseScopes(tc.raw)
		if tc.bad {
			if err == nil || err.Error() != "invalid_scope" {
				t.Fatalf("ParseScopes(%q) 应报 invalid_scope，实际 %v", tc.raw, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseScopes(%q) 失败: %v", tc.raw, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("ParseScopes(%q) = %v，期望 %v", tc.raw, got, tc.want)
		}
	}
}

// 错误响应要能点明是哪一项不被支持，否则第三方只能靠猜。
func TestUnsupportedScopesNamesTheOffendingEntries(t *testing.T) {
	if got := UnsupportedScopes("openid phone"); !reflect.DeepEqual(got, []string{"phone"}) {
		t.Fatalf("UnsupportedScopes = %v", got)
	}
	if got := UnsupportedScopes("openid profile email"); len(got) != 0 {
		t.Fatalf("受支持的 scope 不应出现在 unsupported 里: %v", got)
	}
	if got := UnsupportedScopes(""); len(got) != 0 {
		t.Fatalf("空 scope 不应报不支持: %v", got)
	}
}

// 收敛必须是交集：客户端白名单里没有的 scope，请求里带了也不给。
func TestConvergeScopesIsIntersectionInRequestOrder(t *testing.T) {
	cases := []struct {
		name      string
		requested []string
		allowed   []string
		want      []string
	}{
		{"按请求顺序取交集", []string{"profile", "email", "openid"}, []string{"email", "openid", "profile"}, []string{"profile", "email", "openid"}},
		{"白名单外的请求项被丢掉", []string{"openid", "email"}, []string{"openid"}, []string{"openid"}},
		{"无交集时为空", []string{"email"}, []string{"openid", "profile"}, []string{}},
		{"白名单为空时为空", []string{"openid"}, nil, []string{}},
	}
	for _, tc := range cases {
		got := ConvergeScopes(tc.requested, tc.allowed)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: ConvergeScopes = %v，期望 %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: ConvergeScopes = %v，期望 %v", tc.name, got, tc.want)
			}
		}
	}
}

// 存量授权码里可能有已不再支持的 scope：换码时按支持集合过滤，
// 不允许把它当成默认 scope 放宽，也不允许原样发出去。
func TestSupportedSubsetFiltersLegacyScopes(t *testing.T) {
	got := SupportedSubset([]string{"openid", "phone", "email"})
	if !reflect.DeepEqual(got, []string{"openid", "email"}) {
		t.Fatalf("SupportedSubset = %v", got)
	}
}

// 客户端白名单列默认值就是"老客户端"的白名单：它必须覆盖全部受支持的 scope，
// 否则新增 scope 或者改动默认值时，不传 scope 的老调用链会直接被拒。
var clientScopesDefaultRe = regexp.MustCompile(`oauth_clients ADD COLUMN IF NOT EXISTS scopes text\[\] NOT NULL DEFAULT '\{([a-z,]+)\}'`)

func TestSchemaClientScopesDefaultCoversSupportedScopes(t *testing.T) {
	m := clientScopesDefaultRe.FindStringSubmatch(schema)
	if m == nil {
		t.Fatal("建表语句里找不到 oauth_clients.scopes 的默认值")
	}
	allowed := strings.Split(m[1], ",")
	for _, code := range SupportedScopes {
		if len(ConvergeScopes([]string{code}, allowed)) == 0 {
			t.Fatalf("列默认白名单 %v 没有覆盖受支持的 scope %s", allowed, code)
		}
	}
	if len(ConvergeScopes([]string{DefaultScope}, allowed)) != 1 {
		t.Fatalf("默认 scope %s 不在列默认白名单里: %v", DefaultScope, allowed)
	}
	sorted := append([]string{}, allowed...)
	sort.Strings(sorted)
	want := append([]string{}, SupportedScopes...)
	sort.Strings(want)
	if !reflect.DeepEqual(sorted, want) {
		t.Fatalf("列默认白名单 %v 与 SupportedScopes %v 不一致", allowed, SupportedScopes)
	}
}

// 回调地址逐字相等：白名单是完整地址，不做前缀/通配匹配。
func TestRedirectURIAllowedRequiresExactMatch(t *testing.T) {
	allowed := []string{"https://alpha.example/auth/callback", "http://localhost:3000/auth/callback"}
	for _, uri := range allowed {
		if !RedirectURIAllowed(allowed, uri) {
			t.Fatalf("白名单里的地址应放行: %s", uri)
		}
	}
	for _, uri := range []string{
		"https://alpha.example/auth/callback/extra",
		"https://alpha.example.evil.test/auth/callback",
		"https://alpha.example/auth",
		"",
	} {
		if RedirectURIAllowed(allowed, uri) {
			t.Fatalf("非白名单地址不该放行: %s", uri)
		}
	}
}

// 管理 API 的客户端白名单：非空且只允许受支持的 scope。
func TestValidateClientScopes(t *testing.T) {
	if err := ValidateClientScopes([]string{"openid", "profile"}); err != nil {
		t.Fatalf("合法白名单被拒: %v", err)
	}
	if err := ValidateClientScopes(nil); err == nil {
		t.Fatal("空白名单必须拒绝：那份客户端将永远换不到令牌")
	}
	if err := ValidateClientScopes([]string{"openid", "phone"}); err == nil {
		t.Fatal("含不支持 scope 的白名单必须拒绝")
	}
}
