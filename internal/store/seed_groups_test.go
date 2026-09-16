package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// ── 语种口径 ──
//
// 规范语种键取自权限码清单（access.go PermissionCatalog），而不是在测试里另抄一份：
// 系统组名与权限码名是同一份账号数据里的两种"名称"，键必须完全一致，
// 出现 ja / zh-Hant 这类旁支键时，前端按 locale 取值的路径就会漏掉。

func canonicalNameLocales(t *testing.T) []string {
	t.Helper()
	catalog := PermissionCatalog()
	if len(catalog) == 0 {
		t.Fatal("PermissionCatalog() 不应为空：它是四语键口径的来源")
	}
	keys := make([]string, 0, len(catalog[0].Names))
	for k := range catalog[0].Names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// assertLocaleKeys 断言一张名称表恰好用规范语种键（不多不少）。
func assertLocaleKeys(t *testing.T, field, code string, names map[string]string, want []string) {
	t.Helper()
	got := make([]string, 0, len(names))
	for k := range names {
		got = append(got, k)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s 的 %s 语种键为 %v，期望与权限码清单一致 %v", code, field, got, want)
	}
}

// assertLocalizedText 断言名称表里每一语种都有非空译文，且繁中/日文不是英文占位。
func assertLocalizedText(t *testing.T, field, code string, names map[string]string, want []string) {
	t.Helper()
	en := strings.TrimSpace(names["en-US"])
	for _, loc := range want {
		val := strings.TrimSpace(names[loc])
		if val == "" {
			t.Errorf("%s 的 %s 缺少 %s 文案", code, field, loc)
			continue
		}
		if loc != "en-US" && en != "" && val == en {
			t.Errorf("%s 的 %s 在 %s 下仍是英文占位: %q", code, field, loc, val)
		}
	}
}

// TestSystemGroupNamesAreMultilingual 是系统组名称/描述的四语护栏：六类角色是后台权限组的
// 默认集合，缺 zh-TW / ja-JP 时那两种语言的用户在管理台看到的是简体或英文。
// 纯逻辑用例，不需要数据库，也不会被"没设 AUTH_TEST_DSN"跳过。
func TestSystemGroupNamesAreMultilingual(t *testing.T) {
	want := canonicalNameLocales(t)
	groups := systemGroups()
	if len(groups) == 0 {
		t.Fatal("systemGroups() 不应为空")
	}
	seen := map[string]bool{}
	for _, g := range groups {
		if seen[g.code] {
			t.Errorf("系统组码重复: %s", g.code)
		}
		seen[g.code] = true
		assertLocaleKeys(t, "names", g.code, g.names, want)
		assertLocalizedText(t, "names", g.code, g.names, want)
		assertLocaleKeys(t, "descriptions", g.code, g.desc, want)
		assertLocalizedText(t, "descriptions", g.code, g.desc, want)
	}
}

// TestDefaultGroupNamesCoverCanonicalLocales 钉住"新建组没给名称"时的占位名：
// 值是语言中立的组码、四语同值，因此显示文字与旧的两语占位完全一致（不改变用户看到的名称），
// 但名称表结构与其它定义一致，后台编辑器四种语言都能直接看到待填项。
func TestDefaultGroupNamesCoverCanonicalLocales(t *testing.T) {
	const code = "catalog_reviewers"
	names := defaultGroupNames(code)
	want := canonicalNameLocales(t)
	assertLocaleKeys(t, "names", code, names, want)
	for _, loc := range want {
		if names[loc] != code {
			t.Errorf("占位名应等于组码（语言中立），%s 实际为 %q", loc, names[loc])
		}
	}
}

// TestSeedGroupLocaleBackfillIsAdditive 钉住回填的"只增不改"语义：
// 补缺失或仍是英文占位的语种；人工译文与后台改过的英文名一律保留。
func TestSeedGroupLocaleBackfillIsAdditive(t *testing.T) {
	seed := seedGroupByCode(t, "admin")
	cases := []struct {
		name  string
		cur   map[string]string
		want  map[string]string
		added []string
	}{
		{
			name:  "存量行只有 zh-CN/en-US：补齐繁中与日文",
			cur:   map[string]string{"zh-CN": "管理员", "en-US": "Administrator"},
			want:  seed.names,
			added: []string{"zh-TW", "ja-JP"},
		},
		{
			name:  "英文占位换成种子译文",
			cur:   map[string]string{"zh-CN": "管理员", "zh-TW": "Administrator", "ja-JP": "Administrator", "en-US": "Administrator"},
			want:  seed.names,
			added: []string{"zh-TW", "ja-JP"},
		},
		{
			name:  "空串与纯空白视为缺失",
			cur:   map[string]string{"zh-CN": "管理员", "zh-TW": "   ", "ja-JP": "", "en-US": "Administrator"},
			want:  seed.names,
			added: []string{"zh-TW", "ja-JP"},
		},
		{
			name:  "四语齐备：无补丁（幂等）",
			cur:   map[string]string{"zh-CN": "管理员", "zh-TW": "管理員", "ja-JP": "管理者", "en-US": "Administrator"},
			want:  seed.names,
			added: nil,
		},
		{
			name:  "人工译文一律不动",
			cur:   map[string]string{"zh-CN": "运维管理员", "zh-TW": "維運管理員", "ja-JP": "運用管理者", "en-US": "Administrator"},
			want:  map[string]string{"zh-CN": "运维管理员", "zh-TW": "維運管理員", "ja-JP": "運用管理者", "en-US": "Administrator"},
			added: nil,
		},
		{
			name:  "后台改过的英文名是基准，不被种子改回去",
			cur:   map[string]string{"zh-CN": "管理员", "zh-TW": "Admins", "en-US": "Admins"},
			want:  map[string]string{"zh-CN": "管理员", "zh-TW": "管理員", "ja-JP": "管理者", "en-US": "Admins"},
			added: []string{"zh-TW", "ja-JP"},
		},
		{
			name:  "行内多出的语种键保留",
			cur:   map[string]string{"zh-CN": "管理员", "en-US": "Administrator", "fr": "Administrateur"},
			want:  map[string]string{"zh-CN": "管理员", "zh-TW": "管理員", "ja-JP": "管理者", "en-US": "Administrator", "fr": "Administrateur"},
			added: []string{"zh-TW", "ja-JP"},
		},
		{
			name:  "空名称表：四语全补",
			cur:   nil,
			want:  seed.names,
			added: []string{"zh-CN", "zh-TW", "ja-JP", "en-US"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, added := backfillNameLocales(seed.names, tc.cur)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("回填结果 = %v，期望 %v", got, tc.want)
			}
			if !reflect.DeepEqual(added, tc.added) {
				t.Fatalf("补丁清单 = %v，期望 %v", added, tc.added)
			}
			// 只增不改：非空、且不是英文占位的原有值必须原样保留。
			en := strings.TrimSpace(tc.cur["en-US"])
			if en == "" {
				en = strings.TrimSpace(seed.names["en-US"])
			}
			for k, v := range tc.cur {
				trimmed := strings.TrimSpace(v)
				if trimmed == "" || (k != "en-US" && trimmed == en) {
					continue // 缺失或英文占位：允许被补写
				}
				if got[k] != v {
					t.Fatalf("原有 %s = %q 被改成 %q", k, v, got[k])
				}
			}
		})
	}
}

func seedGroupByCode(t *testing.T, code string) seedGroup {
	t.Helper()
	for _, g := range systemGroups() {
		if g.code == code {
			return g
		}
	}
	t.Fatalf("系统组 %s 不在 systemGroups() 里", code)
	return seedGroup{}
}

// ── 真库回填 ──

// TestSeedGroupLocaleBackfillAgainstPostgres 用一次性库证明回填真的落库：
// 造出"旧版播种结果"（系统组只剩 zh-CN/en-US）→ 再播种一次 → 回读四语是否补齐、
// 人工译文与自定义权限是否被保留、以及没有补丁时是否一行都不写。
// 既有测试库（AUTH_TEST_DSN 指向的库）在这个用例里只提供实例地址，里面的行不动。
func TestSeedGroupLocaleBackfillAgainstPostgres(t *testing.T) {
	dsn := createTempDatabase(t)
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	// 旧版播种形状：只有 zh-CN/en-US，is_system 标记也没补上。
	legacyNames := `{"zh-CN": "占位名", "en-US": "Legacy name"}`
	legacyDescs := `{"zh-CN": "占位描述", "en-US": "Legacy description"}`
	if _, err := s.DB.ExecContext(ctx,
		"UPDATE auth.groups SET names=$1::jsonb, descriptions=$2::jsonb, is_system=false WHERE is_system",
		legacyNames, legacyDescs); err != nil {
		t.Fatalf("造存量行: %v", err)
	}
	// 人工译文 + 英文占位混在一行：zh-CN 是人工译文、zh-TW 是英文占位、en-US 是后台改过的英文名。
	if _, err := s.DB.ExecContext(ctx,
		"UPDATE auth.groups SET names=$1::jsonb WHERE code='admin'",
		`{"zh-CN": "运维管理员", "zh-TW": "Legacy name", "en-US": "Legacy name"}`); err != nil {
		t.Fatalf("造人工译文行: %v", err)
	}
	// 改过英文名的描述行：英文名自己是基准，不能被种子改回去。
	if _, err := s.DB.ExecContext(ctx,
		"UPDATE auth.groups SET descriptions=$1::jsonb WHERE code='member'",
		`{"zh-CN": "普通成员（人工）", "en-US": "Regular member (edited)"}`); err != nil {
		t.Fatalf("造改过英文名的行: %v", err)
	}
	// 管理员改过的权限不得被播种覆盖。
	if _, err := s.DB.ExecContext(ctx,
		"UPDATE auth.groups SET permissions='{community.post.create}'::text[] WHERE code='community_moderator'"); err != nil {
		t.Fatalf("造自定义权限行: %v", err)
	}

	if err := s.seedGroups(ctx); err != nil {
		t.Fatalf("seedGroups: %v", err)
	}

	want := canonicalNameLocales(t)
	for _, g := range systemGroups() {
		row := readGroupRow(t, s, ctx, g.code)
		assertLocaleKeys(t, "names", g.code, row.names, want)
		assertLocaleKeys(t, "descriptions", g.code, row.descs, want)
		assertLocalizedText(t, "names", g.code, row.names, want)
		assertLocalizedText(t, "descriptions", g.code, row.descs, want)
		if !row.isSystem {
			t.Errorf("系统组 %s 的 is_system 应被补回 true", g.code)
		}
	}

	admin := readGroupRow(t, s, ctx, "admin")
	if admin.names["zh-CN"] != "运维管理员" {
		t.Errorf("人工译文被覆盖: zh-CN = %q", admin.names["zh-CN"])
	}
	if admin.names["en-US"] != "Legacy name" {
		t.Errorf("后台改过的英文名被种子改回: en-US = %q", admin.names["en-US"])
	}
	if admin.names["zh-TW"] != seedGroupByCode(t, "admin").names["zh-TW"] {
		t.Errorf("英文占位未被换成种子译文: zh-TW = %q", admin.names["zh-TW"])
	}
	member := readGroupRow(t, s, ctx, "member")
	if member.descs["zh-CN"] != "普通成员（人工）" || member.descs["en-US"] != "Regular member (edited)" {
		t.Errorf("改过英文名的描述被覆盖: %v", member.descs)
	}
	if member.descs["ja-JP"] != seedGroupByCode(t, "member").desc["ja-JP"] {
		t.Errorf("描述缺的日文未补齐: %v", member.descs)
	}
	mod := readGroupRow(t, s, ctx, "community_moderator")
	if mod.perms != "community.post.create" {
		t.Errorf("管理员改过的权限被播种覆盖: %q", mod.perms)
	}

	// 幂等：这一轮没有任何可补的语种、is_system 也已正确，因此不该发 UPDATE。
	// xmin 是行版本，任何 UPDATE 都会换掉它，用它证明"没有无谓写入"。
	before := groupXmins(t, s, ctx)
	if err := s.seedGroups(ctx); err != nil {
		t.Fatalf("第二次 seedGroups: %v", err)
	}
	after := groupXmins(t, s, ctx)
	for code, x := range before {
		if after[code] != x {
			t.Errorf("没有补丁时不应发 UPDATE，但 %s 的行版本变了: %s → %s", code, x, after[code])
		}
	}
}

type groupRow struct {
	names    map[string]string
	descs    map[string]string
	perms    string
	isSystem bool
}

func readGroupRow(t *testing.T, s *Store, ctx context.Context, code string) groupRow {
	t.Helper()
	var names, descs []byte
	var row groupRow
	if err := s.DB.QueryRowContext(ctx,
		"SELECT names,descriptions,array_to_string(permissions,','),is_system FROM auth.groups WHERE code=$1", code).
		Scan(&names, &descs, &row.perms, &row.isSystem); err != nil {
		t.Fatalf("回读 %s: %v", code, err)
	}
	row.names = decodeNames(names)
	row.descs = decodeNames(descs)
	return row
}

// groupXmins 回读每个组的行版本（xmin），用于断言"没有补丁时不写库"。
func groupXmins(t *testing.T, s *Store, ctx context.Context) map[string]string {
	t.Helper()
	rows, err := s.DB.QueryContext(ctx, "SELECT code, xmin::text FROM auth.groups")
	if err != nil {
		t.Fatalf("回读 xmin: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var code, xmin string
		if err := rows.Scan(&code, &xmin); err != nil {
			t.Fatalf("扫描 xmin: %v", err)
		}
		out[code] = xmin
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历 xmin: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("auth.groups 里没有系统组：播种没有生效")
	}
	return out
}

var tempDBName = regexp.MustCompile("^[a-z][a-z0-9_]{0,50}$")

// createTempDatabase 在同一个 PostgreSQL 实例上新建一次性库并返回指向它的连接串，
// 用例结束自动 DROP。需要写入的用例必须用它：既有测试库里的行一律不动。
// 库名由本函数生成（不含外部输入），仍按标识符白名单再校验一次再拼进 DDL。
func createTempDatabase(t *testing.T) string {
	t.Helper()
	base, err := url.Parse(testutil.DSN(t))
	if err != nil {
		t.Fatalf("解析 AUTH_TEST_DSN: %v", err)
	}
	name := fmt.Sprintf("mf_auth_seed_test_%d", time.Now().UnixNano())
	if !tempDBName.MatchString(name) {
		t.Fatalf("一次性库名非法: %s", name)
	}

	var adm *sql.DB
	var lastErr error
	for _, dbName := range []string{"postgres", "template1"} {
		conn, err := sql.Open("postgres", withDatabase(base, dbName))
		if err != nil {
			lastErr = err
			continue
		}
		if _, err = conn.Exec("CREATE DATABASE " + name); err != nil {
			lastErr = err
			conn.Close()
			continue
		}
		adm = conn
		break
	}
	if adm == nil {
		t.Fatalf("创建一次性库 %s 失败（需要与 AUTH_TEST_DSN 同实例且角色可建库）: %v", name, lastErr)
	}
	t.Cleanup(func() {
		// 先踢掉残留连接，否则 DROP DATABASE 会因"正被其它会话使用"失败。
		_, _ = adm.Exec("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()", name)
		if _, err := adm.Exec("DROP DATABASE IF EXISTS " + name); err != nil {
			t.Errorf("清理一次性库 %s: %v", name, err)
		}
		adm.Close()
	})
	return withDatabase(base, name)
}

// withDatabase 返回指向同一实例、换一个库名的连接串。
func withDatabase(base *url.URL, dbName string) string {
	clone := *base
	clone.Path = "/" + dbName
	return clone.String()
}
