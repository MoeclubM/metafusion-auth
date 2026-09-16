package store

import (
	"regexp"
	"strings"
	"testing"
)

// frozenTableDefs 是**线上 auth schema 的终态**：它最初由主仓库当年的 schema.sql（该文件已随主仓库
// （PKCE 列）建出来，账号拆分后由本服务的 Init 接管。之所以继续冻结：这些列形状是运行中的
// 数据与历史会话/令牌的兼容基线，改错了编译与静态检查都发现不了，只有到线上才会以
// "登录失败"或"查不到会话"的形式暴露。
//
// 注意：主仓库现在**不再**创建 auth schema 的对象（schema.sql 与其后续迁移都已随迁移基线收敛删除），
// 因此这份冻结值是唯一来源，不能再拿主仓库的文件做对照。
var frozenTableDefs = map[string]map[string]string{
	"auth.users": {
		"id":            "id uuid primary key",
		"username":      "username text not null unique",
		"email":         "email text not null default ''",
		"password_hash": "password_hash text not null",
		"role":          "role text not null check (role in ('user','editor','admin'))",
	},
	"auth.sessions": {
		"token_hash": "token_hash text primary key",
		"user_id":    "user_id uuid not null references auth.users(id)",
		"expires_at": "expires_at timestamptz not null",
	},
	"auth.oauth_clients": {
		"id":            "id text primary key",
		"secret_hash":   "secret_hash text not null",
		"name":          "name text not null",
		"redirect_uris": "redirect_uris text[] not null default '{}'",
		"scopes":        "scopes text[] not null default '{openid,profile,email}'",
		"trusted":       "trusted boolean not null default false",
		"disabled":      "disabled boolean not null default false",
		"owner_user_id": "owner_user_id uuid references auth.users(id) on delete set null",
		"description":   "description text not null default ''",
		"homepage_url":  "homepage_url text not null default ''",
		"verified":      "verified boolean not null default false",
		"created_at":    "created_at timestamptz not null default now()",
	},
	"auth.oauth_codes": {
		"code":                  "code text primary key",
		"client_id":             "client_id text not null references auth.oauth_clients(id) on delete cascade",
		"user_id":               "user_id uuid not null references auth.users(id) on delete cascade",
		"redirect_uri":          "redirect_uri text not null",
		"scope":                 "scope text not null default 'profile'",
		"expires_at":            "expires_at timestamptz not null",
		"used":                  "used boolean not null default false",
		"code_challenge":        "code_challenge text not null default ''",
		"code_challenge_method": "code_challenge_method text not null default ''",
	},
	"auth.oauth_tokens": {
		"token_hash": "token_hash text primary key",
		"client_id":  "client_id text not null references auth.oauth_clients(id) on delete cascade",
		"user_id":    "user_id uuid not null references auth.users(id) on delete cascade",
		"scope":      "scope text not null default 'profile'",
		"expires_at": "expires_at timestamptz not null",
		"jti":        "jti text not null default ''",
	},
}

var (
	createTableRe = regexp.MustCompile(`(?is)^\s*create table if not exists\s+([a-z_.]+)\s*\(([\s\S]*)\)\s*$`)
	addColumnRe   = regexp.MustCompile(`(?is)^\s*alter table\s+([a-z_.]+)\s+add column if not exists\s+([a-z_]+)\s+([^;]*)$`)
	identRe       = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
)

func splitTopLevel(s, sep string) []string {
	out := []string{}
	depth := 0
	cur := strings.Builder{}
	for _, ch := range s {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		}
		if string(ch) == sep && depth == 0 {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(ch)
	}
	out = append(out, cur.String())
	return out
}

func stripLineComments(ddl string) string {
	lines := strings.Split(ddl, "\n")
	for i, line := range lines {
		if j := strings.Index(line, "--"); j >= 0 {
			lines[i] = line[:j]
		}
	}
	return strings.Join(lines, "\n")
}

func normalizeDef(s string) string {
	if i := strings.Index(s, "--"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(strings.ToLower(strings.Join(strings.Fields(s), " ")), ",")
}

func parseSchema(t *testing.T, ddl string) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	for _, stmt := range splitTopLevel(stripLineComments(ddl), ";") {
		if m := createTableRe.FindStringSubmatch(stmt); m != nil {
			cols := map[string]string{}
			for _, entry := range splitTopLevel(m[2], ",") {
				def := normalizeDef(entry)
				if def == "" {
					continue
				}
				name := strings.Fields(def)[0]
				switch name {
				case "primary", "unique", "foreign", "check", "constraint":
					continue
				}
				if !identRe.MatchString(name) {
					continue
				}
				cols[name] = def
			}
			out[strings.ToLower(strings.TrimSpace(m[1]))] = cols
			continue
		}
		// 建表后补列（PKCE 两列）也要计入列集合。
		if m := addColumnRe.FindStringSubmatch(stmt); m != nil {
			key := strings.ToLower(strings.TrimSpace(m[1]))
			cols, ok := out[key]
			if !ok {
				cols = map[string]string{}
				out[key] = cols
			}
			cols[strings.ToLower(m[2])] = normalizeDef(m[2] + " " + m[3])
		}
	}
	return out
}

func TestSchemaMatchesCatalogTerminalShape(t *testing.T) {
	parsed := parseSchema(t, schema)
	for table, want := range frozenTableDefs {
		got, ok := parsed[table]
		if !ok {
			t.Fatalf("建表语句缺少表 %s", table)
		}
		for col, wantDef := range want {
			gotDef, ok := got[col]
			if !ok {
				t.Fatalf("%s 缺少列 %s（主仓库终态：%s）", table, col, wantDef)
			}
			if gotDef != wantDef {
				t.Fatalf("%s.%s 定义漂移：\n  期望 %s\n  实际 %s", table, col, wantDef, gotDef)
			}
		}
		for col := range got {
			if _, ok := want[col]; !ok {
				t.Fatalf("%s 多出列 %s（主仓库 auth schema 没有它）", table, col)
			}
		}
	}
}
