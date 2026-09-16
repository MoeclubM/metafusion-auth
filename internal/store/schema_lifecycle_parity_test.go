package store

import "testing"

// 账号生命周期四张表的列形状冻结（实例设置 / 权限组 / 成员关系 / 邀请码）。
//
// 与 schema_parity_test.go 那份"历史终态"分开维护：那一份冻的是拆分前的既有列
// （改错会导致登录/会话失败），这一份冻的是本轮新增的注册与授权基础 —— 列名或
// 默认值改错不会编译失败，只会在运行时以"注册 500 / 邀请码不生效"的形式暴露。
// 复用同一套 DDL 解析与归一化工具（同包 parseSchema）。
var frozenLifecycleTableDefs = map[string]map[string]string{
	"auth.instance_settings": {
		"key":        "key text primary key",
		"value":      "value jsonb not null",
		"updated_at": "updated_at timestamptz not null default now()",
	},
	"auth.groups": {
		"id":           "id uuid primary key",
		"code":         "code text not null unique check (code ~ '^[a-z][a-z0-9_-]{1,63}$')",
		"names":        "names jsonb not null default '{}'::jsonb",
		"descriptions": "descriptions jsonb not null default '{}'::jsonb",
		"permissions":  "permissions text[] not null default '{}'",
		"is_system":    "is_system boolean not null default false",
		"sort_order":   "sort_order int not null default 0",
		"created_at":   "created_at timestamptz not null default now()",
	},
	"auth.user_groups": {
		"user_id":    "user_id uuid not null references auth.users(id) on delete cascade",
		"group_id":   "group_id uuid not null references auth.groups(id) on delete cascade",
		"granted_by": "granted_by uuid",
		"granted_at": "granted_at timestamptz not null default now()",
	},
	"auth.invites": {
		"code":       "code text primary key",
		"created_by": "created_by uuid references auth.users(id) on delete set null",
		"note":       "note text not null default ''",
		"max_uses":   "max_uses int not null default 1 check (max_uses > 0)",
		"used_count": "used_count int not null default 0 check (used_count >= 0)",
		"revoked":    "revoked boolean not null default false",
		"expires_at": "expires_at timestamptz",
		"created_at": "created_at timestamptz not null default now()",
	},
	"auth.invite_uses": {
		"invite_code": "invite_code text not null references auth.invites(code) on delete cascade",
		"user_id":     "user_id uuid not null references auth.users(id) on delete cascade",
		"used_at":     "used_at timestamptz not null default now()",
	},
	"auth.oauth_audit": {
		"id":              "id uuid primary key",
		"actor_user_id":   "actor_user_id uuid references auth.users(id) on delete set null",
		"subject_user_id": "subject_user_id uuid references auth.users(id) on delete set null",
		"client_id":       "client_id text not null default ''",
		"action":          "action text not null",
		"scopes":          "scopes text[] not null default '{}'",
		"detail":          "detail text not null default ''",
		"created_at":      "created_at timestamptz not null default now()",
	},
}

func TestSchemaMatchesLifecycleShape(t *testing.T) {
	parsed := parseSchema(t, schema)
	for table, want := range frozenLifecycleTableDefs {
		got, ok := parsed[table]
		if !ok {
			t.Fatalf("建表语句缺少表 %s", table)
		}
		for col, wantDef := range want {
			gotDef, ok := got[col]
			if !ok {
				t.Fatalf("%s 缺少列 %s（期望 %s）", table, col, wantDef)
			}
			if gotDef != wantDef {
				t.Fatalf("%s.%s 定义漂移：\n  期望 %s\n  实际 %s", table, col, wantDef, gotDef)
			}
		}
		for col := range got {
			if _, ok := want[col]; !ok {
				t.Fatalf("%s 多出列 %s（未在冻结清单里登记）", table, col)
			}
		}
	}
}
