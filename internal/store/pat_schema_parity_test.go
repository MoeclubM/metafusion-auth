package store

import "testing"

// PAT 表的列形状冻结：这是本轮新增的唯一一张授权基础表。列名/默认值改错不会编译失败，
// 只会在运行时以"创建 500 / 内省查不到"的形式暴露；token_hash 的唯一性是"按哈希直查"的前提
// （bcrypt 无法索引查询，因此这里必须存 SHA-256）。
var frozenPersonalAccessTokenDefs = map[string]string{
	"id":           "id uuid primary key",
	"user_id":      "user_id uuid not null references auth.users(id) on delete cascade",
	"name":         "name text not null",
	"token_hash":   "token_hash text not null unique",
	"token_prefix": "token_prefix text not null",
	"scopes":       "scopes text[] not null default '{}'",
	"expires_at":   "expires_at timestamptz",
	"last_used_at": "last_used_at timestamptz",
	"created_at":   "created_at timestamptz not null default now()",
	"revoked_at":   "revoked_at timestamptz",
}

func TestSchemaMatchesPersonalAccessTokenShape(t *testing.T) {
	got, ok := parseSchema(t, schema)["auth.personal_access_tokens"]
	if !ok {
		t.Fatal("建表语句缺少表 auth.personal_access_tokens")
	}
	for col, want := range frozenPersonalAccessTokenDefs {
		gotDef, ok := got[col]
		if !ok {
			t.Fatalf("auth.personal_access_tokens 缺少列 %s（期望 %s）", col, want)
		}
		if gotDef != want {
			t.Fatalf("auth.personal_access_tokens.%s 定义漂移：\n  期望 %s\n  实际 %s", col, want, gotDef)
		}
	}
	for col := range got {
		if _, ok := frozenPersonalAccessTokenDefs[col]; !ok {
			t.Fatalf("auth.personal_access_tokens 多出列 %s（未在冻结清单里登记）", col)
		}
	}
}
