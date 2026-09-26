package store

// ListOwnAppAudits 的真库回归：只回本人应用的行、client_id 可选过滤、
// limit 缺省 100（0 与超上限都回落）、空归属拒绝。
// 未设置 AUTH_TEST_DSN 时跳过；用例自建自清，不碰既有数据。

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

func TestListOwnAppAuditsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	db := testutil.Database(t)
	_ = db
	s, err := Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	mkUser := func(name string) string {
		t.Helper()
		id := uuid.NewString()
		if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash) VALUES($1,$2,$3,$4)", id, name, name+"@example.test", "test-hash"); err != nil {
			t.Fatalf("插入测试账号: %v", err)
		}
		t.Cleanup(func() { testutil.DeleteUser(t, s.DB, id) })
		return id
	}
	userA := mkUser("own-audit-a")
	userB := mkUser("own-audit-b")

	mkClient := func(id, name, owner string) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.oauth_clients(id,secret_hash,name,redirect_uris,owner_user_id) VALUES($1,'',$2,'{}',$3)", id, name, owner); err != nil {
			t.Fatalf("插入测试客户端: %v", err)
		}
	}
	clientA, clientB := "mfc-own-audit-a", "mfc-own-audit-b"
	mkClient(clientA, "我的应用", userA)
	mkClient(clientB, "别人的应用", userB)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = s.DB.ExecContext(bg, "DELETE FROM auth.oauth_audit WHERE client_id=$1 OR client_id=$2", clientA, clientB)
		_, _ = s.DB.ExecContext(bg, "DELETE FROM auth.oauth_clients WHERE id=$1 OR id=$2", clientA, clientB)
	})

	record := func(actor, subject, client, action string) {
		t.Helper()
		if err := s.RecordOAuthAudit(ctx, OAuthAuditEntry{ActorID: actor, SubjectID: subject, ClientID: client, Action: action, Scopes: []string{"openid"}}); err != nil {
			t.Fatalf("记审计: %v", err)
		}
	}
	record(userA, userA, clientA, OAuthActionConsentAllow)
	record(userA, userA, clientA, OAuthActionClientUpdate)
	record(userB, userB, clientB, OAuthActionConsentAllow)

	// 缺省 limit（0）与超上限（999）都回落 100：这里只有 2 条，全回。
	for _, limit := range []int{0, 999} {
		items, err := s.ListOwnAppAudits(ctx, userA, "", limit)
		if err != nil || len(items) != 2 {
			t.Fatalf("limit=%d 应回自己的 2 条，实际 n=%d err=%v", limit, len(items), err)
		}
		for _, item := range items {
			if item.ClientID != clientA || item.ClientName != "我的应用" {
				t.Fatalf("行归属或名称不符: %+v", item)
			}
			if item.Actor != "own-audit-a" || item.ActorID != userA {
				t.Fatalf("行应带操作者名: %+v", item)
			}
			if len(item.Scopes) != 1 || item.CreatedAt == "" {
				t.Fatalf("行缺 scope 或时间: %+v", item)
			}
		}
	}

	// client_id 过滤：自己的按出 2 条；别人的回空。
	if items, err := s.ListOwnAppAudits(ctx, userA, clientA, 0); err != nil || len(items) != 2 {
		t.Fatalf("按自己应用过滤应回 2 条，实际 n=%d err=%v", len(items), err)
	}
	if items, err := s.ListOwnAppAudits(ctx, userA, clientB, 0); err != nil || len(items) != 0 {
		t.Fatalf("按别人应用过滤应回空，实际 n=%d err=%v", len(items), err)
	}

	// limit=1 只要最新 1 条（按 created_at 倒序，第一条是 client_update）。
	if items, err := s.ListOwnAppAudits(ctx, userA, "", 1); err != nil || len(items) != 1 {
		t.Fatalf("limit=1 应回 1 条，实际 n=%d err=%v", len(items), err)
	} else if items[0].Action != OAuthActionClientUpdate {
		t.Fatalf("倒序第一条应是后记的 client_update，实际 %+v", items[0])
	}

	// 对面只能看到自己的 1 条；空归属直接拒绝。
	if items, err := s.ListOwnAppAudits(ctx, userB, "", 0); err != nil || len(items) != 1 || items[0].ClientID != clientB {
		t.Fatalf("对面应只看到自己的 1 条，实际 %+v err=%v", items, err)
	}
	if _, err := s.ListOwnAppAudits(ctx, "", "", 0); err == nil || err.Error() != "authentication_required" {
		t.Fatalf("空归属应回 authentication_required，实际 %v", err)
	}
}
