package store

import (
	"context"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 第一方 OAuth 客户端（元数据库 / 论坛 / 资源站）原先由主仓库在启动时播种，
// 账号拆分后种子随 auth schema 一起搬到这里。这条用例钉住三件事：三个客户端都在、
// 重复 Init 不会重复插入、后台改过的配置不会被种子覆盖。
// 未设置 AUTH_TEST_DSN 时跳过（需要真实 PostgreSQL）。
func TestInitSeedsFirstPartyClients(t *testing.T) {
	s := &Store{DB: testutil.Database(t)}
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	clients := map[string]bool{}
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM auth.oauth_clients`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		clients[id] = true
	}
	rows.Close()
	for _, id := range []string{"metafusion-catalog", "metafusion-forum", "metafusion-resources"} {
		if !clients[id] {
			t.Fatalf("第一方客户端 %s 未被播种: %v", id, clients)
		}
	}

	// 后台改过的名字不得被下一次 Init 覆盖（ON CONFLICT DO NOTHING）。
	if _, err := s.DB.ExecContext(ctx, `UPDATE auth.oauth_clients SET name = $1 WHERE id = $2`, "改过的名字", "metafusion-forum"); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := s.DB.QueryRowContext(ctx, `SELECT name FROM auth.oauth_clients WHERE id = $1`, "metafusion-forum").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "改过的名字" {
		t.Fatalf("重复 Init 覆盖了后台配置: %q", name)
	}
}
