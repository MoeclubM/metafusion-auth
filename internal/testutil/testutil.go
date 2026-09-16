// Package testutil 提供"需要真实 PostgreSQL 才运行"的测试入口。
//
// 与主仓库 backend/internal/testutil 同一语义：没有环境变量就跳过，
// 因此本地与 CI 默认不依赖数据库；切流前可以用它跑一次真实回归。
// 连接串必须指向**独立测试库**（库名含 _test），避免误连线上库。
package testutil

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const envKey = "AUTH_TEST_DSN"

// DSN 返回测试库连接串；未设置时跳过用例。
func DSN(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(envKey))
	if dsn == "" {
		t.Skip(envKey + " 未设置：跳过需要真实数据库的用例")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || !strings.Contains(parsed.Path, "_test") {
		t.Fatalf("%s 必须指向独立测试库（库名需含 _test）：%s", envKey, dsn)
	}
	return dsn
}

// Database 返回测试库连接（用完自动关闭）。
func Database(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", DSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// accountTables 是 auth schema 里引用 auth.users 的表，顺序为「先子后父」。
//
// auth.sessions.user_id 没有 ON DELETE 级联（oauth_codes / oauth_tokens / user_groups /
// invite_uses 是 CASCADE，oauth_audit / invites 是 SET NULL），残留的会话行会让
// DELETE FROM auth.users 直接报 23503：CI 用 `go test -p 1 ./...` 串行跑，internal/handler
// 先跑就会留下已登录账号的会话行，internal/store 的用例随即失败。清库因此必须先清 sessions；
// 其余表一并清掉，用过多次的测试库也能回到「没有账号」的起点。
var accountTables = []struct {
	name    string
	columns []string
}{
	{"auth.sessions", []string{"user_id"}},
	{"auth.oauth_tokens", []string{"user_id"}},
	{"auth.oauth_codes", []string{"user_id"}},
	{"auth.user_groups", []string{"user_id"}},
	{"auth.invite_uses", []string{"user_id"}},
	{"auth.oauth_audit", []string{"actor_user_id", "subject_user_id"}},
	{"auth.invites", []string{"created_by"}},
}

// ResetAccounts 清空测试库的账号数据，供需要「从没有账号开始」的用例复用。
// 表名与列名只来自上面的清单，不拼外部输入。
func ResetAccounts(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range accountTables {
		if _, err := db.Exec("DELETE FROM " + table.name); err != nil {
			t.Fatalf("清空 %s: %v", table.name, err)
		}
	}
	if _, err := db.Exec("DELETE FROM auth.users"); err != nil {
		t.Fatalf("清空 auth.users: %v", err)
	}
}

// DeleteUser 删除单个账号及其关联行，顺序与 ResetAccounts 相同。
// 用例收尾不要直接 DELETE FROM auth.users：登录写下的会话行会挡住删除，
// 错误一旦被忽略，脏数据就留到下一次运行。收尾失败只记账不中断，免得盖掉用例本身的失败。
func DeleteUser(t *testing.T, db *sql.DB, userID string) {
	t.Helper()
	for _, table := range accountTables {
		conds := make([]string, 0, len(table.columns))
		for _, col := range table.columns {
			conds = append(conds, col+"=$1")
		}
		stmt := "DELETE FROM " + table.name + " WHERE " + strings.Join(conds, " OR ")
		if _, err := db.Exec(stmt, userID); err != nil {
			t.Errorf("清理 %s: %v", table.name, err)
		}
	}
	if _, err := db.Exec("DELETE FROM auth.users WHERE id=$1", userID); err != nil {
		t.Errorf("清理 auth.users: %v", err)
	}
}
