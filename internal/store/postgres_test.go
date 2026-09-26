package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

func newTestIssuer(t *testing.T) *TokenIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemText := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	t.Setenv("AUTH_JWT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(pemText))
	iss, err := NewTokenIssuerFromEnv("https://findverse.cc/api", "metafusion")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss
}

// 需要真实 PostgreSQL 的回归：初始化 → 首管 → 登录/续期 → 改密 → 角色变更 → 全量登出。
// 未设置 AUTH_TEST_DSN 时整体跳过。测试库会被清空账号数据（连接串已强制要求独立测试库）。
func TestIdentityLifecycleAgainstPostgres(t *testing.T) {
	dsn := testutil.DSN(t)
	db := testutil.Database(t)
	ctx := context.Background()

	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	// 首管用例要求库里没有账号：先按外键顺序清掉会话等引用行（串行跑时 handler 包会留下会话行）。
	// 收尾再清一次，用例建的账号不留给下一次运行（db 比 store 连接更晚关闭）。
	testutil.ResetAccounts(t, db)
	t.Cleanup(func() { testutil.ResetAccounts(t, db) })
	s.Tokens = newTestIssuer(t)

	// 首管：只需一次，重复调用必须被拒（防止并发初始化出两个管理员）。
	needed, err := s.SetupNeeded(ctx)
	if err != nil || !needed {
		t.Fatalf("空库应需要初始化: needed=%v err=%v", needed, err)
	}
	admin, err := s.CreateUser(ctx, "root", "root@example.com", "first-admin-secret", true, nil)
	if err != nil {
		t.Fatalf("create first admin: %v", err)
	}
	if !HasPermission(admin.Permissions, "*") {
		t.Fatalf("首管应持有全部权限，实际 %v", admin.Permissions)
	}
	if _, err = s.CreateUser(ctx, "root2", "", "first-admin-secret", true, nil); err == nil {
		t.Fatal("重复初始化必须被拒绝")
	}

	// 登录 → 令牌可验签 → 身份一致。
	token, logged, err := s.Login(ctx, "root", "first-admin-secret")
	if err != nil || token == "" {
		t.Fatalf("login: %v", err)
	}
	if logged.ID != admin.ID {
		t.Fatalf("登录返回的账号不一致: %s != %s", logged.ID, admin.ID)
	}
	who, err := s.Authenticate(ctx, token)
	if err != nil || who.ID != admin.ID || !HasPermission(who.Permissions, "*") {
		t.Fatalf("验签身份不一致: %+v err=%v", who, err)
	}

	// 访问令牌过期后请求会回退到 s.User（查库）：这条路径必须与 Login/Refresh 一样
	// 补齐组与权限，否则"role 仍是 user、权限全来自自定义组"的成员会在令牌过期那一刻
	// 丢掉全部能力。s.User 就是回退路径本身，直接调用与回退时的行为逐字一致。
	dbUser, err := s.User(ctx, token)
	if err != nil {
		t.Fatalf("回退查库: %v", err)
	}
	if len(dbUser.Groups) == 0 || !HasPermission(dbUser.Permissions, "*") {
		t.Fatalf("回退查库的身份未补齐组与权限: groups=%v permissions=%v", dbUser.Groups, dbUser.Permissions)
	}

	// 改密：旧密码错必须拒绝；改成功后旧密码失效、新密码可用。
	if err = s.ChangePassword(ctx, admin.ID, "wrong-secret", "second-admin-secret"); err == nil {
		t.Fatal("旧密码错误时必须拒绝")
	}
	if err = s.ChangePassword(ctx, admin.ID, "first-admin-secret", "second-admin-secret"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, _, err = s.Login(ctx, "root", "first-admin-secret"); err == nil {
		t.Fatal("旧密码应已失效")
	}
	if _, _, err = s.Login(ctx, "root", "second-admin-secret"); err != nil {
		t.Fatalf("新密码应可用: %v", err)
	}

	// 权限组：可以授予编辑组；最后一个管理员不得失去 admin 组。
	user, err := s.CreateUser(ctx, "kana", "", "editor-account-secret", false, &admin)
	if err != nil {
		t.Fatalf("create editor: %v", err)
	}
	if err = s.SetUserGroups(ctx, user.ID, []string{"catalog_editor", "member"}, &admin); err != nil {
		t.Fatalf("grant catalog editor group: %v", err)
	}
	if err = s.SetUserGroups(ctx, admin.ID, []string{"member"}, &admin); err == nil {
		t.Fatal("唯一管理员降级必须被拒绝")
	}

	// 全量登出：已签发的服务端会话立即失效（无状态令牌靠短 TTL 自然过期）。
	another, _, err := s.Login(ctx, "root", "second-admin-secret")
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if err = s.LogoutAll(ctx, admin.ID); err != nil {
		t.Fatalf("logout all: %v", err)
	}
	if _, err = s.User(ctx, another); err == nil {
		t.Fatal("全量登出后会话应失效")
	}
	_ = time.Now
}
