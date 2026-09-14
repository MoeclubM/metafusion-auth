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
// 未设置 AUTH_TEST_DSN 时整体跳过。测试库会被清空 auth.users（连接串已强制要求独立测试库）。
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
	if _, err = db.ExecContext(ctx, "DELETE FROM auth.users"); err != nil {
		t.Fatalf("clean users: %v", err)
	}
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
	if admin.Role != "admin" {
		t.Fatalf("首管角色应为 admin，实际 %s", admin.Role)
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
	if err != nil || who.ID != admin.ID || who.Role != "admin" {
		t.Fatalf("验签身份不一致: %+v err=%v", who, err)
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

	// 角色：普通用户可以提升为编辑；最后一个管理员不得被降级。
	user, err := s.CreateUser(ctx, "kana", "", "editor-account-secret", false, &admin)
	if err != nil {
		t.Fatalf("create editor: %v", err)
	}
	if err = s.UpdateUserRole(ctx, user.ID, "editor", &admin); err != nil {
		t.Fatalf("promote to editor: %v", err)
	}
	if err = s.UpdateUserRole(ctx, admin.ID, "editor", &admin); err == nil {
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
