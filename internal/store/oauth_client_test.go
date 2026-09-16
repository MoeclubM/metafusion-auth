package store

import (
	"strings"
	"testing"
)

// 客户端密钥只在创建/轮换响应里出现一次，库里只有 bcrypt 哈希；
// 轮换后老密钥必须立刻失效——这条规则写错会以"老密钥还能换到令牌"的形式暴露。
func TestClientSecretHashAndRotation(t *testing.T) {
	secret, err := GenerateClientSecret()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	if len(secret) != 43 {
		t.Fatalf("明文密钥长度 = %d，期望 43（32 字节 base64url）", len(secret))
	}
	other, err := GenerateClientSecret()
	if err != nil || other == secret {
		t.Fatalf("两次生成的密钥必须不同: %v", err)
	}
	hash, err := HashClientSecret(secret)
	if err != nil {
		t.Fatalf("哈希失败: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("secret_hash 看起来不是 bcrypt: %s", hash)
	}
	if hash == secret || strings.Contains(hash, secret) {
		t.Fatal("库里不能出现明文密钥")
	}
	if !VerifyClientSecret(hash, secret) {
		t.Fatal("正确密钥应通过校验")
	}
	if VerifyClientSecret(hash, secret+"x") {
		t.Fatal("错误密钥必须拒绝")
	}
	// 轮换：写入新哈希之后，老密钥立刻失效（没有回滚路径）。
	rotated, err := GenerateClientSecret()
	if err != nil {
		t.Fatalf("生成新密钥失败: %v", err)
	}
	newHash, err := HashClientSecret(rotated)
	if err != nil {
		t.Fatalf("哈希新密钥失败: %v", err)
	}
	if VerifyClientSecret(newHash, secret) {
		t.Fatal("轮换后老密钥必须失效")
	}
	if !VerifyClientSecret(newHash, rotated) {
		t.Fatal("轮换后的新密钥应可用")
	}
	// 无密钥的第一方（secret_hash 为空）在 VerifyClientSecret 上一律不通过：
	// 是否放行由 ExchangeOAuthCode 结合 trusted 判定。
	if VerifyClientSecret("", secret) || VerifyClientSecret("", "") {
		t.Fatal("空哈希不能被当作「无密钥即通过」")
	}
}

// 回调白名单只接受 http(s) 绝对地址，且不接受通配符：通配会让任何子域/路径都能收码。
func TestValidateRedirectURIs(t *testing.T) {
	ok := [][]string{
		{"https://client.example/auth/callback"},
		{"https://client.example/auth/callback", "http://localhost:3000/auth/callback"},
		{"http://127.0.0.1:8080/cb?next=1"},
	}
	for _, uris := range ok {
		if err := ValidateRedirectURIs(uris); err != nil {
			t.Fatalf("合法白名单被拒 %v: %v", uris, err)
		}
	}
	bad := [][]string{
		nil,
		{},
		{""},
		{"/auth/callback"},
		{"client.example/callback"},
		{"https://client.example/*"},
		{"https://*.client.example/cb"},
		{"https://client.example/cb#frag"},
		{"https://user:pw@client.example/cb"},
		{"ftp://client.example/cb"},
		{"javascript:alert(1)"},
	}
	for _, uris := range bad {
		if err := ValidateRedirectURIs(uris); err == nil {
			t.Fatalf("非法白名单必须拒绝: %v", uris)
		}
	}
}

func TestValidClientIDAndGeneratedID(t *testing.T) {
	for _, id := range []string{"mfc-1a2b3c4d5e6f7a8b", "metafusion-forum", "abc"} {
		if !ValidClientID(id) {
			t.Fatalf("合法 client_id 被拒: %s", id)
		}
	}
	for _, id := range []string{"", "A", "1abc", "a", "UPPER", "has space", "mfc/x"} {
		if ValidClientID(id) {
			t.Fatalf("非法 client_id 被接受: %q", id)
		}
	}
	gen, err := generateClientID()
	if err != nil {
		t.Fatalf("生成 client_id 失败: %v", err)
	}
	if !ValidClientID(gen) || !strings.HasPrefix(gen, "mfc-") {
		t.Fatalf("生成的 client_id 形状不符: %s", gen)
	}
}

// 管理动作的准入判定必须与 HTTP 层同口径：权限码 / 通配 / 历史 role=admin。
func TestCanManageOAuth(t *testing.T) {
	if canManageOAuth(nil) {
		t.Fatal("匿名不能管理客户端")
	}
	if canManageOAuth(&User{ID: "u1", Role: "user", Permissions: []string{"community.post.create"}}) {
		t.Fatal("无 auth.oauth.manage 的成员不能管理客户端")
	}
	if !canManageOAuth(&User{ID: "u1", Role: "user", Permissions: []string{"auth.oauth.manage"}}) {
		t.Fatal("持有 auth.oauth.manage 应可管理")
	}
	if !canManageOAuth(&User{ID: "u1", Role: "user", Permissions: []string{"*"}}) {
		t.Fatal("* 通配应可管理")
	}
	if !canManageOAuth(&User{ID: "u1", Role: "admin"}) {
		t.Fatal("历史 role=admin（老令牌不带 permissions 声明）应可管理")
	}
	if canManageOAuth(&User{ID: "u1", Role: "admin", Permissions: []string{"community.post.create"}}) {
		t.Fatal("带 permissions 声明的令牌只认码：role=admin 不再额外放行")
	}
}
