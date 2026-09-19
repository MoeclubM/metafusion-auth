package store

// 真实 PostgreSQL 上的 PAT 回归：创建 → 明文只此一次 → 内省 → 交集收窄 → 吊销 401 →
// 过期 401 → 封禁 401 → scopes 超出本人权限被拒 → 配额 → last_used_at 的写节奏。
//
// 未设置 AUTH_TEST_DSN 时整体跳过（本机与 CI 默认没有数据库）。用例自建自清账号，
// 不读取也不修改既有数据；跑法见 README。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

const patTestPassword = "pat-store-secret"

// patPlainRe 是明文格式的验收：mfp_ + 32 字节熵的 base62 定长表示（62^43 > 2^256）。
var patPlainRe = regexp.MustCompile("^mfp_[0-9A-Za-z]{" + fmt.Sprint(patSecretChars) + "}$")

// patTestUser 建一个真实账号（可选加入某个系统权限组）并补齐权限集合。
// 直接写库是为了不依赖"先有管理员"这条路径——本用例只关心 PAT。
func patTestUser(t *testing.T, ctx context.Context, s *Store, groupCode string) *User {
	t.Helper()
	id := uuid.NewString()
	username := "pat-" + strings.ReplaceAll(id, "-", "")[:12]
	hash, err := bcrypt.GenerateFromPassword([]byte(patTestPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("哈希测试口令: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'user')", id, username, username+"@example.test", string(hash)); err != nil {
		t.Fatalf("插入测试账号: %v", err)
	}
	t.Cleanup(func() { testutil.DeleteUser(t, s.DB, id) })
	if groupCode != "" {
		if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.user_groups(user_id,group_id) SELECT $1,id FROM auth.groups WHERE code=$2", id, groupCode); err != nil {
			t.Fatalf("加入权限组 %s: %v", groupCode, err)
		}
	}
	u := &User{ID: id, Username: username, Role: "user"}
	if err := s.WithAccess(ctx, u); err != nil {
		t.Fatalf("补齐权限: %v", err)
	}
	return u
}

func patRowTimes(t *testing.T, ctx context.Context, s *Store, id string) (expires, lastUsed, revoked sql.NullTime) {
	t.Helper()
	if err := s.DB.QueryRowContext(ctx, "SELECT expires_at,last_used_at,revoked_at FROM auth.personal_access_tokens WHERE id=$1", id).Scan(&expires, &lastUsed, &revoked); err != nil {
		t.Fatalf("读回 PAT 行 %s: %v", id, err)
	}
	return expires, lastUsed, revoked
}

func patActiveCount(t *testing.T, ctx context.Context, s *Store, userID string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM auth.personal_access_tokens WHERE user_id=$1 AND revoked_at IS NULL", userID).Scan(&n); err != nil {
		t.Fatalf("统计未吊销令牌: %v", err)
	}
	return n
}

func patTotalCount(t *testing.T, ctx context.Context, s *Store, userID string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM auth.personal_access_tokens WHERE user_id=$1", userID).Scan(&n); err != nil {
		t.Fatalf("统计令牌总数: %v", err)
	}
	return n
}

func TestPersonalAccessTokensAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	db := testutil.Database(t)
	s, err := Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// 用 Cleanup 而不是 defer：用例收尾要先用这条连接清账号行，连接不能先关。
	t.Cleanup(func() { s.Close() })
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	member := patTestUser(t, ctx, s, "catalog_editor")
	other := patTestUser(t, ctx, s, "")

	// ── 创建：明文格式、库里的确是哈希、时间列初始为空 ──
	item, plain, err := s.CreatePersonalAccessToken(ctx, member, "CI 编目", []string{"catalog.entity.edit", "catalog.entity.edit"}, 0)
	if err != nil {
		t.Fatalf("创建 PAT: %v", err)
	}
	if !patPlainRe.MatchString(plain) {
		t.Fatalf("明文格式不符：%q（期望 mfp_ + %d 位 base62）", plain, patSecretChars)
	}
	if item.TokenPrefix != plain[:patPrefixChars] || len(item.TokenPrefix) != patPrefixChars {
		t.Fatalf("展示前缀应为明文前 %d 字符: %q / %q", patPrefixChars, item.TokenPrefix, plain)
	}
	if !reflect.DeepEqual(item.Scopes, []string{"catalog.entity.edit"}) {
		t.Fatalf("重复 scope 应去重且保持顺序: %v", item.Scopes)
	}
	if item.ExpiresAt != nil || item.RevokedAt != nil || item.LastUsedAt != nil || !item.Active {
		t.Fatalf("新建令牌的投影不符: %+v", item)
	}
	if id, perr := uuid.Parse(item.ID); perr != nil || id.Version() != 7 {
		t.Fatalf("id 应为 uuidv7: %q err=%v", item.ID, perr)
	}
	wantHash := HashPersonalAccessToken(plain)
	var storedHash string
	var storedScopes []string
	if err := s.DB.QueryRowContext(ctx, "SELECT token_hash,scopes FROM auth.personal_access_tokens WHERE id=$1", item.ID).Scan(&storedHash, pq.Array(&storedScopes)); err != nil {
		t.Fatalf("读回 PAT 行: %v", err)
	}
	if storedHash != wantHash {
		t.Fatalf("库里应存 sha256 十六进制: %q != %q", storedHash, wantHash)
	}
	if strings.Contains(storedHash, plain) || storedHash == plain {
		t.Fatal("库里绝不能出现明文")
	}
	if !reflect.DeepEqual(storedScopes, []string{"catalog.entity.edit"}) {
		t.Fatalf("scopes 落库不符: %v", storedScopes)
	}
	if expires, lastUsed, revoked := patRowTimes(t, ctx, s, item.ID); expires.Valid || lastUsed.Valid || revoked.Valid {
		t.Fatalf("新行的三个时间列应为空: expires=%v last_used=%v revoked=%v", expires, lastUsed, revoked)
	}

	// ── 明文不再返回：列表投影里既没有明文也没有哈希 ──
	items, err := s.ListPersonalAccessTokens(ctx, member.ID)
	if err != nil || len(items) != 1 {
		t.Fatalf("列出自有令牌: n=%d err=%v", len(items), err)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("序列化列表: %v", err)
	}
	if strings.Contains(string(raw), plain) {
		t.Fatal("列表响应不得含明文")
	}
	if strings.Contains(string(raw), wantHash) {
		t.Fatal("列表响应不得含 token_hash")
	}
	if !strings.Contains(string(raw), item.TokenPrefix) {
		t.Fatalf("列表应含展示前缀: %s", raw)
	}
	if others, err := s.ListPersonalAccessTokens(ctx, other.ID); err != nil || len(others) != 0 {
		t.Fatalf("列表只应含本人的令牌: n=%d err=%v", len(others), err)
	}

	// ── 内省：身份 + 交集后的权限；last_used_at 同令牌 60 秒内只写一次 ──
	p, err := s.IntrospectPersonalAccessToken(ctx, plain)
	if err != nil {
		t.Fatalf("内省有效令牌: %v", err)
	}
	if p.UserID != member.ID || p.Username != member.Username || p.Role != "user" {
		t.Fatalf("内省身份不符: %+v", p)
	}
	if !reflect.DeepEqual(p.Permissions, []string{"catalog.entity.edit"}) {
		t.Fatalf("有效权限应等于 scopes（本人持有该码）: %v", p.Permissions)
	}
	if !reflect.DeepEqual(p.Scopes, []string{"catalog.entity.edit"}) || p.TokenPrefix != item.TokenPrefix || p.ExpiresAt != nil {
		t.Fatalf("内省元数据不符: %+v", p)
	}
	if p.TokenID != item.ID || p.TokenName != "CI 编目" {
		t.Fatalf("内省应回令牌身份 token_id/token_name: %+v", p)
	}
	_, firstUsed, _ := patRowTimes(t, ctx, s, item.ID)
	if !firstUsed.Valid {
		t.Fatal("首次内省应写入 last_used_at")
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := s.IntrospectPersonalAccessToken(ctx, plain); err != nil {
		t.Fatalf("二次内省: %v", err)
	}
	if _, secondUsed, _ := patRowTimes(t, ctx, s, item.ID); secondUsed.Time != firstUsed.Time {
		t.Fatalf("同一令牌 60 秒内不应重复写 last_used_at: %v → %v", firstUsed.Time, secondUsed.Time)
	}

	// ── 交集：账号权限被收回后，同一张令牌的有效权限立刻变窄 ──
	if _, err := s.DB.ExecContext(ctx, "DELETE FROM auth.user_groups WHERE user_id=$1", member.ID); err != nil {
		t.Fatalf("收回权限组: %v", err)
	}
	narrowed, err := s.IntrospectPersonalAccessToken(ctx, plain)
	if err != nil {
		t.Fatalf("收回组后内省不该失败（身份仍在）: %v", err)
	}
	if narrowed.Permissions == nil || len(narrowed.Permissions) != 0 {
		t.Fatalf("账号失去该码后有效权限应为空数组，实际 %v", narrowed.Permissions)
	}
	if HasPermission(narrowed.Permissions, "catalog.entity.edit") {
		t.Fatal("空权限不得命中任何码（下游必须用 HasPermission 语义，不能让 role 兜底）")
	}
	if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.user_groups(user_id,group_id) SELECT $1,id FROM auth.groups WHERE code='catalog_editor'", member.ID); err != nil {
		t.Fatalf("恢复权限组: %v", err)
	}

	// ── scopes 超出本人权限：拒绝且不落库（PAT 不能当提权通道） ──
	before := patTotalCount(t, ctx, s, member.ID)
	for _, tc := range []struct {
		label, name, wantErr string
		scopes               []string
	}{
		{"提权尝试", "提权尝试", "scope_not_granted: auth.users.manage", []string{"auth.users.manage"}},
		{"格式非法", "格式非法", "invalid_scope: read", []string{"read"}},
		{"空名", "", "invalid_token_name", []string{"catalog.entity.edit"}},
	} {
		if _, _, err := s.CreatePersonalAccessToken(ctx, member, tc.name, tc.scopes, 0); err == nil || err.Error() != tc.wantErr {
			t.Fatalf("%s 的创建应回 %q，实际 %v", tc.label, tc.wantErr, err)
		}
	}
	if patTotalCount(t, ctx, s, member.ID) != before {
		t.Fatal("被拒的创建不得落库")
	}

	// ── 无效令牌：不存在 / 非 mfp_ 前缀 / 空串 / 明文被改一个字符 ──
	for _, bad := range []string{"", "not-a-token", "mfp_" + strings.Repeat("A", patSecretChars), plain + "x"} {
		if _, err := s.IntrospectPersonalAccessToken(ctx, bad); !errors.Is(err, ErrInvalidPAT) {
			t.Fatalf("无效令牌 %q 应回 ErrInvalidPAT，实际 %v", bad, err)
		}
	}

	// ── 过期：1 毫秒有效期，睡过它 ──
	expiring, expiringPlain, err := s.CreatePersonalAccessToken(ctx, member, "短命", []string{"catalog.entity.edit"}, time.Millisecond)
	if err != nil {
		t.Fatalf("创建带有效期的 PAT: %v", err)
	}
	if expiring.ExpiresAt == nil {
		t.Fatal("给了有效期的令牌必须写 expires_at")
	}
	if expires, _, _ := patRowTimes(t, ctx, s, expiring.ID); !expires.Valid {
		t.Fatal("expires_at 应落库")
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := s.IntrospectPersonalAccessToken(ctx, expiringPlain); !errors.Is(err, ErrInvalidPAT) {
		t.Fatalf("过期令牌应回 ErrInvalidPAT，实际 %v", err)
	}

	// ── 吊销：幂等、生效、归属隔离 ──
	if err := s.RevokePersonalAccessToken(ctx, member.ID, item.ID); err != nil {
		t.Fatalf("吊销: %v", err)
	}
	if err := s.RevokePersonalAccessToken(ctx, member.ID, item.ID); err != nil {
		t.Fatalf("重复吊销必须幂等: %v", err)
	}
	if _, err := s.IntrospectPersonalAccessToken(ctx, plain); !errors.Is(err, ErrInvalidPAT) {
		t.Fatalf("吊销后内省应回 ErrInvalidPAT，实际 %v", err)
	}
	if err := s.RevokePersonalAccessToken(ctx, other.ID, expiring.ID); err == nil || err.Error() != "token_not_found" {
		t.Fatalf("不能吊销别人的令牌（按不存在处理）: %v", err)
	}
	if err := s.RevokePersonalAccessToken(ctx, member.ID, "not-a-uuid"); err == nil || err.Error() != "token_not_found" {
		t.Fatalf("非法 id 应回 token_not_found: %v", err)
	}
	items, err = s.ListPersonalAccessTokens(ctx, member.ID)
	if err != nil {
		t.Fatalf("吊销后列表: %v", err)
	}
	found := false
	for _, it := range items {
		if it.ID != item.ID {
			continue
		}
		found = true
		if it.RevokedAt == nil || it.Active {
			t.Fatalf("吊销是写 revoked_at 而不是删行，列表应显示已失效: %+v", it)
		}
	}
	if !found {
		t.Fatal("吊销后列表里仍应能看到这张令牌")
	}

	// ── 账号被封禁：手里的 PAT 立即失效（内省查库时判 NOT u.banned） ──
	banned, bannedPlain, err := s.CreatePersonalAccessToken(ctx, member, "封禁前", []string{"catalog.entity.edit"}, 0)
	if err != nil {
		t.Fatalf("创建 PAT: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE auth.users SET banned=true WHERE id=$1", member.ID); err != nil {
		t.Fatalf("封禁账号: %v", err)
	}
	if _, err := s.IntrospectPersonalAccessToken(ctx, bannedPlain); !errors.Is(err, ErrInvalidPAT) {
		t.Fatalf("封禁账号的令牌应回 ErrInvalidPAT，实际 %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE auth.users SET banned=false WHERE id=$1", member.ID); err != nil {
		t.Fatalf("解封账号: %v", err)
	}
	if repoened, err := s.IntrospectPersonalAccessToken(ctx, bannedPlain); err != nil {
		t.Fatalf("解封后令牌应恢复，实际 %v", err)
	} else if repoened.UserID != member.ID {
		t.Fatalf("解封后身份不符: %+v", repoened)
	}
	if _, err := s.DB.ExecContext(ctx, "UPDATE auth.personal_access_tokens SET revoked_at=now() WHERE id=$1", banned.ID); err != nil {
		t.Fatalf("清理封禁用例的令牌: %v", err)
	}

	// ── 配额：每账号最多 10 张未吊销（字典 settings.patLimitHint 的承诺） ──
	for patActiveCount(t, ctx, s, member.ID) < MaxPersonalAccessTokensPerUser {
		if _, _, err := s.CreatePersonalAccessToken(ctx, member, "批量", []string{"catalog.entity.edit"}, 0); err != nil {
			t.Fatalf("配额内创建失败: %v", err)
		}
	}
	if _, _, err := s.CreatePersonalAccessToken(ctx, member, "超配额", []string{"catalog.entity.edit"}, 0); err == nil || err.Error() != "token_limit_reached" {
		t.Fatalf("超过 %d 张应回 token_limit_reached，实际 %v", MaxPersonalAccessTokensPerUser, err)
	}
	var activeID string
	if err := s.DB.QueryRowContext(ctx, "SELECT id FROM auth.personal_access_tokens WHERE user_id=$1 AND revoked_at IS NULL LIMIT 1", member.ID).Scan(&activeID); err != nil {
		t.Fatalf("取一张未吊销令牌: %v", err)
	}
	if err := s.RevokePersonalAccessToken(ctx, member.ID, activeID); err != nil {
		t.Fatalf("腾位前吊销: %v", err)
	}
	if _, _, err := s.CreatePersonalAccessToken(ctx, member, "腾位后", []string{"catalog.entity.edit"}, 0); err != nil {
		t.Fatalf("吊销一张后应能再创建（配额只数未吊销的）: %v", err)
	}

	// ── 空 scopes 被拒绝：没有任何权限的令牌在既有判定下会变成全权令牌（role 兜底） ──
	for _, scopes := range [][]string{nil, {}, {"", "   "}} {
		if _, _, err := s.CreatePersonalAccessToken(ctx, member, "无权限", scopes, 0); err == nil || err.Error() != "invalid_scope: empty" {
			t.Fatalf("空 scopes %q 应回 invalid_scope: empty，实际 %v", scopes, err)
		}
	}

	// ── 明文不可逆推：两张令牌的哈希互不相同，且前缀不重复到可暴力枚举 ──
	if expiring.TokenPrefix == item.TokenPrefix {
		t.Fatal("不同令牌不应共用展示前缀（各含 8 位随机）")
	}
	var distinct int
	if err := db.QueryRowContext(ctx, "SELECT count(DISTINCT token_hash) FROM auth.personal_access_tokens WHERE user_id=$1", member.ID).Scan(&distinct); err != nil {
		t.Fatalf("统计哈希: %v", err)
	}
	if distinct != patTotalCount(t, ctx, s, member.ID) {
		t.Fatalf("token_hash 应逐张唯一: distinct=%d total=%d", distinct, patTotalCount(t, ctx, s, member.ID))
	}
}
