package store

// 个人访问令牌（PAT）：外部应用、Agent 与 CI 的长期机器接入凭证。
//
// 为什么存 SHA-256 而不是 bcrypt：PAT 明文是 32 字节高熵随机串（见 newPATPlaintext），
// 不存在被猜解的口令空间，而校验必须能按哈希**直查**（bcrypt 每行自带盐，无法索引查询）。
// 明文只在创建响应里出现一次，此后任何路径都取不回（库里只有哈希与展示前缀）。
//
// 权限模型：scopes 是**权限码**（如 catalog.entity.edit），创建时要求账号自己持有
// （见 NormalizePATScopes）；下游的有效权限 = 账号现时权限 ∩ PAT scopes，由内省算好下发。
// 下游仍然只用一份权限判定，不因为 PAT 多一套逻辑。
//
// 撤销窗口：本服务每次内省都查库（自身是即时的），但下游按 60 秒缓存内省结果
// （见 README「个人访问令牌」），因此**端到端吊销最长 60 秒**，不要对外声称立即失效。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const (
	// PATPrefix 是明文前缀：四语字典（settings.patDesc）与文档承诺给用户的格式就是 mfp_。
	PATPrefix = "mfp_"
	// patSecretBytes 是明文随机部分的熵：32 字节（256 位），穷举不可行。
	patSecretBytes = 32
	// patSecretChars 是 base62 定长字符数：62^43 > 2^256，32 字节恰好装进 43 个字符，
	// 因此明文长度恒定（4 + 43 = 47），正则形如 ^mfp_[0-9A-Za-z]{43}$。
	patSecretChars = 43
	// patPrefixChars 是入库与展示的前缀长度（含 mfp_）：界面用它区分"哪一张令牌"，
	// 12 个字符（约 47 位随机）不足以反推明文。
	patPrefixChars = 12
	// patNameMaxRunes 限制令牌名称长度：它只用于让人认出"这是给谁用的"，不做唯一性约束
	// （同一个人建两张同名令牌是合理的：一张给 CI，一张给本地脚本）。
	patNameMaxRunes = 64
	// MaxPersonalAccessTokensPerUser 是每账号未吊销令牌的上限：四语字典
	// （settings.patLimitHint）已经对用户承诺"最多 10 个"。
	MaxPersonalAccessTokensPerUser = 10
	// patLastUsedTTL 是同一条令牌两次 last_used_at 写库之间的最小间隔。
	// 与下游内省结果缓存同为 60 秒：界面上的"最近使用"精确到分钟足够。
	patLastUsedTTL = time.Minute
)

// ErrInvalidPAT 是内省失败的唯一错误：令牌不存在 / 已吊销 / 已过期 / 账号被封禁，一律返回它。
// 区分原因等于告诉探测者"这个令牌曾经有效"，也会被拿来枚举账号状态，因此 HTTP 层统一
// 401 + 单一机器码（invalid_token）。
//
// **有效权限为空不属于它**：创建时 scopes 至少一项（空 scopes 在创建端就被拒），但账号事后
// 丢了那些码会让交集变空——那时令牌仍然有效，内省回 200 + permissions: []，只是什么都做不了。
// 这一格的安全性由调用方保证：用 HasPermission(principal.Permissions, code) 判定，
// 而不是会按 role 兜底到 admin/editor 的 Can（见 PATPrincipal.Permissions）。
var ErrInvalidPAT = errors.New("invalid_token")

// PersonalAccessToken 是一张 PAT 的对外投影：**没有 token_hash 字段**，明文也无处可放，
// 因此任何序列化路径都不可能把哈希或明文带出去。
type PersonalAccessToken struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	// Active 由服务端算好（未吊销且未过期）：前端不必自己比时间，也不必假设两端时钟一致。
	Active bool `json:"active"`
}

// activeAt 报告这张令牌在给定时刻是否可用。
func (t PersonalAccessToken) activeAt(now time.Time) bool {
	return t.RevokedAt == nil && (t.ExpiresAt == nil || t.ExpiresAt.After(now))
}

// PATPrincipal 是内省的答案：下游据此构造调用者身份。
// TokenID/TokenName 让下游能区分"同一账号的哪一张令牌在调用"（按前缀只能认出大概，
// 按 id/name 才能落审计与限流；明文与哈希都不下发）。
type PATPrincipal struct {
	TokenID   string `json:"token_id"`
	TokenName string `json:"token_name"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	// Permissions 是**有效权限**：账号现时权限 ∩ 该 PAT 的 scopes。创建时 scopes 至少一项，
	// 但账号权限被收回后交集可能为空（空数组）——那正是最危险的一格：
	// 下游必须以它为准，且只能用 HasPermission(perms, code) 语义；
	// Can(user, code) 在 permissions 为空时会按 role 兜底到 admin/editor，等于把"什么都做不了"
	// 的令牌变成全权令牌。
	Permissions []string   `json:"permissions"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at"`
	TokenPrefix string     `json:"token_prefix"`
}

// newPATPlaintext 生成一张新令牌的明文：mfp_ + 32 字节随机数的 base62 定长表示
// （math/big 的 base62 字母表：0-9a-zA-Z；左侧补 '0' 到定长，保证长度恒定）。
func newPATPlaintext() (string, error) {
	raw := make([]byte, patSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := new(big.Int).SetBytes(raw).Text(62)
	// 62^43 > 2^256，任何 32 字节整数都不会超过 43 位；超了说明上面的常量被改错了。
	if len(secret) > patSecretChars {
		return "", errors.New("pat secret width overflow")
	}
	return PATPrefix + strings.Repeat("0", patSecretChars-len(secret)) + secret, nil
}

// HashPersonalAccessToken 是 PAT 在库里的存储形式（SHA-256 十六进制），也是内省的查询键。
func HashPersonalAccessToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// patPrefixOf 取展示前缀：明文的前 12 个字符（含 mfp_）。
func patPrefixOf(plain string) string {
	if len(plain) <= patPrefixChars {
		return plain
	}
	return plain[:patPrefixChars]
}

// NormalizePATScopes 校验并归一创建请求里的 scopes：去空白、去重、保持请求顺序。
//
// 两条硬要求：
//  1. 每个码必须是格式合法的权限码，且**当前账号自己持有**（Can）——PAT 只能是权限的子集，
//     不能当提权通道；超出本人权限的码直接拒绝（scope_not_granted: <code>），不静默取交集，
//     否则用户会拿到一张比他要的更弱的令牌却毫不知情。
//  2. 空数组被拒绝（invalid_scope: empty）：**没有权限的令牌在既有判定下会变成全权令牌**——
//     Can 在 permissions 为空时按 role 兜底到 admin/editor，于是"仅身份"的令牌对管理员账号
//     等于全权 PAT（下游不会有第二道判定来兜住它）。与其留一个会静默扩权的语义，
//     不如让创建方显式写明需要哪些码。
//
// 判定用的是调用方传入的 actor（HTTP 层来自访问令牌）：访问令牌里的 permissions 最多陈旧
// 15 分钟，但那不是漏洞——内省每次都回表重算交集，账号权限被收回后令牌立刻就窄了。
func NormalizePATScopes(scopes []string, actor *User) ([]string, error) {
	if actor == nil {
		return nil, fmt.Errorf("forbidden")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range scopes {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !ValidPermissionCode(s) {
			return nil, fmt.Errorf("invalid_scope: %s", s)
		}
		if seen[s] {
			continue
		}
		if !Can(actor, s) {
			return nil, fmt.Errorf("scope_not_granted: %s", s)
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid_scope: empty")
	}
	return out, nil
}

// EffectivePATPermissions 计算有效权限：账号现时权限 ∩ 该 PAT 的 scopes。
// 逐码走 Can()——与下游用的是同一条判定，不另写一套。账号权限被收回后，下一次内省就窄了。
func EffectivePATPermissions(u *User, scopes []string) []string {
	out := []string{}
	for _, s := range scopes {
		if !Can(u, s) {
			continue
		}
		if s == WildcardPermission {
			// * 已经是全权，后面的码不再有意义（与 ExpandPermissions 同口径）。
			return []string{WildcardPermission}
		}
		out = append(out, s)
	}
	return out
}

// CreatePersonalAccessToken 创建一张 PAT，返回元数据与**仅此一次**的明文。
// expiresIn <= 0 表示永不过期（不写 expires_at）。
func (s *Store) CreatePersonalAccessToken(ctx context.Context, actor *User, name string, scopes []string, expiresIn time.Duration) (PersonalAccessToken, string, error) {
	out := PersonalAccessToken{}
	if actor == nil || strings.TrimSpace(actor.ID) == "" {
		return out, "", fmt.Errorf("forbidden")
	}
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > patNameMaxRunes {
		return out, "", fmt.Errorf("invalid_token_name")
	}
	norm, err := NormalizePATScopes(scopes, actor)
	if err != nil {
		return out, "", err
	}
	plain, err := newPATPlaintext()
	if err != nil {
		return out, "", err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return out, "", err
	}
	out = PersonalAccessToken{
		ID: id.String(), Name: name, TokenPrefix: patPrefixOf(plain),
		Scopes: norm, CreatedAt: time.Now(), Active: true,
	}
	if expiresIn > 0 {
		exp := out.CreatedAt.Add(expiresIn)
		out.ExpiresAt = &exp
	}
	hash := HashPersonalAccessToken(plain)
	err = s.write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM auth.personal_access_tokens WHERE user_id=$1 AND revoked_at IS NULL", actor.ID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPersonalAccessTokensPerUser {
			return fmt.Errorf("token_limit_reached")
		}
		var expires any
		if out.ExpiresAt != nil {
			expires = *out.ExpiresAt
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO auth.personal_access_tokens(id,user_id,name,token_hash,token_prefix,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
			out.ID, actor.ID, out.Name, hash, out.TokenPrefix, pq.Array(out.Scopes), expires)
		return err
	})
	if err != nil {
		return PersonalAccessToken{}, "", err
	}
	return out, plain, nil
}

// ListPersonalAccessTokens 列出**某个账号自己的**令牌（HTTP 层的调用者只会传当前登录身份）。
// 明文与哈希都不在投影里；按创建时间倒序（id 是 uuidv7，同秒创建也能稳定排序）。
func (s *Store) ListPersonalAccessTokens(ctx context.Context, userID string) ([]PersonalAccessToken, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name,token_prefix,scopes,expires_at,last_used_at,created_at,revoked_at FROM auth.personal_access_tokens WHERE user_id=$1 ORDER BY created_at DESC, id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	out := []PersonalAccessToken{}
	for rows.Next() {
		var (
			t        PersonalAccessToken
			scopes   []string
			expires  sql.NullTime
			lastUsed sql.NullTime
			revoked  sql.NullTime
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, pq.Array(&scopes), &expires, &lastUsed, &t.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		t.Scopes = scopes
		if t.Scopes == nil {
			t.Scopes = []string{}
		}
		if expires.Valid {
			exp := expires.Time
			t.ExpiresAt = &exp
		}
		if lastUsed.Valid {
			last := lastUsed.Time
			t.LastUsedAt = &last
		}
		if revoked.Valid {
			rev := revoked.Time
			t.RevokedAt = &rev
		}
		t.Active = t.activeAt(now)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokePersonalAccessToken 吊销本人的一张令牌：只写 revoked_at，不删行（列表要能继续显示
// "这张已经失效"，审计也留痕）。幂等：已经吊销过的再调一次仍然成功。
//
// 归属隔离：路径里没有别人的 user id，条件就是 user_id=本人；不是自己的令牌（或根本不存在）
// 一律返回 token_not_found，不把"这张令牌属于别人"这个事实透出去（与开发者中心的 404 同口径）。
func (s *Store) RevokePersonalAccessToken(ctx context.Context, userID, id string) error {
	id = strings.TrimSpace(id)
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("token_not_found")
	}
	res, err := s.DB.ExecContext(ctx, "UPDATE auth.personal_access_tokens SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL", id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var one int
	if err := s.DB.QueryRowContext(ctx, "SELECT 1 FROM auth.personal_access_tokens WHERE id=$1 AND user_id=$2", id, userID).Scan(&one); err != nil {
		return fmt.Errorf("token_not_found")
	}
	return nil
}

// IntrospectPersonalAccessToken 校验一张 PAT 并返回它当前能代表什么身份与权限。
//
// 判定顺序：哈希直查（token_hash 唯一索引）→ 行未吊销 → 未过期（expires_at 为空即永不过期）
// → 账号未封禁 → **有效权限 = 账号现时权限 ∩ scopes**（每次回表重算，不读缓存）。
// 交集为空是**合法结果**（200 + permissions: []），不是无效令牌：令牌确实属于一个可用账号，
// 只是此刻没有任何权限码；判定这一格只能用 HasPermission 语义（见 PATPrincipal.Permissions）。
// 本服务不缓存内省结果：结果缓存放在下游（60 秒），这样"吊销多久生效"只有一个来源，
// 而不是两级 TTL 叠加出说不清的窗口。
func (s *Store) IntrospectPersonalAccessToken(ctx context.Context, token string) (*PATPrincipal, error) {
	token = strings.TrimSpace(token)
	// 前缀只是廉价的前置过滤（下游只会带 mfp_ 令牌来），不是安全边界：判定完全靠哈希查库。
	// 无数据库（桩实例）时一律按无效处理，绝不放行。
	if s.DB == nil || token == "" || !strings.HasPrefix(token, PATPrefix) {
		return nil, ErrInvalidPAT
	}
	hash := HashPersonalAccessToken(token)
	var (
		tokenID   string
		tokenName string
		userID    string
		username  string
		role      string
		scopes    []string
		expires   sql.NullTime
	)
	err := s.DB.QueryRowContext(ctx, "SELECT t.id,t.name,t.user_id,u.username,u.role,t.scopes,t.expires_at"+
		" FROM auth.personal_access_tokens t JOIN auth.users u ON u.id=t.user_id"+
		" WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>now()) AND NOT u.banned",
		hash).Scan(&tokenID, &tokenName, &userID, &username, &role, pq.Array(&scopes), &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 不存在 / 已吊销 / 已过期 / 账号被封：对外只有一种答案。
			return nil, ErrInvalidPAT
		}
		// 真的读不动库（连接断了等）不能当成"令牌无效"：那是两件不同的事，
		// HTTP 层据此回 503（下游仍然必须把非 200 当作"不认这个令牌"）。
		return nil, err
	}
	u := User{ID: userID, Username: username, Role: role}
	if err := s.WithAccess(ctx, &u); err != nil {
		return nil, err
	}
	p := &PATPrincipal{
		TokenID: tokenID, TokenName: tokenName,
		UserID: userID, Username: username, Role: role,
		Permissions: EffectivePATPermissions(&u, scopes),
		Scopes:      scopes, TokenPrefix: patPrefixOf(token),
	}
	if p.Permissions == nil {
		p.Permissions = []string{}
	}
	if p.Scopes == nil {
		p.Scopes = []string{}
	}
	if expires.Valid {
		exp := expires.Time
		p.ExpiresAt = &exp
	}
	s.touchPersonalAccessToken(ctx, hash)
	return p, nil
}

// touchPersonalAccessToken 更新 last_used_at，但**同一条令牌 60 秒内只写一次**：
// 内省在下游每个未命中缓存的请求上都会被调用，逐次 UPDATE 会把读路径变成写路径
// （行锁 + WAL + 一次额外往返）。代价是"极短时间内用过又立刻撤销"时，界面上的
// 最近使用时间可能停在上一分钟内——这是可接受的精度损失。
//
// 写失败只记账不报错：鉴权结论早已成立，审计字段丢一次不值得让下游请求失败。
func (s *Store) touchPersonalAccessToken(ctx context.Context, hash string) {
	now := time.Now()
	s.cacheMu.Lock()
	if s.patTouched == nil {
		s.patTouched = map[string]time.Time{}
	}
	if last, ok := s.patTouched[hash]; ok && now.Sub(last) < patLastUsedTTL {
		s.cacheMu.Unlock()
		return
	}
	s.patTouched[hash] = now
	// 只在这条路径上增长（每条用过的令牌一项）：超过阈值就顺手清掉过期的项。
	if len(s.patTouched) > 4096 {
		for k, at := range s.patTouched {
			if now.Sub(at) >= patLastUsedTTL {
				delete(s.patTouched, k)
			}
		}
	}
	s.cacheMu.Unlock()
	if _, err := s.DB.ExecContext(ctx, "UPDATE auth.personal_access_tokens SET last_used_at=now() WHERE token_hash=$1", hash); err != nil {
		// 不回显 err：数据库错误可能带上语句参数（哈希），而这里不值得为审计字段冒这个风险。
		log.Print("personal access token last_used_at update failed")
	}
}
