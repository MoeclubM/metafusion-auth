package store

// OAuth 2.0 / OIDC 授权方的存储侧：客户端登记、授权码签发与交换、令牌签发与吊销。
//
// 与 identity.go 的分工：identity.go 管「账号自己」（用户 / 会话 / 登录 / 续期），
// 本文件管「账号对外授权」（第三方客户端与它的码 / 令牌）。两者共用 sessionHash 与 access.go 的权限码。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// ── scope ──

// SupportedScopes 是账号服务承认的 scope 集合：发现文档的 scopes_supported、同意页的
// 说明文案与"请求收敛"都以它为准。新增一项必须同时补 handler/consent.go 的四语说明，
// 否则同意页会漏展示（由 handler 用例拦）。
var SupportedScopes = []string{"openid", "profile", "email"}

// DefaultScope 是请求未带 scope 时的默认值：与拆分前的默认值逐字一致，
// 老客户端（不传 scope）仍拿到同一个 scope。
const DefaultScope = "profile"

// ValidScope 判定单个 scope 是否受支持。
func ValidScope(code string) bool {
	code = strings.TrimSpace(code)
	for _, s := range SupportedScopes {
		if s == code {
			return true
		}
	}
	return false
}

// SplitScopes 把空格分隔的 scope 串拆成去重保序的集合，不做支持性判断。
func SplitScopes(raw string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, code := range strings.Fields(raw) {
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}

// UnsupportedScopes 返回请求里不受支持的 scope：错误响应靠它点明是哪一项，
// 而不是只回一个笼统的 invalid_scope。
func UnsupportedScopes(raw string) []string {
	out := []string{}
	for _, code := range SplitScopes(raw) {
		if !ValidScope(code) {
			out = append(out, code)
		}
	}
	return out
}

// SupportedSubset 过滤掉不受支持的 scope。只用于处理**存量数据**（已经发出的授权码）：
// 新请求一律走 ParseScopes 直接报错，不把不支持的 scope 静默降级。
func SupportedSubset(codes []string) []string {
	out := []string{}
	for _, code := range codes {
		if ValidScope(code) {
			out = append(out, code)
		}
	}
	return out
}

// ParseScopes 校验并归一化请求 scope：出现不支持的项直接 invalid_scope（不静默丢弃），
// 整个参数为空时回落 DefaultScope。
func ParseScopes(raw string) ([]string, error) {
	if len(UnsupportedScopes(raw)) > 0 {
		return nil, fmt.Errorf("invalid_scope")
	}
	codes := SplitScopes(raw)
	if len(codes) == 0 {
		return []string{DefaultScope}, nil
	}
	return codes, nil
}

// ConvergeScopes 收敛为「客户端允许 ∩ 请求」：保持请求顺序；客户端没被允许的一律不给，
// 因此给第三方的永远只是白名单的子集。
func ConvergeScopes(requested, allowed []string) []string {
	allow := map[string]bool{}
	for _, code := range allowed {
		allow[strings.TrimSpace(code)] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, code := range requested {
		code = strings.TrimSpace(code)
		if !allow[code] || seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}

// FormatScopes 是 scope 的存储与传输形式：空格分隔（与 OAuth 的 scope 参数一致）。
func FormatScopes(scopes []string) string { return strings.Join(scopes, " ") }

// ValidateClientScopes 校验管理 API 登记的客户端 scope 白名单：非空且全部受支持。
func ValidateClientScopes(scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("invalid_scopes")
	}
	for _, code := range scopes {
		if !ValidScope(code) {
			return fmt.Errorf("invalid_scope: %s", code)
		}
	}
	return nil
}

// RedirectURIAllowed 用逐字相等比较回调地址：白名单就是完整地址，
// 不做前缀/通配匹配（通配会让任何子域或路径都能收码）。
func RedirectURIAllowed(allowed []string, redirectURI string) bool {
	for _, uri := range allowed {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// ValidateHomepageURL 校验应用主页：空串表示没填（可选字段）；非空时必须是 http(s) 绝对地址，
// 不接受内嵌凭据——它会被渲染成同意页与开发者中心里的可点链接。
func ValidateHomepageURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return fmt.Errorf("invalid_homepage_url: %s", raw)
	}
	return nil
}

// ValidateClientDescription 校验应用简介长度：与客户名一样按**字符数**（不是字节数）计，
// 否则中文简介会被莫名其妙地判超长。
func ValidateClientDescription(desc string) error {
	if len([]rune(strings.TrimSpace(desc))) > 500 {
		return fmt.Errorf("invalid_client_description")
	}
	return nil
}

// ── 客户端管理（管理台，受 auth.oauth.manage 保护）──

// OAuthClientInput 是管理 API 与开发者中心的写入形状。字段用指针区分「没传」与「传了零值」：
// 更新接口只改传了的字段（改名 / 简介 / 主页 / 白名单 / scope / trusted / verified / 启停各改各的）。
// 开发者中心只允许前五项：管理面字段（trusted / disabled / verified）传了会被明确拒绝，
// 不是静默忽略——静默忽略会让开发者以为自己的应用已被信任。
type OAuthClientInput struct {
	ID           string    `json:"client_id"`
	Name         *string   `json:"name"`
	Description  *string   `json:"description"`
	HomepageURL  *string   `json:"homepage_url"`
	RedirectURIs *[]string `json:"redirect_uris"`
	Scopes       *[]string `json:"scopes"`
	Trusted      *bool     `json:"trusted"`
	Disabled     *bool     `json:"disabled"`
	Verified     *bool     `json:"verified"`
}

// seededClientIDs 是第一方种子客户端：Init 每次启动都按 id 复活它们，
// 删除只会让人误以为撤销成功，因此 DELETE 被拒（要停用用 disabled=true）。
var seededClientIDs = []string{"metafusion-catalog", "metafusion-forum", "metafusion-resources"}

var clientIDRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

// ValidClientID 校验客户端 id 形状：小写字母开头，后续为小写字母/数字/_/-。
func ValidClientID(id string) bool { return clientIDRe.MatchString(strings.TrimSpace(id)) }

// canManageOAuth 与 HTTP 层 requirePermission("auth.oauth.manage") 同源（store.Can）：
// 令牌带 permissions 时一律以码为准，只有完全没有权限声明的老令牌才按历史 role=admin 兜底。
func canManageOAuth(actor *User) bool { return Can(actor, "auth.oauth.manage") }

// ValidateRedirectURIs 校验回调白名单：每一条都必须是 http(s) 绝对地址，
// 不接受通配符、片段（#）与内嵌凭据——通配会让任何子域或任何路径都能收码。
func ValidateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return fmt.Errorf("invalid_redirect_uris")
	}
	for _, raw := range uris {
		uri := strings.TrimSpace(raw)
		if uri == "" || strings.Contains(uri, "*") {
			return fmt.Errorf("invalid_redirect_uri: %s", raw)
		}
		u, err := url.Parse(uri)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("invalid_redirect_uri: %s", raw)
		}
	}
	return nil
}

// GenerateClientSecret 生成一次性明文密钥：32 字节 base64url（43 字符，落在 bcrypt
// 的 72 字节上限内）。明文只在创建 / 轮换的响应里出现一次，之后库里只有哈希。
func GenerateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashClientSecret 生成密钥哈希（bcrypt）：与既有 secret_hash 列的校验方式一致。
func HashClientSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	return string(hash), err
}

// VerifyClientSecret 校验密钥。哈希为空表示「无密钥的第一方」，这里一律不通过；
// 是否放行由调用方结合 trusted 判定（见 ExchangeOAuthCode）。
func VerifyClientSecret(hash, secret string) bool {
	if hash == "" || secret == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil
}

func generateClientID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "mfc-" + hex.EncodeToString(b), nil
}

// normalizeStrings 去空格、丢空项、保序去重：白名单里的重复项只会让运维困惑。
func normalizeStrings(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// CreateOAuthClient 是管理台的客户端创建入口（要求 auth.oauth.manage）：可登记受信任的自有平台
// 与已核验应用。开发者自助登记走 CreateDeveloperApp，两者共用下面同一份实现与校验。
func (s *Store) CreateOAuthClient(ctx context.Context, in OAuthClientInput, actor *User) (OAuthClient, string, error) {
	if !canManageOAuth(actor) {
		return OAuthClient{}, "", fmt.Errorf("forbidden")
	}
	return s.createOAuthClient(ctx, in, actor, "", true)
}

// createOAuthClient 是管理台与开发者中心的共同实现：ownerID 非空表示该应用归属这个用户。
// privileged=false（开发者自建）时管理面字段一律落零值——否则开发者只要在请求体里塞一个
// trusted=true 就能跳过同意页，等于把"自有平台"的身份交给请求方自己声明。
func (s *Store) createOAuthClient(ctx context.Context, in OAuthClientInput, actor *User, ownerID string, privileged bool) (OAuthClient, string, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		gen, err := generateClientID()
		if err != nil {
			return OAuthClient{}, "", err
		}
		id = gen
	}
	if !ValidClientID(id) {
		return OAuthClient{}, "", fmt.Errorf("invalid_client_id")
	}
	name := ""
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if name == "" || len([]rune(name)) > 120 {
		return OAuthClient{}, "", fmt.Errorf("invalid_client_name")
	}
	description, homepage := "", ""
	if in.Description != nil {
		description = strings.TrimSpace(*in.Description)
	}
	if err := ValidateClientDescription(description); err != nil {
		return OAuthClient{}, "", err
	}
	if in.HomepageURL != nil {
		homepage = strings.TrimSpace(*in.HomepageURL)
	}
	if err := ValidateHomepageURL(homepage); err != nil {
		return OAuthClient{}, "", err
	}
	scopes := append([]string{}, SupportedScopes...)
	if in.Scopes != nil {
		scopes = normalizeStrings(*in.Scopes)
	}
	if err := ValidateClientScopes(scopes); err != nil {
		return OAuthClient{}, "", err
	}
	uris := []string{}
	if in.RedirectURIs != nil {
		uris = normalizeStrings(*in.RedirectURIs)
	}
	if err := ValidateRedirectURIs(uris); err != nil {
		return OAuthClient{}, "", err
	}
	trusted, disabled, verified := false, false, false
	if privileged {
		trusted = in.Trusted != nil && *in.Trusted
		disabled = in.Disabled != nil && *in.Disabled
		verified = in.Verified != nil && *in.Verified
	}
	secret, err := GenerateClientSecret()
	if err != nil {
		return OAuthClient{}, "", err
	}
	hash, err := HashClientSecret(secret)
	if err != nil {
		return OAuthClient{}, "", err
	}
	// SecretHash 一并回填（json 标签是 "-"，不会进响应）：开发者中心靠它给出 has_secret，
	// 否则刚登记完的应用会被显示成"没有密钥"。
	client := OAuthClient{ID: id, SecretHash: hash, Name: name, Description: description, HomepageURL: homepage, RedirectURIs: uris, Scopes: scopes, Trusted: trusted, Disabled: disabled, Verified: verified, OwnerID: ownerID, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	err = s.write(ctx, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, "SELECT true FROM auth.oauth_clients WHERE id=$1", client.ID).Scan(&exists); err == nil {
			return fmt.Errorf("client_exists")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO auth.oauth_clients(id, secret_hash, name, description, homepage_url, redirect_uris, scopes, trusted, disabled, verified, owner_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", client.ID, hash, client.Name, client.Description, client.HomepageURL, pq.Array(client.RedirectURIs), pq.Array(client.Scopes), client.Trusted, client.Disabled, client.Verified, nullableUUID(ownerID)); err != nil {
			return err
		}
		return recordOAuthAuditTx(ctx, tx, actor.ID, "", client.ID, OAuthActionClientCreate, client.Scopes, client.Name)
	})
	if err != nil {
		return OAuthClient{}, "", err
	}
	return client, secret, nil
}

// UpdateOAuthClient 是管理台的客户端更新入口（要求 auth.oauth.manage），可改管理面字段。
func (s *Store) UpdateOAuthClient(ctx context.Context, id string, in OAuthClientInput, actor *User) (OAuthClient, error) {
	if !canManageOAuth(actor) {
		return OAuthClient{}, fmt.Errorf("forbidden")
	}
	return s.updateOAuthClient(ctx, id, in, actor, true, nil)
}

// updateOAuthClient 是管理台与开发者中心的共同实现：只改传了的字段，并逐项做与创建时相同的校验。
// check 在行锁内拿到当前客户端（含 owner 与 trusted），归属判定与更新因此是同一个原子动作，
// 不会出现"判定时还是我的、更新时已易主"。
func (s *Store) updateOAuthClient(ctx context.Context, id string, in OAuthClientInput, actor *User, privileged bool, check func(*OAuthClient) error) (OAuthClient, error) {
	id = strings.TrimSpace(id)
	if !ValidClientID(id) {
		return OAuthClient{}, fmt.Errorf("invalid_client_id")
	}
	if !privileged && (in.Trusted != nil || in.Disabled != nil || in.Verified != nil) {
		return OAuthClient{}, fmt.Errorf("invalid_field: app_managed_fields")
	}
	sets := []string{}
	args := []any{}
	changed := []string{}
	add := func(col string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s=$%d", col, len(args)))
		changed = append(changed, col)
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len([]rune(name)) > 120 {
			return OAuthClient{}, fmt.Errorf("invalid_client_name")
		}
		add("name", name)
	}
	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		if err := ValidateClientDescription(description); err != nil {
			return OAuthClient{}, err
		}
		add("description", description)
	}
	if in.HomepageURL != nil {
		homepage := strings.TrimSpace(*in.HomepageURL)
		if err := ValidateHomepageURL(homepage); err != nil {
			return OAuthClient{}, err
		}
		add("homepage_url", homepage)
	}
	if in.RedirectURIs != nil {
		uris := normalizeStrings(*in.RedirectURIs)
		if err := ValidateRedirectURIs(uris); err != nil {
			return OAuthClient{}, err
		}
		add("redirect_uris", pq.Array(uris))
	}
	if in.Scopes != nil {
		scopes := normalizeStrings(*in.Scopes)
		if err := ValidateClientScopes(scopes); err != nil {
			return OAuthClient{}, err
		}
		add("scopes", pq.Array(scopes))
	}
	if privileged {
		if in.Trusted != nil {
			add("trusted", *in.Trusted)
		}
		if in.Disabled != nil {
			add("disabled", *in.Disabled)
		}
		if in.Verified != nil {
			add("verified", *in.Verified)
		}
	}
	err := s.write(ctx, func(tx *sql.Tx) error {
		current, err := lockedClient(ctx, tx, id)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(current); err != nil {
				return err
			}
		}
		if len(sets) == 0 {
			return nil
		}
		args = append(args, id)
		q := "UPDATE auth.oauth_clients SET " + strings.Join(sets, ", ") + fmt.Sprintf(" WHERE id=$%d", len(args))
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
		return recordOAuthAuditTx(ctx, tx, actor.ID, "", id, OAuthActionClientUpdate, nil, strings.Join(changed, ","))
	})
	if err != nil {
		return OAuthClient{}, err
	}
	client, err := s.GetOAuthClient(ctx, id)
	if err != nil {
		return OAuthClient{}, err
	}
	return *client, nil
}

// lockedClient 在事务里按 id 锁定并读出一个客户端的最小投影（归属 + 可展示字段），
// 供更新 / 轮换 / 删除这类"先判归属再动手"的路径复用。行不存在时返回 client_not_found。
func lockedClient(ctx context.Context, tx *sql.Tx, id string) (*OAuthClient, error) {
	var c OAuthClient
	if err := tx.QueryRowContext(ctx, "SELECT id, name, COALESCE(owner_user_id::text,''), trusted FROM auth.oauth_clients WHERE id=$1 FOR UPDATE", id).Scan(&c.ID, &c.Name, &c.OwnerID, &c.Trusted); err != nil {
		return nil, fmt.Errorf("client_not_found")
	}
	return &c, nil
}

// RotateOAuthClientSecret 轮换密钥：写入新哈希并返回一次性明文。老密钥立即失效
// （库里只有哈希，没有回滚路径）；对「无密钥的第一方」轮换后该客户端必须开始带
// client_secret 才换得到令牌，运维需同步更新对端配置。
func (s *Store) RotateOAuthClientSecret(ctx context.Context, id string, actor *User) (OAuthClient, string, error) {
	if !canManageOAuth(actor) {
		return OAuthClient{}, "", fmt.Errorf("forbidden")
	}
	return s.rotateOAuthClientSecret(ctx, id, actor, nil)
}

func (s *Store) rotateOAuthClientSecret(ctx context.Context, id string, actor *User, check func(*OAuthClient) error) (OAuthClient, string, error) {
	id = strings.TrimSpace(id)
	if !ValidClientID(id) {
		return OAuthClient{}, "", fmt.Errorf("invalid_client_id")
	}
	secret, err := GenerateClientSecret()
	if err != nil {
		return OAuthClient{}, "", err
	}
	hash, err := HashClientSecret(secret)
	if err != nil {
		return OAuthClient{}, "", err
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		current, err := lockedClient(ctx, tx, id)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(current); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE auth.oauth_clients SET secret_hash=$1 WHERE id=$2", hash, id); err != nil {
			return err
		}
		return recordOAuthAuditTx(ctx, tx, actor.ID, "", id, OAuthActionClientRotate, nil, "")
	})
	if err != nil {
		return OAuthClient{}, "", err
	}
	client, err := s.GetOAuthClient(ctx, id)
	if err != nil {
		return OAuthClient{}, "", err
	}
	return *client, secret, nil
}

// DeleteOAuthClient 删除客户端（管理台入口）：授权码与令牌随外键级联删除，已签发的 jti 一并作废。
// 种子客户端拒绝删除（见 seededClientIDs）；审计行保留，删客户端不抹痕迹。
func (s *Store) DeleteOAuthClient(ctx context.Context, id string, actor *User) error {
	if !canManageOAuth(actor) {
		return fmt.Errorf("forbidden")
	}
	return s.deleteOAuthClient(ctx, id, actor, nil)
}

func (s *Store) deleteOAuthClient(ctx context.Context, id string, actor *User, check func(*OAuthClient) error) error {
	id = strings.TrimSpace(id)
	for _, seeded := range seededClientIDs {
		if seeded == id {
			return fmt.Errorf("seeded_client_immutable")
		}
	}
	var issued []revokedToken
	err := s.write(ctx, func(tx *sql.Tx) error {
		current, err := lockedClient(ctx, tx, id)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(current); err != nil {
				return err
			}
		}
		name := current.Name
		if issued, err = issuedTokensFor(ctx, tx, "client_id", id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM auth.oauth_clients WHERE id=$1", id); err != nil {
			return err
		}
		return recordOAuthAuditTx(ctx, tx, actor.ID, "", id, OAuthActionClientDelete, nil, name)
	})
	if err != nil {
		return err
	}
	revokeIssued(s.Tokens, issued)
	return nil
}

// OAuthClient 是客户端的对外投影：SecretHash 永不出现在 JSON 里（json:"-"）。
// Verified 是核验状态（自有平台恒为已核验，见 DeveloperApp）；自己人是第一方还是第三方，
// 由 FirstParty 判定，不靠调用方猜 trusted 的含义。
type OAuthClient struct {
	ID           string   `json:"client_id"`
	SecretHash   string   `json:"-"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	HomepageURL  string   `json:"homepage_url"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Trusted      bool     `json:"trusted"`
	Disabled     bool     `json:"disabled"`
	Verified     bool     `json:"verified"`
	OwnerID      string   `json:"owner_user_id,omitempty"`
	Owner        string   `json:"owner_username,omitempty"`
	CreatedAt    string   `json:"created_at"`
}

// FirstParty 判定"自有平台"：受信任（免同意）的客户端只能是平台自己登记的。
// 开发者中心自建的应用永远拿不到 trusted，因此这个判定不会把第三方的应用认成自家的。
func (c OAuthClient) FirstParty() bool { return c.Trusted }

// clientColumns 是客户端投影的列清单：列表、详情与开发者中心共用一份，避免三处形状漂移。
const clientColumns = "c.id, c.secret_hash, c.name, c.description, c.homepage_url, c.redirect_uris, c.scopes, c.trusted, c.disabled, c.verified, COALESCE(c.owner_user_id::text,''), COALESCE(u.username,''), c.created_at"

// scanClient 按 clientColumns 的顺序读一行（列表与详情共用）。
func scanClient(row interface{ Scan(...any) error }) (OAuthClient, error) {
	var c OAuthClient
	var uris, scopes []string
	var created time.Time
	if err := row.Scan(&c.ID, &c.SecretHash, &c.Name, &c.Description, &c.HomepageURL, pq.Array(&uris), pq.Array(&scopes), &c.Trusted, &c.Disabled, &c.Verified, &c.OwnerID, &c.Owner, &created); err != nil {
		return c, err
	}
	c.RedirectURIs = uris
	c.Scopes = scopes
	c.CreatedAt = created.UTC().Format(time.RFC3339)
	return c, nil
}

func (s *Store) ListOAuthClients(ctx context.Context) ([]OAuthClient, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+clientColumns+" FROM auth.oauth_clients c LEFT JOIN auth.users u ON u.id=c.owner_user_id ORDER BY c.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []OAuthClient
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (s *Store) GetOAuthClient(ctx context.Context, id string) (*OAuthClient, error) {
	row := s.DB.QueryRowContext(ctx, "SELECT "+clientColumns+" FROM auth.oauth_clients c LEFT JOIN auth.users u ON u.id=c.owner_user_id WHERE c.id=$1", strings.TrimSpace(id))
	c, err := scanClient(row)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateOAuthCode 签发授权码：challenge 为 PKCE code_challenge（可空），method 仅接受
// S256/plain，其它值拒绝（避免降级绕过）。
//
// scope 在这里**再收敛一次**（调用方通常已按收敛结果渲染过同意页）：写进码里的只能是
// 「客户端允许 ∩ 请求」的交集，任何调用方都无法把客户端没被允许的 scope 塞进码里。
// 返回码与最终写库的 scope。
func (s *Store) CreateOAuthCode(ctx context.Context, clientID string, userID string, redirectURI, requestedScope, challenge, method string) (string, string, error) {
	client, err := s.GetOAuthClient(ctx, clientID)
	if err != nil || client == nil {
		return "", "", fmt.Errorf("invalid_client")
	}
	if client.Disabled {
		// 停用的客户端不能再拿到新的授权码（已发出的令牌由 userinfo 侧拒绝）。
		return "", "", fmt.Errorf("invalid_client")
	}
	requested, err := ParseScopes(requestedScope)
	if err != nil {
		return "", "", err
	}
	granted := ConvergeScopes(requested, client.Scopes)
	if len(granted) == 0 {
		return "", "", fmt.Errorf("invalid_scope")
	}
	if !RedirectURIAllowed(client.RedirectURIs, redirectURI) {
		return "", "", fmt.Errorf("invalid_redirect_uri")
	}
	challenge = strings.TrimSpace(challenge)
	method = strings.ToUpper(strings.TrimSpace(method))
	if challenge == "" {
		method = ""
	} else if method != "S256" && method != "PLAIN" {
		return "", "", fmt.Errorf("invalid_code_challenge_method")
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	code := hex.EncodeToString(b)
	scope := FormatScopes(granted)
	if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.oauth_codes(code, client_id, user_id, redirect_uri, scope, expires_at, code_challenge, code_challenge_method) VALUES($1, $2, $3, $4, $5, $6, $7, $8)", code, clientID, userID, redirectURI, scope, time.Now().Add(10*time.Minute), challenge, method); err != nil {
		return "", "", err
	}
	return code, scope, nil
}

// VerifyPKCE 按 RFC 7636 校验 verifier。导出是因为内存实现（handler 的测试替身）
// 必须用同一份判定，不能在两边各写一套 PKCE 规则。
func VerifyPKCE(method, challenge, verifier string) bool {
	return verifyPKCE(method, challenge, verifier)
}

// verifyPKCE 按 RFC 7636 校验 verifier：S256 比较 BASE64URL(SHA256(verifier))，
// plain 直接比对。存量无 challenge 的码视为公开客户端历史行为，不强制。
func verifyPKCE(method, challenge, verifier string) bool {
	if challenge == "" {
		return true
	}
	verifier = strings.TrimSpace(verifier)
	if verifier == "" {
		return false
	}
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return challenge == base64.RawURLEncoding.EncodeToString(sum[:])
	case "PLAIN", "plain":
		return challenge == verifier
	default:
		return false
	}
}

// OAuthGrant 是一次成功的授权码兑换：令牌、最终 scope 与**真实**有效期。
// ExpiresIn 直接取自签发器（JWT 为 AccessTokenTTL），响应里的 expires_in 不再估算。
type OAuthGrant struct {
	Token     string
	Scope     string
	ExpiresIn int
	User      *User
}

func (s *Store) ExchangeOAuthCode(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (OAuthGrant, error) {
	client, err := s.GetOAuthClient(ctx, clientID)
	if err != nil || client == nil {
		return OAuthGrant{}, fmt.Errorf("invalid_client")
	}
	if client.Disabled {
		return OAuthGrant{}, fmt.Errorf("invalid_client")
	}
	if client.SecretHash != "" {
		if clientSecret == "" || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)) != nil {
			return OAuthGrant{}, fmt.Errorf("invalid_client_secret")
		}
	} else if !client.Trusted {
		// 无密钥的非受信客户端一律拒绝：空密钥只能是预置受信第一方，
		// 且第一方也应尽快配置密钥或改走 PKCE。
		return OAuthGrant{}, fmt.Errorf("invalid_client_secret")
	}
	var userID string
	var codeURI string
	var codeScope string
	var challenge, challengeMethod string
	// 先读码并完成全部校验，再原子标记已用：PKCE/redirect 校验失败**不得消耗**
	// 授权码，否则一次错误 verifier 请求即可作废合法客户端刚拿到的码。
	// 单次性由下方条件 UPDATE 保证：并发双兑只有一个成功，后到者按未命中
	// 拿到 expired_or_used_code。
	err = s.DB.QueryRowContext(ctx, "SELECT user_id, redirect_uri, scope, COALESCE(code_challenge,''), COALESCE(code_challenge_method,'') FROM auth.oauth_codes WHERE code=$1 AND client_id=$2 AND used=false AND expires_at>now()", strings.TrimSpace(code), clientID).Scan(&userID, &codeURI, &codeScope, &challenge, &challengeMethod)
	if err != nil {
		return OAuthGrant{}, fmt.Errorf("expired_or_used_code")
	}
	if redirectURI != "" && redirectURI != codeURI {
		return OAuthGrant{}, fmt.Errorf("redirect_uri_mismatch")
	}
	if !verifyPKCE(challengeMethod, challenge, verifier) {
		return OAuthGrant{}, fmt.Errorf("invalid_code_verifier")
	}
	res, err := s.DB.ExecContext(ctx, "UPDATE auth.oauth_codes SET used=true WHERE code=$1 AND client_id=$2 AND used=false AND expires_at>now()", strings.TrimSpace(code), clientID)
	if err != nil {
		return OAuthGrant{}, fmt.Errorf("invalid_grant")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return OAuthGrant{}, fmt.Errorf("expired_or_used_code")
	}
	// 换码时按客户端**当前**的 scope 白名单再收敛一次：管理员可能在发码之后收紧了白名单，
	// 令牌只能更少、不能更多。存量码里若有已不再支持的 scope 按支持集合过滤掉，
	// 不静默放宽成默认 scope。
	granted := ConvergeScopes(SupportedSubset(SplitScopes(codeScope)), client.Scopes)
	if len(granted) == 0 {
		return OAuthGrant{}, fmt.Errorf("invalid_scope")
	}
	var u User
	if err = s.DB.QueryRowContext(ctx, "SELECT id, username, COALESCE(email,''), role FROM auth.users WHERE id=$1", userID).Scan(&u.ID, &u.Username, &u.Email, &u.Role); err != nil {
		return OAuthGrant{}, err
	}
	// 签发 OIDC access_token：配置签发器时为 RS256 JWT（可被 JWKS 本地验签），
	// 否则退回不透明随机串。无论哪种都只落 SHA-256 以便吊销。
	token, jti, ttl, exp, err := s.signOAuthToken(u)
	if err != nil {
		return OAuthGrant{}, err
	}
	// 行的过期时刻与令牌真实有效期一致：JWT 只有 AccessTokenTTL，行留 30 天会让
	// "查库兜底"把已过期的令牌当成有效（userinfo 以存活行为准）。
	expiresAt := time.Now().Add(ttl)
	if exp > 0 {
		expiresAt = time.Unix(exp, 0)
	}
	scope := FormatScopes(granted)
	if _, err = s.DB.ExecContext(ctx, "INSERT INTO auth.oauth_tokens(token_hash, client_id, user_id, scope, jti, expires_at) VALUES($1, $2, $3, $4, $5, $6)", sessionHash(token), clientID, userID, scope, jti, expiresAt); err != nil {
		return OAuthGrant{}, err
	}
	return OAuthGrant{Token: token, Scope: scope, ExpiresIn: int(ttl.Seconds()), User: &u}, nil
}

// signOAuthToken 为 OAuth/OIDC 流程签发访问令牌：有签发器用 RS256 JWT，
// 否则用 32 字节随机串。返回值里的 jti 用于按客户端/用户批量吊销
// （不透明随机串没有 jti，靠令牌行走吊销）。
func (s *Store) signOAuthToken(u User) (string, string, time.Duration, int64, error) {
	if s.Tokens == nil {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", "", 0, 0, err
		}
		return hex.EncodeToString(b), "", 30 * 24 * time.Hour, 0, nil
	}
	token, jti, exp, err := s.Tokens.Sign(u)
	if err != nil {
		return "", "", 0, 0, err
	}
	// 用常量而不是 time.Until(exp)：后者带签发耗时误差，会让 expires_in 报出 899 这种数字。
	return token, jti, AccessTokenTTL, exp.Unix(), nil
}

// IDToken 为 OIDC 客户端签发 id_token：与访问令牌同密钥、同算法、同身份声明，
// 额外把 aud 指向客户端。客户端可用 JWKS 公钥本地验签获得用户身份。
func (s *Store) IDToken(u User, clientID string) (string, int64, error) {
	if s.Tokens == nil {
		return "", 0, nil
	}
	aud := clientID
	if aud == "" {
		aud = s.Tokens.Audience()
	}
	token, exp, err := s.Tokens.SignForAudience(u, aud)
	if err != nil {
		return "", 0, err
	}
	return token, exp.Unix(), nil
}

func (s *Store) UserFromOAuthToken(ctx context.Context, token string) (*User, error) {
	// 与 Authenticate 同口径：令牌有效不代表账号可用（封禁的账号不能借第三方令牌读 userinfo）。
	var u User
	err := s.DB.QueryRowContext(ctx, "SELECT u.id, u.username, COALESCE(u.email,''), u.role FROM auth.oauth_tokens t JOIN auth.users u ON u.id=t.user_id WHERE t.token_hash=$1 AND NOT u.banned AND t.expires_at>now()", sessionHash(token)).Scan(&u.ID, &u.Username, &u.Email, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ── 令牌吊销 ──

// revokedToken 是吊销时要回填给签发器的一条记录：jti 与它自然过期的时间
// （签发器的注销集合只保留到该时刻）。
type revokedToken struct {
	jti string
	exp time.Time
}

// issuedTokensFor 读取某个维度（client_id / user_id）下未过期的令牌行。
// column 只接受调用方写死的常量，不存在拼接用户输入的 SQL。
func issuedTokensFor(ctx context.Context, tx *sql.Tx, column, value string) ([]revokedToken, error) {
	rows, err := tx.QueryContext(ctx, "SELECT COALESCE(jti,''), expires_at FROM auth.oauth_tokens WHERE "+column+"=$1 AND expires_at>now()", value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []revokedToken
	for rows.Next() {
		var r revokedToken
		if err := rows.Scan(&r.jti, &r.exp); err != nil {
			return nil, err
		}
		if r.jti != "" {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// revokeIssued 把一批 jti 放进签发器的注销集合：本进程内已签发的无状态 JWT 立即失效。
// 签发器为 nil（纯查库模式）时是安全的空操作。
func revokeIssued(t *TokenIssuer, tokens []revokedToken) {
	for _, r := range tokens {
		t.Revoke(r.jti, r.exp.Unix())
	}
}

// RevokeOAuthTokensByClient 吊销某客户端名下未过期的访问令牌，并作废它尚未兑换的授权码
// （否则被吊销的客户端可以立刻拿旧码换一个新令牌）。返回吊销的令牌数。
func (s *Store) RevokeOAuthTokensByClient(ctx context.Context, clientID string, actor *User) (int, error) {
	clientID = strings.TrimSpace(clientID)
	return s.revokeOAuthTokens(ctx, "client_id", clientID, clientID, "", actor)
}

// RevokeOAuthTokensByUser 吊销某用户名下全部未过期的第三方访问令牌（第三方站点对它的授权）。
// 与 /auth/logout-all 的分工：这里只动 OAuth 令牌，不删该用户自己的服务端会话。
func (s *Store) RevokeOAuthTokensByUser(ctx context.Context, userID string, actor *User) (int, error) {
	userID = strings.TrimSpace(userID)
	return s.revokeOAuthTokens(ctx, "user_id", userID, "", "user:"+userID, actor)
}

// ── 用户自助管理自己的授权 ──

// AuthorizedApp 是"某个用户对某个客户端的授权"的对外投影，供设置页展示与自助撤回。
// Active 表示当前还有未过期的令牌；LastAuthorizedAt 来自同意审计，
// 因此"授权过、令牌已过期"的应用也会出现在列表里而不是凭空消失。
type AuthorizedApp struct {
	ClientID         string   `json:"client_id"`
	Name             string   `json:"name"`
	Scopes           []string `json:"scopes"`
	Active           bool     `json:"active"`
	LastAuthorizedAt string   `json:"last_authorized_at,omitempty"`
	ExpiresAt        string   `json:"expires_at,omitempty"`
}

// ListOAuthGrants 列出该用户授权过的应用。取两份数据的并集：
// 未过期的第三方令牌（仍在生效）与同意审计（授权过、含已到期）。
// 只看令牌会漏掉"授权过但已过期"的应用，只看审计会漏掉同意页改造前签发的令牌。
func (s *Store) ListOAuthGrants(ctx context.Context, userID string) ([]AuthorizedApp, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("authentication_required")
	}
	type acc struct {
		name    string
		scopes  map[string]bool
		active  bool
		lastAt  time.Time
		expires time.Time
	}
	grants := map[string]*acc{}
	touch := func(clientID string) *acc {
		g, ok := grants[clientID]
		if !ok {
			g = &acc{scopes: map[string]bool{}}
			grants[clientID] = g
		}
		return g
	}

	rows, err := s.DB.QueryContext(ctx, "SELECT t.client_id, COALESCE(c.name,''), t.scope, t.expires_at FROM auth.oauth_tokens t LEFT JOIN auth.oauth_clients c ON c.id=t.client_id WHERE t.user_id=$1 AND t.expires_at>now()", userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var clientID, name, scope string
		var exp time.Time
		if err := rows.Scan(&clientID, &name, &scope, &exp); err != nil {
			rows.Close()
			return nil, err
		}
		g := touch(clientID)
		if g.name == "" {
			g.name = name
		}
		for _, sc := range SplitScopes(scope) {
			g.scopes[sc] = true
		}
		g.active = true
		if exp.After(g.expires) {
			g.expires = exp
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	audits, err := s.DB.QueryContext(ctx, "SELECT a.client_id, COALESCE(c.name,''), a.scopes, a.created_at FROM auth.oauth_audit a LEFT JOIN auth.oauth_clients c ON c.id=a.client_id WHERE a.subject_user_id=$1 AND a.action IN ($2,$3) ORDER BY a.created_at DESC", userID, OAuthActionConsentAllow, OAuthActionTrustedAllow)
	if err != nil {
		return nil, err
	}
	for audits.Next() {
		var clientID, name string
		var scopes []string
		var at time.Time
		if err := audits.Scan(&clientID, &name, pq.Array(&scopes), &at); err != nil {
			audits.Close()
			return nil, err
		}
		g := touch(clientID)
		if g.name == "" {
			g.name = name
		}
		// 审计按时间倒序：第一条即最近一次授权，只有它决定"最近授权时间"。
		if g.lastAt.IsZero() {
			g.lastAt = at
			// 没有生效中的令牌时（已过期或已被撤回），scope 以最近一次授权为准，
			// 否则列表会显示一个空 scope 的应用。
			if !g.active {
				for _, sc := range scopes {
					g.scopes[sc] = true
				}
			}
		}
	}
	audits.Close()
	if err := audits.Err(); err != nil {
		return nil, err
	}

	out := make([]AuthorizedApp, 0, len(grants))
	for clientID, g := range grants {
		// 客户端已被删除时名字取不到，用 client_id 兜底：列表项不能没有标题。
		name := g.name
		if strings.TrimSpace(name) == "" {
			name = clientID
		}
		item := AuthorizedApp{ClientID: clientID, Name: name, Scopes: SortedScopes(g.scopes), Active: g.active}
		if !g.lastAt.IsZero() {
			item.LastAuthorizedAt = g.lastAt.UTC().Format(time.RFC3339)
		}
		if g.active && !g.expires.IsZero() {
			item.ExpiresAt = g.expires.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		if out[i].LastAuthorizedAt != out[j].LastAuthorizedAt {
			return out[i].LastAuthorizedAt > out[j].LastAuthorizedAt
		}
		return out[i].ClientID < out[j].ClientID
	})
	return out, nil
}

// SortedScopes 把 scope 集合按稳定顺序展开（授权顺序不留痕，排序保证列表与审计可比对）。
func SortedScopes(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for sc := range set {
		out = append(out, sc)
	}
	sort.Strings(out)
	return out
}

// RevokeOwnOAuthGrant 让用户撤回自己对某个应用的授权：删除本人该客户端的未过期令牌
// 与未兑换的授权码，并留一条审计。
//
// 只按 (user_id, client_id) 定位，天然碰不到别人的授权——这也是它与管理员的
// /admin/users/{id}/revoke-oauth-tokens（按用户，需权限码）的区别。
func (s *Store) RevokeOwnOAuthGrant(ctx context.Context, userID, clientID string) (int, error) {
	userID = strings.TrimSpace(userID)
	clientID = strings.TrimSpace(clientID)
	if userID == "" {
		return 0, fmt.Errorf("authentication_required")
	}
	if clientID == "" {
		return 0, fmt.Errorf("invalid_client")
	}
	if _, err := s.GetOAuthClient(ctx, clientID); err != nil {
		return 0, fmt.Errorf("client_not_found")
	}
	var (
		issued []revokedToken
		n      int
	)
	err := s.write(ctx, func(tx *sql.Tx) error {
		var err error
		if issued, err = issuedTokensForOwnGrant(ctx, tx, userID, clientID); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, "DELETE FROM auth.oauth_tokens WHERE user_id=$1 AND client_id=$2 AND expires_at>now()", userID, clientID)
		if err != nil {
			return err
		}
		deleted, _ := res.RowsAffected()
		n = int(deleted)
		if _, err := tx.ExecContext(ctx, "DELETE FROM auth.oauth_codes WHERE user_id=$1 AND client_id=$2 AND used=false AND expires_at>now()", userID, clientID); err != nil {
			return err
		}
		return recordOAuthAuditTx(ctx, tx, userID, userID, clientID, OAuthActionTokensRevoked, nil, "self_service")
	})
	if err != nil {
		return 0, err
	}
	revokeIssued(s.Tokens, issued)
	return n, nil
}

// issuedTokensForOwnGrant 读该用户在该客户端下未过期的令牌行（jti 用于本进程内立即注销）。
func issuedTokensForOwnGrant(ctx context.Context, tx *sql.Tx, userID, clientID string) ([]revokedToken, error) {
	rows, err := tx.QueryContext(ctx, "SELECT COALESCE(jti,''), expires_at FROM auth.oauth_tokens WHERE user_id=$1 AND client_id=$2 AND expires_at>now()", userID, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []revokedToken
	for rows.Next() {
		var r revokedToken
		if err := rows.Scan(&r.jti, &r.exp); err != nil {
			return nil, err
		}
		if r.jti != "" {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// revokeOAuthTokens 是两条吊销路径的共同实现：删除令牌/授权码与写审计在同一事务里完成，
// 不会出现"令牌没了但没有记录"或反之的中间态；提交后再注销 jti——回填内存状态不属于事务。
func (s *Store) revokeOAuthTokens(ctx context.Context, column, value, auditClientID, detail string, actor *User) (int, error) {
	if !canManageOAuth(actor) {
		return 0, fmt.Errorf("forbidden")
	}
	if value == "" {
		return 0, fmt.Errorf("invalid_revoke_target")
	}
	var (
		issued []revokedToken
		n      int
	)
	err := s.write(ctx, func(tx *sql.Tx) error {
		var err error
		if issued, err = issuedTokensFor(ctx, tx, column, value); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, "DELETE FROM auth.oauth_tokens WHERE "+column+"=$1 AND expires_at>now()", value)
		if err != nil {
			return err
		}
		deleted, _ := res.RowsAffected()
		n = int(deleted)
		if _, err := tx.ExecContext(ctx, "DELETE FROM auth.oauth_codes WHERE "+column+"=$1 AND used=false AND expires_at>now()", value); err != nil {
			return err
		}
		return recordOAuthAuditTx(ctx, tx, actor.ID, "", auditClientID, OAuthActionTokensRevoked, nil, detail)
	})
	if err != nil {
		return 0, err
	}
	revokeIssued(s.Tokens, issued)
	return n, nil
}

// ── 同意与操作的审计 ──

// 审计动作取值。同意/拒绝由 handler 在发码前落独立一行（写失败即拒绝授权：
// "谁把哪些 scope 授给了谁"必须可查），客户端管理与吊销由 store 在同一事务里写。
const (
	OAuthActionConsentAllow  = "consent_allow"
	OAuthActionConsentDeny   = "consent_deny"
	OAuthActionTrustedAllow  = "trusted_allow"
	OAuthActionClientCreate  = "client_create"
	OAuthActionClientUpdate  = "client_update"
	OAuthActionClientRotate  = "client_secret_rotated"
	OAuthActionClientDelete  = "client_deleted"
	OAuthActionTokensRevoked = "tokens_revoked"
)

// OAuthAuditEntry 是一条授权审计：谁（actor）对哪个客户端 / 哪个用户做了什么、
// 授了哪些 scope、何时。client_id 不建外键——客户端删掉之后这份记录必须还在。
type OAuthAuditEntry struct {
	ID        string   `json:"id"`
	ActorID   string   `json:"actor_user_id,omitempty"`
	Actor     string   `json:"actor_username,omitempty"`
	SubjectID string   `json:"subject_user_id,omitempty"`
	ClientID  string   `json:"client_id"`
	Action    string   `json:"action"`
	Scopes    []string `json:"scopes"`
	Detail    string   `json:"detail,omitempty"`
	CreatedAt string   `json:"created_at"`
}

// RecordOAuthAudit 记一条独立审计（同意页的同意/拒绝走这里）。
func (s *Store) RecordOAuthAudit(ctx context.Context, entry OAuthAuditEntry) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		return recordOAuthAuditTx(ctx, tx, entry.ActorID, entry.SubjectID, entry.ClientID, entry.Action, entry.Scopes, entry.Detail)
	})
}

// recordOAuthAuditTx 在调用方的事务里插审计行：与业务动作同生共死。
func recordOAuthAuditTx(ctx context.Context, tx *sql.Tx, actorID, subjectID, clientID, action string, scopes []string, detail string) error {
	if scopes == nil {
		scopes = []string{}
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO auth.oauth_audit(id, actor_user_id, subject_user_id, client_id, action, scopes, detail) VALUES($1,$2,$3,$4,$5,$6,$7)", newUUID(), nullableUUID(actorID), nullableUUID(subjectID), clientID, action, pq.Array(scopes), detail)
	return err
}

// nullableUUID 把空串转成 SQL NULL：审计里 actor/subject 允许缺省。
func nullableUUID(id string) any {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	return id
}

// ListOAuthAudits 读最近的授权审计（管理台排障用），可按 client_id 过滤。
func (s *Store) ListOAuthAudits(ctx context.Context, clientID string, limit int) ([]OAuthAuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{}
	where := ""
	if cid := strings.TrimSpace(clientID); cid != "" {
		args = append(args, cid)
		where = fmt.Sprintf(" WHERE a.client_id=$%d", len(args))
	}
	args = append(args, limit)
	q := "SELECT a.id, COALESCE(a.actor_user_id::text,''), COALESCE(u.username,''), COALESCE(a.subject_user_id::text,''), a.client_id, a.action, a.scopes, a.detail, a.created_at" +
		" FROM auth.oauth_audit a LEFT JOIN auth.users u ON u.id=a.actor_user_id" + where + fmt.Sprintf(" ORDER BY a.created_at DESC LIMIT $%d", len(args))
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthAuditEntry{}
	for rows.Next() {
		var (
			e       OAuthAuditEntry
			scopes  []string
			created time.Time
		)
		if err := rows.Scan(&e.ID, &e.ActorID, &e.Actor, &e.SubjectID, &e.ClientID, &e.Action, pq.Array(&scopes), &e.Detail, &created); err != nil {
			return nil, err
		}
		e.Scopes = scopes
		e.CreatedAt = created.UTC().Format(time.RFC3339)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── userinfo ──

// OAuthUserinfo 解析第三方访问令牌：判定依据是 auth.oauth_tokens 的**存活行**
// （且客户端未被停用），而不是 JWT 验签结果。
//
// 这样吊销 / 停用 / 过期都能即时生效：JWT 在有效期内自身仍可验签，这是无状态令牌的
// 固有性质——下游服务用 JWKS 本地验签时只能等短 TTL 自然过期（README 里如实写明）。
// 兼容登录令牌：没有 oauth_tokens 行时回退 auth.sessions，此时 scope 记为空串。
func (s *Store) OAuthUserinfo(ctx context.Context, token string) (*User, string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, "", fmt.Errorf("invalid_token")
	}
	hash := sessionHash(token)
	var u User
	var scope string
	err := s.DB.QueryRowContext(ctx, "SELECT u.id, u.username, COALESCE(u.email,''), u.role, t.scope FROM auth.oauth_tokens t JOIN auth.users u ON u.id=t.user_id JOIN auth.oauth_clients c ON c.id=t.client_id WHERE t.token_hash=$1 AND t.expires_at>now() AND c.disabled=false", hash).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &scope)
	if err == nil {
		return &u, scope, nil
	}
	if err := s.DB.QueryRowContext(ctx, "SELECT u.id, u.username, COALESCE(u.email,''), u.role FROM auth.sessions s JOIN auth.users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()", hash).Scan(&u.ID, &u.Username, &u.Email, &u.Role); err != nil {
		return nil, "", fmt.Errorf("invalid_token")
	}
	return &u, "", nil
}
