package store

// 准入与权限：实例设置、邀请码、权限组。
//
// 职责边界：账号服务只负责"存组、存权限码、算出某个人的权限集合"，**不解释权限码的含义**。
// 各子系统（目录 / 论坛 / 存储）各自声明自己的权限码（如 catalog.entity.edit、
// community.post.moderate），在自己的代码里把码映射成本地能力；两边都只从
// /api/auth/me 或访问令牌的 claims 读取，谁也不查对方的库。
//
// 这样"元数据系统的权限组"和"论坛的权限组"可以完全不同，却都来源于同一份账号数据。

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"
)

// ── 权限码 ──

// PermissionCode 是一个已知权限码的清单项：给管理台下拉、文档与审阅用。
type PermissionCode struct {
	Code         string            `json:"code"`
	Service      string            `json:"service"`
	Names        map[string]string `json:"names"`
	Descriptions map[string]string `json:"descriptions,omitempty"`
}

// PermissionCatalog 内置各子系统的权限码清单（四语名）。
// 它只是"清单"，不是白名单：下游可以自定义新码，格式合法即可（见 ValidPermissionCode）。
func PermissionCatalog() []PermissionCode {
	return []PermissionCode{
		{Code: "*", Service: "auth", Names: map[string]string{"zh-CN": "全部权限", "zh-TW": "全部權限", "ja-JP": "すべての権限", "en-US": "All permissions"}},
		{Code: "auth.users.manage", Service: "auth", Names: map[string]string{"zh-CN": "管理账号", "zh-TW": "管理帳號", "ja-JP": "アカウント管理", "en-US": "Manage accounts"}},
		{Code: "auth.groups.manage", Service: "auth", Names: map[string]string{"zh-CN": "管理权限组", "zh-TW": "管理權限組", "ja-JP": "権限グループ管理", "en-US": "Manage permission groups"}},
		{Code: "auth.invites.manage", Service: "auth", Names: map[string]string{"zh-CN": "管理邀请码", "zh-TW": "管理邀請碼", "ja-JP": "招待コード管理", "en-US": "Manage invite codes"}},
		{Code: "auth.settings.manage", Service: "auth", Names: map[string]string{"zh-CN": "管理实例设置", "zh-TW": "管理實例設定", "ja-JP": "インスタンス設定", "en-US": "Manage instance settings"}},
		{Code: "auth.oauth.manage", Service: "auth", Names: map[string]string{"zh-CN": "管理 OAuth 客户端", "zh-TW": "管理 OAuth 用戶端", "ja-JP": "OAuth クライアントの管理", "en-US": "Manage OAuth clients"}},
		{Code: "catalog.entity.edit", Service: "catalog", Names: map[string]string{"zh-CN": "编辑目录实体", "zh-TW": "編輯目錄實體", "ja-JP": "カタログ実体の編集", "en-US": "Edit catalog entities"}},
		{Code: "catalog.relation.edit", Service: "catalog", Names: map[string]string{"zh-CN": "编辑实体关系", "zh-TW": "編輯實體關係", "ja-JP": "関係の編集", "en-US": "Edit entity relations"}},
		{Code: "catalog.definitions.manage", Service: "catalog", Names: map[string]string{"zh-CN": "管理动态定义", "zh-TW": "管理動態定義", "ja-JP": "動的定義の管理", "en-US": "Manage dynamic definitions"}},
		{Code: "catalog.lifecycle.manage", Service: "catalog", Names: map[string]string{"zh-CN": "审核与生命周期", "zh-TW": "審核與生命週期", "ja-JP": "審査とライフサイクル", "en-US": "Review and lifecycle"}},
		{Code: "catalog.import.submit", Service: "catalog", Names: map[string]string{"zh-CN": "提交外部导入", "zh-TW": "提交外部匯入", "ja-JP": "外部取り込みの投入", "en-US": "Submit external imports"}},
		{Code: "catalog.shelves.manage", Service: "catalog", Names: map[string]string{"zh-CN": "管理货架", "zh-TW": "管理貨架", "ja-JP": "シェルフ管理", "en-US": "Manage shelves"}},
		{Code: "community.post.create", Service: "community", Names: map[string]string{"zh-CN": "发帖", "zh-TW": "發帖", "ja-JP": "投稿", "en-US": "Create posts"}},
		{Code: "community.post.moderate", Service: "community", Names: map[string]string{"zh-CN": "管理帖子", "zh-TW": "管理貼文", "ja-JP": "投稿の管理", "en-US": "Moderate posts"}},
		{Code: "community.topic.pin", Service: "community", Names: map[string]string{"zh-CN": "置顶主题", "zh-TW": "置頂主題", "ja-JP": "トピック固定", "en-US": "Pin topics"}},
		{Code: "community.board.manage", Service: "community", Names: map[string]string{"zh-CN": "管理板块", "zh-TW": "管理版塊", "ja-JP": "板の管理", "en-US": "Manage boards"}},
		{Code: "storage.asset.upload", Service: "storage", Names: map[string]string{"zh-CN": "上传资源", "zh-TW": "上傳資源", "ja-JP": "アップロード", "en-US": "Upload assets"}},
		{Code: "storage.asset.moderate", Service: "storage", Names: map[string]string{"zh-CN": "审核资源", "zh-TW": "審核資源", "ja-JP": "アセット審査", "en-US": "Moderate assets"}},
	}
}

var permissionRe = regexp.MustCompile(`^\*$|^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`)
var groupCodeRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

// ValidPermissionCode 校验权限码格式：* 或 服务.资源.动作（最多四段）。
func ValidPermissionCode(code string) bool { return permissionRe.MatchString(strings.TrimSpace(code)) }

// ValidGroupCode 校验组码格式：小写字母开头，含小写字母/数字/_/-。
func ValidGroupCode(code string) bool { return groupCodeRe.MatchString(strings.TrimSpace(code)) }

// ExpandPermissions 把多个组的权限码并成一个人的权限集合：去重、稳定排序语义（保持首次出现顺序），
// 含 * 时直接返回 [*]（通配即全权，避免下游还要判两次）。
func ExpandPermissions(groups []Group) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range groups {
		for _, p := range g.Permissions {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			if p == "*" {
				return []string{"*"}
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// WildcardPermission 是"全部权限"码（accounts 的 admin 组持有）。
const WildcardPermission = "*"

// HasPermission 判断权限集合是否命中某个码（* 视为全命中）。
func HasPermission(perms []string, code string) bool {
	for _, p := range perms {
		if p == "*" || p == code {
			return true
		}
	}
	return false
}

// Can 报告身份是否持有权限码，是账号服务里唯一的授权断言（HTTP 闸门与 store 复核共用）。
//
// 令牌带 permissions 时一律以码为准（含 * 通配），此时角色不再额外放行——否则
// "角色兜底"会变成绕过权限组的后门，或反过来让同一个管理动作在两个层次得到不同答案。
// 只有完全没有 permissions 声明时（老令牌，或尚未按权限组配置的实例）才按历史 role
// 兜底到 admin。与主仓库 catalog.User.Can 同口径（那边另有 editor 兜底实体编辑）。
func Can(u *User, code string) bool {
	if u == nil {
		return false
	}
	if len(u.Permissions) > 0 {
		return HasPermission(u.Permissions, code)
	}
	return u.Role == "admin"
}

// ── 实例设置 ──

const (
	SettingRegistrationEnabled  = "registration_enabled"
	SettingInviteRequired       = "invite_required"
	SettingRequireEmailVerify   = "require_email_verification"
	SettingAuthRateLimitEnabled = "auth_rate_limit_enabled"
	SettingRateLimitPerMinute   = "auth_rate_limit_per_minute"
	SettingRegistrationGroups   = "registration_default_groups"
)

// 退役键 site_name：站点名由前端构建期文案决定，账号服务里的这个设置没有任何消费方
// （详情见 README「实例设置」）。已从 DefaultSettings 与 UpdateSettings 的接受表移除，
// 写它会拿到 invalid_setting: site_name；存量行不再出现在任何读取面上（见 settingsWith）。

// DefaultRateLimitPerMinute 是限流默认速率，单位"次/分钟"。
//
// 它必须等于本设置真正生效前的强制值（15/分钟）：设置一旦接线，默认值就成了线上行为，
// 顺手改成别的数字等于在"接线"这一步悄悄改掉限流强度。
const DefaultRateLimitPerMinute = 15

// DefaultSettings 是实例设置默认值：**注册默认关闭**（受控站点），邀请码默认不强制，
// 新注册账号默认进 member 组（无任何特权）。
func DefaultSettings() map[string]any {
	return map[string]any{
		SettingRegistrationEnabled:  false,
		SettingInviteRequired:       false,
		SettingRequireEmailVerify:   false,
		SettingAuthRateLimitEnabled: true,
		SettingRateLimitPerMinute:   DefaultRateLimitPerMinute,
		SettingRegistrationGroups:   []string{"member"},
	}
}

// rateLimitCacheTTL 是限流策略的缓存时长。限流在每个请求上都要问一次策略，
// 每次都打库等于给认证写入端点加一次往返；写设置时立即失效（见 UpdateSettings），
// 因此 5 秒只是"多实例下最长滞后"，本实例改完立刻生效。
const rateLimitCacheTTL = 5 * time.Second

type cachedRateLimit struct {
	enabled   bool
	perMinute int
	expiresAt time.Time
}

// RateLimitPolicy 返回当前生效的限流策略（是否启用、每分钟上限），供 HTTP 中间件按请求读取。
//
// 读不到设置时按默认值返回（fail-closed）：宁可继续限流，也不要因为一次读库失败就放开。
// 非法速率（<=0）同样回落默认值，避免"设成 0"变成把所有人挡在门外。
func (s *Store) RateLimitPolicy(ctx context.Context) (bool, int) {
	now := time.Now()
	s.cacheMu.Lock()
	if c := s.rateLimit; c != nil && now.Before(c.expiresAt) {
		s.cacheMu.Unlock()
		return c.enabled, c.perMinute
	}
	s.cacheMu.Unlock()

	enabled, perMinute := true, DefaultRateLimitPerMinute
	if all, err := s.Settings(ctx); err == nil {
		if v, ok := all[SettingAuthRateLimitEnabled].(bool); ok {
			enabled = v
		}
		if n, ok := toInt(all[SettingRateLimitPerMinute]); ok && n > 0 {
			perMinute = n
		}
	}
	s.cacheMu.Lock()
	s.rateLimit = &cachedRateLimit{enabled: enabled, perMinute: perMinute, expiresAt: now.Add(rateLimitCacheTTL)}
	s.cacheMu.Unlock()
	return enabled, perMinute
}

// invalidateRateLimitCache 让下一次请求重新读设置：管理台保存后立即生效，不必等 TTL。
func (s *Store) invalidateRateLimitCache() {
	s.cacheMu.Lock()
	s.rateLimit = nil
	s.cacheMu.Unlock()
}

// Settings 读取实例设置（缺省项用默认值补齐）。
// 无数据库（桩实例/单元测试）时返回默认值：准入能力探测必须 fail-closed——
// "读不到配置"等价于"注册关闭"，绝不因为读不到而放行。
func (s *Store) Settings(ctx context.Context) (map[string]any, error) {
	if s.DB == nil {
		return DefaultSettings(), nil
	}
	return settingsWith(ctx, s.DB)
}

func settingsWith(ctx context.Context, q queryer) (map[string]any, error) {
	out := DefaultSettings()
	if q == nil {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, "SELECT key, value FROM auth.instance_settings")
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var raw []byte
		if err := rows.Scan(&k, &raw); err != nil {
			return out, err
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		// 只回传**当前接受表**里的键（DefaultSettings 的键集）：退役键的存量行留在库里，
		// 但不进任何读取面——回传一个谁也改不了、也没有消费方的键，只会让管理台看起来
		// 还有这个设置项。新增设置项必须同时加进 DefaultSettings，否则读写都不认它。
		if _, known := out[k]; !known {
			continue
		}
		out[k] = v
	}
	return out, rows.Err()
}

// PublicSettings 是未登录页面能看到的子集（准入能力，不含内部配置）。
func (s *Store) PublicSettings(ctx context.Context) (map[string]any, error) {
	all, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"registration_enabled":        all[SettingRegistrationEnabled],
		"invite_required":             all[SettingInviteRequired],
		"require_email_verification":  all[SettingRequireEmailVerify],
		"email_verification_enabled":  false, // 邮件通道未接入：字段保留，前端据此隐藏验证流程
		"rate_limit_enabled":          all[SettingAuthRateLimitEnabled],
		"auth_rate_limit_enabled":     all[SettingAuthRateLimitEnabled],
		"auth_rate_limit_per_minute":  all[SettingRateLimitPerMinute],
		"registration_default_groups": all[SettingRegistrationGroups],
	}, nil
}

// UpdateSettings 写入实例设置补丁。只接受已知键（避免前端写进垃圾键）；
// 值按类型归一（布尔/整数/字符串数组），未知键报 invalid_setting。
func (s *Store) UpdateSettings(ctx context.Context, patch map[string]any, actor *User) error {
	if !Can(actor, "auth.settings.manage") {
		return fmt.Errorf("forbidden")
	}
	norm := map[string]any{}
	for k, v := range patch {
		switch k {
		case SettingRegistrationEnabled, SettingInviteRequired, SettingRequireEmailVerify, SettingAuthRateLimitEnabled:
			b, ok := v.(bool)
			if !ok {
				return fmt.Errorf("invalid_setting: %s", k)
			}
			norm[k] = b
		case SettingRateLimitPerMinute:
			n, ok := toInt(v)
			if !ok || n < 1 || n > 100000 {
				return fmt.Errorf("invalid_setting: %s", k)
			}
			norm[k] = n
		case SettingRegistrationGroups:
			codes, ok := toStrSlice(v)
			if !ok {
				return fmt.Errorf("invalid_setting: %s", k)
			}
			for _, c := range codes {
				if !ValidGroupCode(c) {
					return fmt.Errorf("invalid_group_code: %s", c)
				}
			}
			norm[k] = codes
		default:
			return fmt.Errorf("invalid_setting: %s", k)
		}
	}
	if len(norm) == 0 {
		return nil
	}
	err := s.write(ctx, func(tx *sql.Tx) error {
		for k, v := range norm {
			raw, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO auth.instance_settings(key,value,updated_at) VALUES($1,$2,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()", k, string(raw)); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		// 限流策略按请求读取：这里立刻作废缓存，管理台改完不必等 TTL 才生效。
		s.invalidateRateLimitCache()
	}
	return err
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), n == float64(int(n))
	}
	return 0, false
}

func toStrSlice(v any) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// genCode 生成邀请码：8 字节随机、十六进制大写，形如 A1B2-C3D4-E5F6-7890。
func genCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	h := strings.ToUpper(hex.EncodeToString(b))
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16], nil
}

var _ = pq.Array // 保持依赖显式（组权限数组用 pq.Array 读写）
var _ = time.Now
