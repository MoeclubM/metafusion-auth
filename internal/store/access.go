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

// HasPermission 判断权限集合是否命中某个码（* 视为全命中）。
func HasPermission(perms []string, code string) bool {
	for _, p := range perms {
		if p == "*" || p == code {
			return true
		}
	}
	return false
}

// ── 实例设置 ──

const (
	SettingRegistrationEnabled  = "registration_enabled"
	SettingInviteRequired       = "invite_required"
	SettingRequireEmailVerify   = "require_email_verification"
	SettingAuthRateLimitEnabled = "auth_rate_limit_enabled"
	SettingRateLimitPerMinute   = "auth_rate_limit_per_minute"
	SettingRegistrationGroups   = "registration_default_groups"
	SettingSiteName             = "site_name"
)

// DefaultSettings 是实例设置默认值：**注册默认关闭**（受控站点），邀请码默认不强制，
// 新注册账号默认进 member 组（无任何特权）。
func DefaultSettings() map[string]any {
	return map[string]any{
		SettingRegistrationEnabled:  false,
		SettingInviteRequired:       false,
		SettingRequireEmailVerify:   false,
		SettingAuthRateLimitEnabled: true,
		SettingRateLimitPerMinute:   30,
		SettingRegistrationGroups:   []string{"member"},
		SettingSiteName:             "MetaFusion",
	}
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
	if actor == nil || !HasPermission(actor.Permissions, "auth.settings.manage") {
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
		case SettingSiteName:
			sv, ok := v.(string)
			if !ok || strings.TrimSpace(sv) == "" || len([]rune(sv)) > 64 {
				return fmt.Errorf("invalid_setting: %s", k)
			}
			norm[k] = strings.TrimSpace(sv)
		default:
			return fmt.Errorf("invalid_setting: %s", k)
		}
	}
	if len(norm) == 0 {
		return nil
	}
	return s.write(ctx, func(tx *sql.Tx) error {
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
