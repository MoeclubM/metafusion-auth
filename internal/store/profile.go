package store

// 公开账号资料（GET /api/users/:id）：字段只来自 auth.users 里**真实存在的列**
// （id / username / display_name / bio / banned / email），不填没有来源的占位值——
// 空字符串或 false 会被读成"这个人就是没头像 / 就是没开收藏"，而事实是"没有这个来源"。
//
// 与 User（登录态投影）的分工：这里不下发 password_hash、组与权限；email 是隐私字段，
// 只有请求者就是本人时才带出（判定在 PublicProfile 里，HTTP 层绕不过去）。

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// PublicUser 是公开资料里的账号投影。
type PublicUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	// 昵称与简介是公开资料的一部分（空串=未设置，前端回退用户名/占位）。
	DisplayName string `json:"display_name,omitempty"`
	Bio         string `json:"bio,omitempty"`
	// Banned 沿用 User.Banned 的 omitempty 口径：只在为真时下发。
	//
	// 被 ban 的账号照样返回资料，只带上"已停用"这个事实：封禁是访问控制（不能登录/续期/验签），
	// 不是"这个人不存在"；他的历史贡献与别人会话里的引用都还指向这个 id，回 404 会让
	// 其它服务里的链接整片失效。前端据此降级展示即可。
	Banned bool `json:"banned,omitempty"`
	// Email 只在请求者就是本人时下发。
	Email string `json:"email,omitempty"`
}

// PublicProfileStats 只放本服务真正拥有的统计：作品/收藏/帖子/评论数分别在目录与互动服务里，
// 账号服务不读它们的库（跨 schema 读会让拆分白做），给 0 等于陈述"这个人什么都没写"。
type PublicProfileStats struct {
	// InvitedCount 口径见 invitedCountQuery。
	InvitedCount int `json:"invited_count"`
}

// PublicProfile 是公开资料的响应体。
type PublicProfile struct {
	User  PublicUser         `json:"user"`
	Stats PublicProfileStats `json:"stats"`
}

// invitedCountQuery 统计"该用户邀请成功的人数"，与 InvitedMembers 同一口径：
// auth.invite_uses 记录谁用哪个码注册进来，码归 auth.invites.created_by 所有。
//
//   - 只算真被用掉、且因此注册成功的次数（行由注册事务的 consumeInvite 写下），发出去没用的码不计；
//   - 同一个人被同一邀请人的多个码拉进来只算一次（count DISTINCT user_id）；
//   - 码之后被吊销或过期不回溯扣减：人已经进来了，与 InvitedMembers 的展示保持一致；
//   - 被封禁的受邀者同样计入：封禁是账号状态，不抹掉"他确实是被谁邀请进来的"这个事实。
const invitedCountQuery = "SELECT count(DISTINCT iu.user_id)" +
	" FROM auth.invites i JOIN auth.invite_uses iu ON iu.invite_code=i.code" +
	" WHERE i.created_by=$1"

// PublicProfile 读取公开资料。viewerID 是请求者身份（匿名传空串）：email 只有
// viewerID == id 时才带出，其余情况（匿名、看别人）该字段缺省。
//
// 非 uuid 与查不到都返回 sql.ErrNoRows（HTTP 层统一映射 404）：把非法参数原样丢给
// postgres 会得到 22P02 报错，那会以 500 暴露"参数直接进了 SQL"，而且同一个"没有这个账号"
// 会因写法不同拿到不同状态码。
// 资料长度上限（按 rune 计）：昵称 32 字、简介 500 字。超限 400，前后端同一口径
// （前端 settings 页的 hint 写同一数字，改一处必须改另一处）。
const (
	MaxDisplayNameRunes = 32
	MaxBioRunes         = 500
)

// UpdateProfile 自助改昵称与简介：只认本人 userID。空串=未设置（回退用户名/占位）。
func (s *Store) UpdateProfile(ctx context.Context, userID, displayName, bio string) (PublicUser, error) {
	var out PublicUser
	displayName = strings.TrimSpace(displayName)
	bio = strings.TrimSpace(bio)
	if utf8.RuneCountInString(displayName) > MaxDisplayNameRunes {
		return out, fmt.Errorf("invalid_display_name")
	}
	if utf8.RuneCountInString(bio) > MaxBioRunes {
		return out, fmt.Errorf("invalid_bio")
	}
	err := s.DB.QueryRowContext(ctx,
		"UPDATE auth.users SET display_name=$2,bio=$3 WHERE id=$1 RETURNING id,username,display_name,bio",
		userID, displayName, bio).Scan(&out.ID, &out.Username, &out.DisplayName, &out.Bio)
	if err != nil {
		return out, err // 含 sql.ErrNoRows → 404（账号在令牌有效期内被删）
	}
	return out, nil
}

// FillProfile 给 /auth/me 补读穿：JWT 投影里的昵称/简介至多陈旧一个令牌周期，
// /auth/me 按 id 回表取最新列，其余字段沿用令牌投影（权限与角色走验签路径，不碰）。
func (s *Store) FillProfile(ctx context.Context, u *User) error {
	if u == nil {
		return sql.ErrNoRows
	}
	return s.DB.QueryRowContext(ctx,
		"SELECT COALESCE(display_name,''),COALESCE(bio,'') FROM auth.users WHERE id=$1", u.ID).
		Scan(&u.DisplayName, &u.Bio)
}

func (s *Store) PublicProfile(ctx context.Context, id, viewerID string) (PublicProfile, error) {
	var out PublicProfile
	if s.DB == nil {
		// 无库桩实例（httptest 用例）按"查不到"回答：公开读没有可放行的信息，
		// 与 IsBanned"读不到库不放大权限"同口径。生产的 s.DB 恒非空。
		return out, sql.ErrNoRows
	}
	uid, err := uuid.Parse(strings.TrimSpace(id))
	if err != nil {
		return out, sql.ErrNoRows
	}
	// 规范化后再查：{uuid} / urn:uuid: / 无连字符形式都能解析成同一个 id，
	// 交给 postgres 的字面量也永远是规范写法。
	id = uid.String()
	var banned bool
	err = s.DB.QueryRowContext(ctx,
		"SELECT id,username,COALESCE(email,''),banned,COALESCE(display_name,''),COALESCE(bio,'') FROM auth.users WHERE id=$1", id).
		Scan(&out.User.ID, &out.User.Username, &out.User.Email, &banned, &out.User.DisplayName, &out.User.Bio)
	if err != nil {
		return out, err // 含 sql.ErrNoRows → 404
	}
	out.User.Banned = banned
	// viewerID 同样按 uuid 规范化后再比：同一个 id 的大小写/短写形式不能比成"不是本人"
	// （比对写反方向的错更危险——下次改动就可能把别人的邮箱发出去）。
	if v, verr := uuid.Parse(strings.TrimSpace(viewerID)); verr != nil || v.String() != id {
		out.User.Email = ""
	}
	if err := s.DB.QueryRowContext(ctx, invitedCountQuery, id).Scan(&out.Stats.InvitedCount); err != nil {
		return out, err
	}
	return out, nil
}
