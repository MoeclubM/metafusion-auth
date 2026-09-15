package store

// 系统权限组种子：站点开箱即用的四类角色 —— 管理员、目录编辑/审核、论坛版主、普通成员。
//
// 这里刻意把"目录"和"论坛"的组分开：两个子系统的权限体系不同（元数据编辑 vs 社区治理），
// 但都来源于同一份账号数据，因此同一个人可以只做目录编辑、只做论坛版主，或两者兼任。
// 组本身可在管理台改名/改权限/增删（is_system 的组不可删，避免把默认组语义删掉）。

import (
	"context"
	"database/sql"
)

type seedGroup struct {
	code  string
	names map[string]string
	desc  map[string]string
	perms []string
	order int
}

func systemGroups() []seedGroup {
	return []seedGroup{
		{
			code:  "admin",
			names: map[string]string{"zh-CN": "管理员", "zh-TW": "管理員", "ja-JP": "管理者", "en-US": "Administrator"},
			desc:  map[string]string{"zh-CN": "拥有全部权限，含账号与权限组管理", "en-US": "Full permissions including accounts and groups"},
			perms: []string{"*"}, order: 0,
		},
		{
			code:  "catalog_admin",
			names: map[string]string{"zh-CN": "目录管理员", "zh-TW": "目錄管理員", "ja-JP": "カタログ管理者", "en-US": "Catalog administrator"},
			desc:  map[string]string{"zh-CN": "管理动态定义、审核与生命周期、货架与外部库", "en-US": "Manage definitions, review/lifecycle, shelves and external databases"},
			perms: []string{"catalog.entity.edit", "catalog.relation.edit", "catalog.definitions.manage", "catalog.lifecycle.manage", "catalog.import.submit", "catalog.shelves.manage"}, order: 10,
		},
		{
			code:  "catalog_editor",
			names: map[string]string{"zh-CN": "目录编辑", "zh-TW": "目錄編輯", "ja-JP": "カタログ編集者", "en-US": "Catalog editor"},
			desc:  map[string]string{"zh-CN": "创建与编辑实体、维护关系、提交外部导入", "en-US": "Create and edit entities, maintain relations, submit imports"},
			perms: []string{"catalog.entity.edit", "catalog.relation.edit", "catalog.import.submit"}, order: 20,
		},
		{
			code:  "community_admin",
			names: map[string]string{"zh-CN": "论坛管理员", "zh-TW": "論壇管理員", "ja-JP": "フォーラム管理者", "en-US": "Community administrator"},
			desc:  map[string]string{"zh-CN": "管理板块、置顶与帖子治理", "en-US": "Manage boards, pins and posts"},
			perms: []string{"community.post.create", "community.post.moderate", "community.topic.pin", "community.board.manage"}, order: 30,
		},
		{
			code:  "community_moderator",
			names: map[string]string{"zh-CN": "论坛版主", "zh-TW": "論壇版主", "ja-JP": "フォーラムモデレーター", "en-US": "Community moderator"},
			desc:  map[string]string{"zh-CN": "治理帖子与置顶，不改板块结构", "en-US": "Moderate posts and pins without changing board structure"},
			perms: []string{"community.post.create", "community.post.moderate", "community.topic.pin"}, order: 40,
		},
		{
			code:  "member",
			names: map[string]string{"zh-CN": "注册成员", "zh-TW": "註冊成員", "ja-JP": "登録メンバー", "en-US": "Member"},
			desc:  map[string]string{"zh-CN": "普通注册用户：可浏览、收藏、发帖，不具编辑权", "en-US": "Regular member: browse, favorite and post, no editing rights"},
			perms: []string{"community.post.create"}, order: 100,
		},
	}
}

// seedGroups 幂等播种系统组：已存在的组只补 is_system 标记与四语名（不动管理员改过的权限）。
func (s *Store) seedGroups(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		for _, g := range systemGroups() {
			names, err := jsonMarshal(g.names)
			if err != nil {
				return err
			}
			desc, err := jsonMarshal(g.desc)
			if err != nil {
				return err
			}
			perms := g.perms
			if perms == nil {
				perms = []string{}
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO auth.groups(id,code,names,descriptions,permissions,is_system,sort_order) VALUES($1,$2,$3,$4,$5,true,$6) ON CONFLICT (code) DO UPDATE SET is_system=true", newUUID(), g.code, names, desc, pqArray(perms), g.order); err != nil {
				return err
			}
		}
		return nil
	})
}
