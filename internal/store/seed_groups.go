package store

// 系统权限组种子：站点开箱即用的四类角色 —— 管理员、目录编辑/审核、论坛版主、普通成员。
//
// 这里刻意把"目录"和"论坛"的组分开：两个子系统的权限体系不同（元数据编辑 vs 社区治理），
// 但都来源于同一份账号数据，因此同一个人可以只做目录编辑、只做论坛版主，或两者兼任。
// 组本身可在管理台改名/改权限/增删（is_system 的组不可删，避免把默认组语义删掉）。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
			desc:  map[string]string{"zh-CN": "拥有全部权限，含账号与权限组管理", "zh-TW": "擁有全部權限，含帳號與權限組管理", "ja-JP": "すべての権限を保有し、アカウントと権限グループの管理を含む", "en-US": "Full permissions including accounts and groups"},
			perms: []string{"*"}, order: 0,
		},
		{
			code:  "catalog_admin",
			names: map[string]string{"zh-CN": "目录管理员", "zh-TW": "目錄管理員", "ja-JP": "カタログ管理者", "en-US": "Catalog administrator"},
			desc:  map[string]string{"zh-CN": "管理动态定义、审核与生命周期、货架与外部库", "zh-TW": "管理動態定義、審核與生命週期、貨架與外部庫", "ja-JP": "動的定義、審査とライフサイクル、シェルフ、外部データベースの管理", "en-US": "Manage definitions, review/lifecycle, shelves and external databases"},
			perms: []string{"catalog.entity.edit", "catalog.relation.edit", "catalog.definitions.manage", "catalog.lifecycle.manage", "catalog.import.submit", "catalog.shelves.manage"}, order: 10,
		},
		{
			code:  "catalog_editor",
			names: map[string]string{"zh-CN": "目录编辑", "zh-TW": "目錄編輯", "ja-JP": "カタログ編集者", "en-US": "Catalog editor"},
			desc:  map[string]string{"zh-CN": "创建与编辑实体、维护关系、提交外部导入", "zh-TW": "建立與編輯實體、維護關係、提交外部匯入", "ja-JP": "実体の作成と編集、関係の管理、外部取り込みの投入", "en-US": "Create and edit entities, maintain relations, submit imports"},
			perms: []string{"catalog.entity.edit", "catalog.relation.edit", "catalog.import.submit"}, order: 20,
		},
		{
			code:  "community_admin",
			names: map[string]string{"zh-CN": "论坛管理员", "zh-TW": "論壇管理員", "ja-JP": "フォーラム管理者", "en-US": "Community administrator"},
			desc:  map[string]string{"zh-CN": "管理板块、置顶与帖子治理", "zh-TW": "管理版塊、置頂與貼文治理", "ja-JP": "板の管理、ピン留めと投稿の管理", "en-US": "Manage boards, pins and posts"},
			perms: []string{"community.post.create", "community.post.moderate", "community.topic.pin", "community.board.manage"}, order: 30,
		},
		{
			code:  "community_moderator",
			names: map[string]string{"zh-CN": "论坛版主", "zh-TW": "論壇版主", "ja-JP": "フォーラムモデレーター", "en-US": "Community moderator"},
			desc:  map[string]string{"zh-CN": "治理帖子与置顶，不改板块结构", "zh-TW": "治理貼文與置頂，不變更版塊結構", "ja-JP": "投稿とピン留めの管理のみ。板の構成は変更しない", "en-US": "Moderate posts and pins without changing board structure"},
			perms: []string{"community.post.create", "community.post.moderate", "community.topic.pin"}, order: 40,
		},
		{
			code:  "member",
			names: map[string]string{"zh-CN": "注册成员", "zh-TW": "註冊成員", "ja-JP": "登録メンバー", "en-US": "Member"},
			desc:  map[string]string{"zh-CN": "普通注册用户：可浏览、收藏、发帖，不具编辑权", "zh-TW": "一般註冊使用者：可瀏覽、收藏、發帖，不具編輯權", "ja-JP": "一般登録ユーザー：閲覧・お気に入り・投稿が可能。編集権限はなし", "en-US": "Regular member: browse, favorite and post, no editing rights"},
			perms: []string{"community.post.create"}, order: 100,
		},
	}
}

// nameLocaleOrder 是名称表的规范语种键顺序：与权限码清单（access.go PermissionCatalog）
// 及主仓库四语字典同一口径。写库顺序稳定，测试也据此断言。
var nameLocaleOrder = []string{"zh-CN", "zh-TW", "ja-JP", "en-US"}

// defaultGroupNames 是后台新建组未给名称时的占位名：值是语言中立的组码，
// 四语给同一个串不改变任何用户看到的文字（缺键时那几种语种本来也会回退到同一个串），
// 只是让名称表结构与其它定义一致，后台编辑器也能直接看到四种语言待填。
func defaultGroupNames(code string) map[string]string {
	out := make(map[string]string, len(nameLocaleOrder))
	for _, loc := range nameLocaleOrder {
		out[loc] = code
	}
	return out
}

// backfillNameLocales 把种子里有、当前缺失或当前仍等于英文的语种键补进现有名称表（只增不改）：
//
//   - 当前没有该语种键，或值是空串 / 纯空白 → 用种子译文补上；
//   - 当前值仍是英文占位（等于本行的 en-US；本行没有 en-US 时才用种子的 en-US）→ 换成种子译文；
//   - 已有的人工译文一律不动（含后台把 zh-CN 改成别的写法、或行内有种子没有的语种键的情况）。
//
// 返回补好的名称表与被补的语种键（按 nameLocaleOrder 顺序）。没有可补的键时 added 为空，
// 调用方据此跳过 UPDATE —— 这就是"无新增时不发无谓 UPDATE"的判据。
func backfillNameLocales(seed, cur map[string]string) (map[string]string, []string) {
	out := make(map[string]string, len(cur)+len(seed))
	for k, v := range cur {
		out[k] = v
	}
	if len(seed) == 0 {
		return out, nil
	}
	en := strings.TrimSpace(cur["en-US"])
	if en == "" {
		en = strings.TrimSpace(seed["en-US"])
	}
	var added []string
	for _, loc := range nameLocaleOrder {
		val := strings.TrimSpace(seed[loc])
		if val == "" {
			continue // 种子里这一语种本来就没给译文，没有可补的信息
		}
		existing := strings.TrimSpace(out[loc])
		if existing == val {
			continue // 已经是同一条译文（上一次回填补过），不算补丁
		}
		if existing != "" {
			// en-US 是"英文占位"判定的基准本身，不能拿它当占位：后台把英文名改成别的写法时
			// 必须原样保留（否则每次启动都会被种子改回去）。其它语种：值仍等于英文说明
			// 它还是占位，可以补成种子译文。
			if loc == "en-US" || !(en != "" && existing == en) {
				continue // 已有的人工译文：不覆盖
			}
		}
		out[loc] = val
		added = append(added, loc)
	}
	return out, added
}

// seedGroups 幂等播种系统组，读后写都在同一事务里（write 已取账号服务的 advisory 锁，
// 并发启动不会两边同时判定"库里没有"）：
//
//   - 库里没有该组 → 整条插入（名称/描述/权限/排序都来自种子）；
//   - 已存在 → 只补 is_system 标记与缺失/仍是英文占位的语种名（names 与 descriptions 都补），
//     管理员改过的权限、排序与已有译文一律不动；
//   - 没有任何要补的东西时不发 UPDATE。
//
// 只有 systemGroups() 里的系统组走这条路径，后台自建的组不会被回填。
func (s *Store) seedGroups(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		for _, g := range systemGroups() {
			if err := seedSystemGroup(ctx, tx, g); err != nil {
				return err
			}
		}
		return nil
	})
}

func seedSystemGroup(ctx context.Context, tx *sql.Tx, g seedGroup) error {
	var rawNames, rawDescs []byte
	var isSystem bool
	err := tx.QueryRowContext(ctx, "SELECT names,descriptions,is_system FROM auth.groups WHERE code=$1", g.code).
		Scan(&rawNames, &rawDescs, &isSystem)
	if errors.Is(err, sql.ErrNoRows) {
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
		_, err = tx.ExecContext(ctx, "INSERT INTO auth.groups(id,code,names,descriptions,permissions,is_system,sort_order) VALUES($1,$2,$3,$4,$5,true,$6)", newUUID(), g.code, names, desc, pqArray(perms), g.order)
		return err
	}
	if err != nil {
		return err
	}

	names, addedNames := backfillNameLocales(g.names, decodeNames(rawNames))
	descs, addedDescs := backfillNameLocales(g.desc, decodeNames(rawDescs))

	// 只写真正变化的列：旧行缺 is_system 时补标记，语种有补丁时才写该列的整张表
	// （补丁是"当前表 + 种子译文"，所以不会动其它语种）。
	set := make([]string, 0, 3)
	args := make([]any, 0, 3)
	if !isSystem {
		set = append(set, "is_system=true")
	}
	if len(addedNames) > 0 {
		raw, err := jsonMarshal(names)
		if err != nil {
			return err
		}
		args = append(args, raw)
		set = append(set, fmt.Sprintf("names=$%d", len(args)))
	}
	if len(addedDescs) > 0 {
		raw, err := jsonMarshal(descs)
		if err != nil {
			return err
		}
		args = append(args, raw)
		set = append(set, fmt.Sprintf("descriptions=$%d", len(args)))
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, g.code)
	_, err = tx.ExecContext(ctx, "UPDATE auth.groups SET "+strings.Join(set, ", ")+" WHERE code=$"+strconv.Itoa(len(args)), args...)
	return err
}
