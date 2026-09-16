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

	"github.com/lib/pq"
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
			// storage.asset.upload 是「创建并登记自己的资产」：收口前后成员都能上传，
			// 这里显式声明它，才能让存量实例通过下面的权限回填补齐（收紧要另改本种子或改用自定义组）。
			perms: []string{"community.post.create", "storage.asset.upload"}, order: 100,
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

// backfillPermissions 把种子声明、而库里缺失的权限码补进现有组（只加不减）：
//
//   - 库里已有的码全部保留，含管理员手工加过的：本函数不删任何码；
//   - 种子里有、库里没有的码追加到末尾，顺序稳定（先库里原序，再按种子顺序）；
//   - 库里带 `*` 通配时不再补具体码：通配已覆盖全部权限，补了只是噪音。
//
// 返回合并结果与本次补入的码；没有补入时 added 为空，调用方据此跳过 UPDATE（幂等判据）。
//
// 为什么需要它：新增权限码（例如 storage.asset.upload 开始被存储服务的写接口强制）时，
// 存量实例的组里不会有这个码，服务侧一收口就会把原本能用的成员挡在外面；
// 这里随启动把种子声明的码补齐，让升级前后行为一致，再谈收紧。
//
// 已知取舍（与定义种子的"只增不改"同一取舍）：种子声明过的码被管理员移除后，下次启动会被补回。
// 要长期收紧某个种子码，改的是种子本身（或把用户改挂到不声明该码的自定义组），
// 而不是靠后台移除——否则每次重启都会反复。
func backfillPermissions(seed, cur []string) ([]string, []string) {
	out := make([]string, 0, len(cur)+len(seed))
	seen := make(map[string]bool, len(cur)+len(seed))
	for _, code := range cur {
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	if seen[WildcardPermission] {
		return out, nil
	}
	var added []string
	for _, code := range seed {
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
		added = append(added, code)
	}
	return out, added
}

// seedGroups 幂等播种系统组，读后写都在同一事务里（write 已取账号服务的 advisory 锁，
// 并发启动不会两边同时判定"库里没有"）：
//
//   - 库里没有该组 → 整条插入（名称/描述/权限/排序都来自种子）；
//   - 已存在 → 只补 is_system 标记、缺失/仍是英文占位的语种名（names 与 descriptions 都补），
//     以及种子声明而库里缺失的权限码（只加不减，见 backfillPermissions）；
//     管理员手工加过的码、排序与已有译文一律不动；
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
	var curPerms []string
	var isSystem bool
	err := tx.QueryRowContext(ctx, "SELECT names,descriptions,permissions,is_system FROM auth.groups WHERE code=$1", g.code).
		Scan(&rawNames, &rawDescs, pq.Array(&curPerms), &isSystem)
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
	perms, addedPerms := backfillPermissions(g.perms, curPerms)

	// 只写真正变化的列：旧行缺 is_system 时补标记，语种有补丁时才写该列的整张表
	// （补丁是"当前表 + 种子译文"，所以不会动其它语种）。
	set := make([]string, 0, 4)
	args := make([]any, 0, 4)
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
	if len(addedPerms) > 0 {
		args = append(args, pq.Array(perms))
		set = append(set, fmt.Sprintf("permissions=$%d", len(args)))
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, g.code)
	_, err = tx.ExecContext(ctx, "UPDATE auth.groups SET "+strings.Join(set, ", ")+" WHERE code=$"+strconv.Itoa(len(args)), args...)
	return err
}
