package store

import (
	"regexp"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/audit"
)

// frozenAuditTableDefs 冻结跨服务共用的审计表列形状（audit.audit_log）。
//
// 这张表不属于 auth schema，但它的列形状同样值得冻结：四个服务都往里写、账号服务的读取面
// 与主仓库契约文档 docs/architecture/audit-log.md 都按这些列名取值，改错不会编译失败，
// 只会在运行时以"读取面查不到列"或"另一个服务写不进来"的形式暴露。
// 复用同包的 DDL 归一化工具（splitTopLevel / normalizeDef）；建表语句现在包在
// `DO $audit_ddl$ ... IF to_regclass(...) IS NULL THEN ... END IF` 守卫里，
// 因此不能用 parseSchema（它只认顶层 CREATE TABLE IF NOT EXISTS）。
var frozenAuditTableDefs = map[string]map[string]string{
	"audit.audit_log": {
		"id":               "id uuid primary key",
		"occurred_at":      "occurred_at timestamptz not null default now()",
		"service":          "service text not null",
		"action":           "action text not null",
		"actor_user_id":    "actor_user_id uuid",
		"actor_username":   "actor_username text not null default ''",
		"credential_type":  "credential_type text not null default ''",
		"actor_ip":         "actor_ip text not null default ''",
		"actor_user_agent": "actor_user_agent text not null default ''",
		"target_type":      "target_type text not null default ''",
		"target_id":        "target_id text not null default ''",
		"changes":          "changes jsonb not null default '{}'::jsonb",
		"result":           "result text not null default 'success' check (result in ('success','failure'))",
		"error_code":       "error_code text not null default ''",
		"request_method":   "request_method text not null default ''",
		"route":            "route text not null default ''",
		"http_status":      "http_status int not null default 0",
		"request_id":       "request_id text not null default ''",
	},
}

func TestAuditLogSchemaIsFrozen(t *testing.T) {
	got := parseGuardedAuditTable(t, audit.Schema)
	want := frozenAuditTableDefs["audit.audit_log"]
	for col, wantDef := range want {
		gotDef, ok := got[col]
		if !ok {
			t.Fatalf("audit.audit_log 缺少列 %s（期望 %s）", col, wantDef)
		}
		if gotDef != wantDef {
			t.Fatalf("audit.audit_log.%s 定义漂移：\n  期望 %s\n  实际 %s", col, wantDef, gotDef)
		}
	}
	for col := range got {
		if _, ok := want[col]; !ok {
			t.Fatalf("audit.audit_log 多出列 %s（未在冻结清单里登记）", col)
		}
	}
}

// parseGuardedAuditTable 从守卫式 DDL 里取出 audit.audit_log 的列集合。
func parseGuardedAuditTable(t *testing.T, ddl string) map[string]string {
	t.Helper()
	m := auditCreateTableRe.FindStringSubmatch(stripLineComments(ddl))
	if m == nil {
		t.Fatalf("审计 DDL 里找不到 CREATE TABLE audit.audit_log (...)：%s", ddl)
	}
	cols := map[string]string{}
	for _, entry := range splitTopLevel(m[1], ",") {
		def := normalizeDef(entry)
		if def == "" {
			continue
		}
		name := strings.Fields(def)[0]
		switch name {
		case "primary", "unique", "foreign", "check", "constraint":
			continue
		}
		if !identRe.MatchString(name) {
			continue
		}
		cols[name] = def
	}
	return cols
}

var auditCreateTableRe = regexp.MustCompile(`(?is)CREATE TABLE audit\.audit_log\s*\((.*?)
\s*\);`)

// 回归守卫：建表段必须整段包在 to_regclass 判断里，且**不能**再用 CREATE INDEX IF NOT EXISTS。
//
// 理由（真库实测）：PostgreSQL 的 CREATE INDEX IF NOT EXISTS 先做表所有权检查再看索引是否存在，
// 而表由部署时的 mf_audit_owner 预建 —— 非 owner 的运行角色在启动时会拿到
// 42501 must be owner of table audit_log，四个服务全部起不来。有人把守卫拆掉或把索引写成
// IF NOT EXISTS（哪怕放回守卫外面）这条用例就会红。
func TestAuditSchemaUsesExistenceGuard(t *testing.T) {
	if !strings.Contains(audit.Schema, "IF to_regclass('audit.audit_log') IS NULL THEN") {
		t.Fatal("建表段必须用 to_regclass 守卫：非 owner 角色执行 CREATE INDEX 会 42501（见注释）")
	}
	if strings.Contains(audit.Schema, "CREATE INDEX IF NOT EXISTS") {
		t.Fatal("索引不能写成 CREATE INDEX IF NOT EXISTS：它会先查表所有权，非 owner 角色启动即失败")
	}
	if !strings.Contains(audit.Schema, "PERFORM pg_advisory_xact_lock(740205)") {
		t.Fatal("跨服务建表锁必须在守卫内部先取，才能串行化四个服务的建表")
	}
}

// 读取面的过滤与排序依赖这四条索引：没有它们，管理台一翻页就是全表扫。
func TestAuditLogSchemaKeepsQueryIndexes(t *testing.T) {
	for _, index := range []string{
		"audit_log_occurred_at_idx",
		"audit_log_service_action_idx",
		"audit_log_actor_idx",
		"audit_log_target_idx",
	} {
		if !strings.Contains(audit.Schema, index) {
			t.Fatalf("审计 DDL 缺少索引 %s（读取面的过滤/排序依赖它）", index)
		}
	}
}

// 建表必须与另外三个服务用同一把 advisory 锁：四个服务可能同时首次启动，
// 两条 CREATE TABLE 撞在 pg_type 唯一索引上会让其中一个服务起不来。
func TestAuditSchemaTakesSharedCreationLock(t *testing.T) {
	if !strings.Contains(audit.Schema, "pg_advisory_xact_lock(740205)") {
		t.Fatal("审计 DDL 必须取 740205 这把跨服务建表锁（四个服务共用）")
	}
}
