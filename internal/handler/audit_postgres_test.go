package handler

// 审计留痕的端到端用例（真库）：每个账号管理动作各留一行、敏感值零泄漏、失败路径也留痕，
// 以及读取面的过滤/分页/非法参数。未设置 AUTH_TEST_DSN 时整包跳过（见 testutil）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-auth/internal/audit"
	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// auditTestIP 是请求的来源地址：断言审计行里的 actor_ip 取自真实连接，而不是空串。
const auditTestIP = "203.0.113.7:41234"

// auditRequestIDPrefix 是本次用例所有请求的 request_id 前缀，也是断言时的筛选条件
// （测试库是共享的，别的用例/别的轮次的行不能被算进来）。
const auditRequestIDPrefix = "mf-audit-test-"

// auditRequest 发一个带 X-Request-Id 的请求：请求 id 是"这一次写操作"的关联键，
// 审计行的定位与断言都靠它。
func auditRequest(t *testing.T, r *gin.Engine, method, path, bearer, body, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	req.RemoteAddr = auditTestIP
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// auditRow 是一行审计的断言用投影。
type auditRow struct {
	Action         string
	Result         string
	ErrorCode      string
	ActorUserID    string
	ActorUsername  string
	CredentialType string
	ActorIP        string
	ActorUserAgent string
	TargetType     string
	TargetID       string
	Changes        string
	RequestMethod  string
	Route          string
	HTTPStatus     int
	RequestID      string
}

// fetchAuditRows 按 request_id 取审计行：一个请求应当**恰好**留一行。
func fetchAuditRows(t *testing.T, st *store.Store, requestID string) []auditRow {
	t.Helper()
	rows, err := st.DB.Query("SELECT action, result, error_code, COALESCE(actor_user_id::text,''), actor_username, credential_type, actor_ip, actor_user_agent, target_type, target_id, changes::text, request_method, route, http_status, request_id FROM audit.audit_log WHERE request_id=$1 ORDER BY occurred_at", requestID)
	if err != nil {
		t.Fatalf("查审计行: %v", err)
	}
	defer rows.Close()
	out := []auditRow{}
	for rows.Next() {
		var item auditRow
		if err = rows.Scan(&item.Action, &item.Result, &item.ErrorCode, &item.ActorUserID, &item.ActorUsername,
			&item.CredentialType, &item.ActorIP, &item.ActorUserAgent, &item.TargetType, &item.TargetID,
			&item.Changes, &item.RequestMethod, &item.Route, &item.HTTPStatus, &item.RequestID); err != nil {
			t.Fatalf("扫审计行: %v", err)
		}
		out = append(out, item)
	}
	return out
}

// newAuditTestServer 打开真库、建表、挂上带审计写入器的处理器。
func newAuditTestServer(t *testing.T) (*gin.Engine, *store.Store, *audit.Recorder) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err = st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	st.Tokens = newTestIssuer(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(st)
	// 换成"用例能排空队列"的写入器：生产那份是无界后台写，断言前需要 Flush。
	h.audit = audit.NewRecorder(st.DB, audit.ServiceName)
	t.Cleanup(h.audit.Close)
	h.Register(r)
	return r, st, h.audit
}

// 每个账号管理写操作各留一行，且行里的"谁/对谁/结果/来源"都对得上。
func TestAuditLogCoversAccountMutationsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	r, st, recorder := newAuditTestServer(t)

	_, _, adminBearer := insertChainUser(t, ctx, st, "admin")
	targetID, targetName, _ := insertChainUser(t, ctx, st, "user")
	memberID, memberName, memberBearer := insertChainUser(t, ctx, st, "user")
	// 自助邀请码端点要求 auth.invites.manage：给这个成员签一张带该码的令牌（
	// requireUser 只要求登录，权限判定在 store 里按码走）。
	inviteBearer := signBearer(t, st, store.User{ID: memberID, Username: memberName, Permissions: []string{"auth.invites.manage"}})
	// PAT 的 scope 必须是"账号现时权限 ∩ 请求"：这张令牌带上成员真正持有的码。
	patBearer := signBearer(t, st, store.User{ID: memberID, Username: memberName, Permissions: []string{"community.post.create"}})

	const resetPassword = "Rotated-Passw0rd!"
	const selfPassword = "Self-Changed-Passw0rd!"
	createdName := "audit-created-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	createdEmail := createdName + "@example.test"
	groupCode := "audit_probe_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:6]

	steps := []struct {
		name       string
		method     string
		path       string
		bearer     string
		body       string
		wantStatus int
		wantAction string
	}{
		{"改权限组", http.MethodPut, "/api/admin/users/" + targetID + "/groups", adminBearer, "{\"groups\":[\"member\",\"catalog_editor\"]}", 200, "user.groups_changed"},
		{"重置口令", http.MethodPut, "/api/admin/users/" + targetID + "/password", adminBearer, "{\"password\":\"" + resetPassword + "\"}", 200, "user.password_reset"},
		{"封禁", http.MethodPut, "/api/admin/users/" + targetID + "/ban", adminBearer, "{\"banned\":true}", 200, "user.banned"},
		{"解封", http.MethodPut, "/api/admin/users/" + targetID + "/ban", adminBearer, "{\"banned\":false}", 200, "user.unbanned"},
		{"改设置", http.MethodPut, "/api/admin/settings", adminBearer, "{\"registration_enabled\":true}", 200, "settings.updated"},
		{"建账号", http.MethodPost, "/api/admin/users", adminBearer, "{\"username\":\"" + createdName + "\",\"email\":\"" + createdEmail + "\",\"password\":\"Created-Passw0rd!\"}", 200, "user.created"},
		{"建权限组", http.MethodPost, "/api/admin/groups", adminBearer, "{\"code\":\"" + groupCode + "\",\"names\":{\"en-US\":\"Audit probe\"},\"permissions\":[\"auth.audit.read\"]}", 200, "group.created"},
		{"删权限组", http.MethodDelete, "/api/admin/groups/" + groupCode, adminBearer, "", 200, "group.deleted"},
		{"自助建邀请码", http.MethodPost, "/api/auth/invite", inviteBearer, "{\"note\":\"audit probe\",\"max_uses\":1}", 200, "invite.self_created"},
		{"管理员建邀请码", http.MethodPost, "/api/admin/invites", adminBearer, "{\"note\":\"audit probe\",\"max_uses\":1}", 200, "invite.created"},
		{"自助改口令", http.MethodPut, "/api/auth/password", memberBearer, "{\"old_password\":\"" + chainTestPassword + "\",\"new_password\":\"" + selfPassword + "\"}", 200, "user.password_changed"},
		{"吊销全部会话", http.MethodPost, "/api/auth/logout-all", memberBearer, "", 200, "user.sessions_revoked"},
	}

	requestIDs := map[string]string{}
	var plainInviteCodes []string
	for _, step := range steps {
		requestID := auditRequestIDPrefix + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
		requestIDs[step.name] = requestID
		w := auditRequest(t, r, step.method, step.path, step.bearer, step.body, requestID)
		if w.Code != step.wantStatus {
			t.Fatalf("%s 应 %d，实际 %d / %s", step.name, step.wantStatus, w.Code, w.Body.String())
		}
		if got := w.Header().Get("X-Request-Id"); got != requestID {
			t.Fatalf("%s 响应应回写 X-Request-Id=%s，实际 %q", step.name, requestID, got)
		}
		if step.wantAction == "invite.self_created" || step.wantAction == "invite.created" {
			var body struct {
				Code string `json:"code"`
			}
			decodeInto(t, w, &body)
			if body.Code == "" {
				t.Fatalf("%s 响应里应有邀请码", step.name)
			}
			plainInviteCodes = append(plainInviteCodes, body.Code)
		}
	}
	if err := recorder.Flush(ctx); err != nil {
		t.Fatalf("排空审计队列: %v", err)
	}
	if dropped := recorder.Dropped(); dropped != 0 {
		t.Fatalf("真库用例不该丢审计行，实际丢 %d 行", dropped)
	}

	for _, step := range steps {
		rows := fetchAuditRows(t, st, requestIDs[step.name])
		if len(rows) != 1 {
			t.Fatalf("%s 应恰好留 1 行审计，实际 %d 行", step.name, len(rows))
		}
		row := rows[0]
		if row.Action != step.wantAction {
			t.Fatalf("%s 动作码应为 %s，实际 %s", step.name, step.wantAction, row.Action)
		}
		if row.Result != audit.ResultSuccess {
			t.Fatalf("%s 成功动作的 result 应为 success，实际 %s（%s）", step.name, row.Result, row.ErrorCode)
		}
		if row.ErrorCode != "" {
			t.Fatalf("%s 成功动作不该带错误码，实际 %s", step.name, row.ErrorCode)
		}
		if row.ActorUserID == "" || row.ActorUsername == "" {
			t.Fatalf("%s 应记下操作者：%#v", step.name, row)
		}
		if row.CredentialType != audit.CredentialSession {
			t.Fatalf("%s 凭据类型应为 session，实际 %s", step.name, row.CredentialType)
		}
		if row.ActorIP != "203.0.113.7" {
			t.Fatalf("%s 来源 IP 应为 203.0.113.7，实际 %q", step.name, row.ActorIP)
		}
		if row.Route == "" || row.RequestMethod == "" || row.HTTPStatus != step.wantStatus {
			t.Fatalf("%s 的请求信息不完整：%#v", step.name, row)
		}
		if row.RequestID != requestIDs[step.name] {
			t.Fatalf("%s 的 request_id 应为 %s，实际 %s", step.name, requestIDs[step.name], row.RequestID)
		}
	}

	// 封禁与解封是同一路由的两种语义：动作码必须分开，否则"谁被封过"要读 changes。
	if action := fetchAuditRows(t, st, requestIDs["封禁"])[0].Action; action != "user.banned" {
		t.Fatalf("封禁动作码应为 user.banned，实际 %s", action)
	}
	if action := fetchAuditRows(t, st, requestIDs["解封"])[0].Action; action != "user.unbanned" {
		t.Fatalf("解封动作码应为 user.unbanned，实际 %s", action)
	}

	// 登录留痕：成功记登录者，失败记 attempted_username（且不记口令）。
	loginRID := auditRequestIDPrefix + "login-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	w := auditRequest(t, r, http.MethodPost, "/api/auth/login", "", "{\"username\":\""+targetName+"\",\"password\":\""+resetPassword+"\"}", loginRID)
	if w.Code != http.StatusOK {
		t.Fatalf("重置口令后应能用新口令登录，实际 %d / %s", w.Code, w.Body.String())
	}
	badRID := auditRequestIDPrefix + "bad-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	if w = auditRequest(t, r, http.MethodPost, "/api/auth/login", "", "{\"username\":\""+targetName+"\",\"password\":\"wrong-password\"}", badRID); w.Code != http.StatusUnauthorized {
		t.Fatalf("错口令登录应 401，实际 %d", w.Code)
	}
	missingRID := auditRequestIDPrefix + "missing-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	if w = auditRequest(t, r, http.MethodPost, "/api/auth/login", "", "{\"username\":\""+createdName+"@example.test\",\"password\":\"wrong-password\"}", missingRID); w.Code != http.StatusUnauthorized {
		t.Fatalf("不存在账号登录应 401，实际 %d", w.Code)
	}
	if err := recorder.Flush(ctx); err != nil {
		t.Fatalf("排空审计队列: %v", err)
	}
	okRows := fetchAuditRows(t, st, loginRID)
	if len(okRows) != 1 || okRows[0].Action != "session.login" || okRows[0].ActorUsername != targetName {
		t.Fatalf("登录成功应留一行 session.login 且记下登录者：%#v", okRows)
	}
	badRows := fetchAuditRows(t, st, badRID)
	if len(badRows) != 1 {
		t.Fatalf("登录失败也应留痕，实际 %d 行", len(badRows))
	}
	if badRows[0].Action != "session.login_failed" || badRows[0].Result != audit.ResultFailure {
		t.Fatalf("登录失败应记 session.login_failed + failure：%#v", badRows[0])
	}
	if badRows[0].ErrorCode != "invalid_credentials" {
		t.Fatalf("登录失败的 error_code 应为 invalid_credentials，实际 %s", badRows[0].ErrorCode)
	}
	if badRows[0].CredentialType != audit.CredentialAnonymous {
		t.Fatalf("登录失败时凭据类型应为 anonymous，实际 %s", badRows[0].CredentialType)
	}
	// attempted_username 若填的是邮箱，必须已被遮罩（这是"值里出现邮箱"那条防线）。
	missingRows := fetchAuditRows(t, st, missingRID)
	if len(missingRows) != 1 {
		t.Fatalf("不存在账号的登录失败也应留痕，实际 %d 行", len(missingRows))
	}
	if emailPattern.FindString(missingRows[0].Changes) != "" {
		t.Fatalf("登录失败摘要里的邮箱必须遮罩，实际 %s", missingRows[0].Changes)
	}

	// 失败路径：非法载荷 400、缺权限 403、匿名 401 —— 三类都要留痕。
	failCases := []struct {
		name       string
		method     string
		path       string
		bearer     string
		body       string
		wantStatus int
		wantAction string
		wantErr    string
	}{
		{"非法载荷", http.MethodPut, "/api/admin/users/" + targetID + "/ban", adminBearer, "{}", 400, "user.banned", "invalid_payload"},
		{"缺权限", http.MethodPut, "/api/admin/settings", memberBearer, "{\"registration_enabled\":false}", 403, "settings.updated", "forbidden"},
		{"匿名", http.MethodPut, "/api/admin/users/" + targetID + "/groups", "", "{\"groups\":[\"member\"]}", 401, "user.groups_changed", "authentication_required"},
	}
	for _, tc := range failCases {
		requestID := auditRequestIDPrefix + "fail-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
		if w := auditRequest(t, r, tc.method, tc.path, tc.bearer, tc.body, requestID); w.Code != tc.wantStatus {
			t.Fatalf("%s 应 %d，实际 %d / %s", tc.name, tc.wantStatus, w.Code, w.Body.String())
		}
		if err := recorder.Flush(ctx); err != nil {
			t.Fatalf("排空审计队列: %v", err)
		}
		rows := fetchAuditRows(t, st, requestID)
		if len(rows) != 1 {
			t.Fatalf("%s 应留 1 行审计，实际 %d 行", tc.name, len(rows))
		}
		if rows[0].Result != audit.ResultFailure || rows[0].ErrorCode != tc.wantErr {
			t.Fatalf("%s 应记 failure/%s，实际 %s/%s", tc.name, tc.wantErr, rows[0].Result, rows[0].ErrorCode)
		}
		if rows[0].Action != tc.wantAction {
			t.Fatalf("%s 动作码应为 %s，实际 %s", tc.name, tc.wantAction, rows[0].Action)
		}
	}

	// 敏感值扫描：以 PAT 创建/吊销为入口（响应里有明文令牌），再扫本次所有审计行。
	patRID := auditRequestIDPrefix + "pat-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	w = auditRequest(t, r, http.MethodPost, "/api/auth/tokens", patBearer, "{\"name\":\"audit probe\",\"scopes\":[\"community.post.create\"]}", patRID)
	if w.Code != http.StatusCreated {
		t.Fatalf("创建 PAT 应 201，实际 %d / %s", w.Code, w.Body.String())
	}
	var patBody struct {
		Token string `json:"token"`
		Item  struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	decodeInto(t, w, &patBody)
	if patBody.Token == "" || patBody.Item.ID == "" {
		t.Fatalf("创建 PAT 的响应应含明文与 id：%s", w.Body.String())
	}
	revokeRID := auditRequestIDPrefix + "revoke-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	if w = auditRequest(t, r, http.MethodDelete, "/api/auth/tokens/"+patBody.Item.ID, patBearer, "", revokeRID); w.Code != http.StatusOK {
		t.Fatalf("吊销 PAT 应 200，实际 %d / %s", w.Code, w.Body.String())
	}
	if err := recorder.Flush(ctx); err != nil {
		t.Fatalf("排空审计队列: %v", err)
	}
	if rows := fetchAuditRows(t, st, patRID); len(rows) != 1 || rows[0].Action != "pat.created" {
		t.Fatalf("创建 PAT 应留一行 pat.created：%#v", rows)
	}
	if rows := fetchAuditRows(t, st, revokeRID); len(rows) != 1 || rows[0].Action != "pat.revoked" {
		t.Fatalf("吊销 PAT 应留一行 pat.revoked：%#v", rows)
	}

	assertNoSensitiveValues(t, st, append([]string{
		resetPassword, selfPassword, "Created-Passw0rd!", chainTestPassword,
		createdEmail, targetName + "@example.test",
		patBody.Token,
	}, plainInviteCodes...))
}

// emailPattern 是"完整邮箱"的形状：审计行里出现任何命中它的串都算泄漏
// （遮罩形式 j***@example.com 不匹配——星号不在字符类里）。
var emailPattern = regexp.MustCompile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}")

// assertNoSensitiveValues 对本次用例产生的所有审计行做两轮检查：
// ① 不给明文（口令/令牌/邀请码/邮箱）；② 整行文本里不得出现任何邮箱形状的串。
func assertNoSensitiveValues(t *testing.T, st *store.Store, secrets []string) {
	t.Helper()
	rows, err := st.DB.Query("SELECT action, actor_username, actor_ip, actor_user_agent, target_type, target_id, changes::text, error_code, route, request_id FROM audit.audit_log WHERE request_id LIKE $1", auditRequestIDPrefix+"%")
	if err != nil {
		t.Fatalf("扫审计行: %v", err)
	}
	defer rows.Close()
	scanned := 0
	for rows.Next() {
		var cols [10]string
		dest := []any{&cols[0], &cols[1], &cols[2], &cols[3], &cols[4], &cols[5], &cols[6], &cols[7], &cols[8], &cols[9]}
		if err = rows.Scan(dest...); err != nil {
			t.Fatalf("扫审计行: %v", err)
		}
		scanned++
		line := strings.Join(cols[:], " | ")
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			if strings.Contains(line, secret) {
				t.Fatalf("审计行含敏感明文 %q：%s", secret, line)
			}
		}
		if hit := emailPattern.FindString(line); hit != "" {
			t.Fatalf("审计行含完整邮箱 %q：%s", hit, line)
		}
	}
	if scanned == 0 {
		t.Fatal("没有扫到任何审计行：筛选条件或写入路径不对")
	}
}

// 读取面：过滤组合、稳定分页、非法参数 400、权限门。用例直接插入带唯一动作码的行，
// 让断言不依赖别的用例留下的数据。
func TestAuditLogReadEndpointAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	r, st, _ := newAuditTestServer(t)

	_, adminName, adminBearer := insertChainUser(t, ctx, st, "admin")
	_, _, memberBearer := insertChainUser(t, ctx, st, "user")

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	action := "auditprobe_" + suffix + ".tick"
	// 截断到秒：过滤参数是 RFC3339（秒精度），带纳秒的基准时间会让 <= 边界差一跳。
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for i := 0; i < 5; i++ {
		result := audit.ResultSuccess
		errorCode := ""
		if i == 4 {
			result = audit.ResultFailure
			errorCode = "probe_failure"
		}
		if _, err := st.DB.ExecContext(ctx, "INSERT INTO audit.audit_log(id, occurred_at, service, action, actor_user_id, actor_username, credential_type, actor_ip, actor_user_agent, target_type, target_id, changes, result, error_code, request_method, route, http_status, request_id) VALUES($1,$2,$3,$4,NULLIF((SELECT id::text FROM auth.users WHERE username=$5),'')::uuid,$5,'session','198.51.100.9','probe-agent','entity',$6,$7,$8,$9,'PUT','/api/catalog/entities/:id',200,$10)",
			uuid.NewString(), base.Add(time.Duration(i)*time.Minute), audit.ServiceName, action, adminName,
			"probe-"+strconv.Itoa(i), "{\"seq\":"+strconv.Itoa(i)+"}", result, errorCode, "mf-read-probe-"+suffix+"-"+strconv.Itoa(i)); err != nil {
			t.Fatalf("插入探针审计行: %v", err)
		}
	}

	get := func(query string, bearer string) *httptest.ResponseRecorder {
		return auditRequest(t, r, http.MethodGet, "/api/admin/audit-logs?"+query, bearer, "", "")
	}
	decodePage := func(w *httptest.ResponseRecorder) store.AuditPage {
		var page store.AuditPage
		decodeInto(t, w, &page)
		return page
	}

	w := get("action="+action+"&per_page=10", adminBearer)
	if w.Code != http.StatusOK {
		t.Fatalf("读取审计应 200，实际 %d / %s", w.Code, w.Body.String())
	}
	page := decodePage(w)
	if page.Total != 5 || len(page.Items) != 5 {
		t.Fatalf("按动作码过滤应命中 5 行，实际 total=%d items=%d", page.Total, len(page.Items))
	}
	if page.Page != 1 || page.PerPage != 10 {
		t.Fatalf("响应应回显请求的 page/per_page，实际 %d/%d", page.Page, page.PerPage)
	}
	for _, item := range page.Items {
		if item.Action != action || item.Service != audit.ServiceName {
			t.Fatalf("过滤结果串了别的行：%#v", item)
		}
	}
	// 排序：occurred_at DESC（插入时 i 递增，因此第 4 条最新）。
	if page.Items[0].TargetID != "probe-4" {
		t.Fatalf("应按时间倒序，实际首行 %s", page.Items[0].TargetID)
	}
	if page.Items[0].Result != audit.ResultFailure || page.Items[0].ErrorCode != "probe_failure" {
		t.Fatalf("失败行应带上 result/error_code：%#v", page.Items[0])
	}

	// 分页稳定且不重叠。
	first := decodePage(get("action="+action+"&per_page=2&page=1", adminBearer))
	second := decodePage(get("action="+action+"&per_page=2&page=2", adminBearer))
	third := decodePage(get("action="+action+"&per_page=2&page=3", adminBearer))
	if first.Total != 5 || len(first.Items) != 2 || len(second.Items) != 2 || len(third.Items) != 1 {
		t.Fatalf("分页切分不对：%d/%d/%d（total=%d）", len(first.Items), len(second.Items), len(third.Items), first.Total)
	}
	seen := map[string]bool{}
	for _, item := range append(append([]store.AuditRow{}, first.Items...), second.Items...) {
		if seen[item.ID] {
			t.Fatalf("翻页出现重复行：%s", item.ID)
		}
		seen[item.ID] = true
	}

	// 其它过滤维度。
	if got := decodePage(get("action="+action+"&result=failure", adminBearer)).Total; got != 1 {
		t.Fatalf("result=failure 应命中 1 行，实际 %d", got)
	}
	if got := decodePage(get("action="+action+"&target_id=probe-2", adminBearer)).Total; got != 1 {
		t.Fatalf("按 target_id 过滤应命中 1 行，实际 %d", got)
	}
	if got := decodePage(get("action="+action+"&target_type=entity", adminBearer)).Total; got != 5 {
		t.Fatalf("按 target_type 过滤应命中 5 行，实际 %d", got)
	}
	if got := decodePage(get("service="+audit.ServiceName+"&action="+action, adminBearer)).Total; got != 5 {
		t.Fatalf("service+action 组合过滤应命中 5 行，实际 %d", got)
	}
	if got := decodePage(get("action="+action+"&actor="+adminName[:6], adminBearer)).Total; got != 5 {
		t.Fatalf("按操作者名前缀过滤应命中 5 行，实际 %d", got)
	}
	if got := decodePage(get("action="+action+"&actor=someone-else", adminBearer)).Total; got != 0 {
		t.Fatalf("不匹配的操作者名应 0 行，实际 %d", got)
	}
	if got := decodePage(get("action="+action+"&from="+base.Add(2*time.Minute).Format(time.RFC3339), adminBearer)).Total; got != 3 {
		t.Fatalf("from 过滤应命中 3 行，实际 %d", got)
	}
	if got := decodePage(get("action="+action+"&to="+base.Add(2*time.Minute).Format(time.RFC3339), adminBearer)).Total; got != 3 {
		t.Fatalf("to 过滤应命中 3 行，实际 %d", got)
	}
	if got := decodePage(get("request_id=mf-read-probe-"+suffix+"-3", adminBearer)).Total; got != 1 {
		t.Fatalf("按 request_id 过滤应命中 1 行，实际 %d", got)
	}

	// 权限门：匿名 401、无码成员 403（都不该看到别人的审计）。
	if w = get("action="+action, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("匿名读取审计应 401，实际 %d", w.Code)
	}
	if w = get("action="+action, memberBearer); w.Code != http.StatusForbidden {
		t.Fatalf("无 auth.audit.read 的成员应 403，实际 %d", w.Code)
	}

	// 非法参数：一律 400 invalid_query:<参数>。
	for _, tc := range []struct{ query, want string }{
		{"page=0", "invalid_query: page"},
		{"per_page=500", "invalid_query: per_page"},
		{"result=maybe", "invalid_query: result"},
		{"actor_user_id=nope", "invalid_query: actor_user_id"},
		{"from=2026-09-19", "invalid_query: from"},
		{"from=2026-09-19T10:00:00Z&to=2026-09-19T09:00:00Z", "invalid_query: to"},
	} {
		w = get(tc.query, adminBearer)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d / %s", tc.query, w.Code, w.Body.String())
		}
		var body struct {
			Error string `json:"error"`
		}
		decodeInto(t, w, &body)
		if body.Error != tc.want {
			t.Fatalf("%s 的错误码应为 %q，实际 %q", tc.query, tc.want, body.Error)
		}
	}

	// 审计读取本身不是写操作：不该因为读一次就多留一行。
	before := decodePage(get("service="+audit.ServiceName+"&action="+action, adminBearer)).Total
	_ = get("service="+audit.ServiceName+"&action="+action, adminBearer)
	after := decodePage(get("service="+audit.ServiceName+"&action="+action, adminBearer)).Total
	if before != after {
		t.Fatalf("读取审计不该产生新的审计行：%d → %d", before, after)
	}

	// 跨服务可见性：读取面不是"只看 auth 的行"，别的服务写进同一张表的行也查得到
	// （这正是统一表 + 单一读取面的取舍所在，见契约 §5）。
	catalogRID := "mf-read-probe-" + suffix + "-catalog"
	if _, err := st.DB.ExecContext(ctx, "INSERT INTO audit.audit_log(id, occurred_at, service, action, target_type, target_id, changes, result, request_method, route, http_status, request_id) VALUES($1,$2,'catalog',$3,'entity','probe-catalog','{}','success','POST','/api/catalog/entities',200,$4)",
		uuid.NewString(), base, action, catalogRID); err != nil {
		t.Fatalf("插入跨服务探针行: %v", err)
	}
	cross := decodePage(get("service=catalog&action="+action, adminBearer))
	if cross.Total != 1 || len(cross.Items) != 1 || cross.Items[0].Service != "catalog" {
		t.Fatalf("读取面应能看到其它服务的审计行：%#v", cross)
	}
	if all := decodePage(get("action="+action+"&per_page=10", adminBearer)); all.Total != 6 {
		t.Fatalf("不按服务过滤时应含跨服务行（共 6 行），实际 %d", all.Total)
	}

	// 清理探针行：审计表不参与 testutil 的清库（它跨服务，不该被别的用例顺手清掉）。
	if _, err := st.DB.ExecContext(ctx, "DELETE FROM audit.audit_log WHERE request_id LIKE $1", "mf-read-probe-"+suffix+"%"); err != nil {
		t.Fatalf("清理探针行: %v", err)
	}
}
