package handler

// respond 的错误映射与"原文不外发"：
//  1. SQLSTATE → 稳定码与状态码（唯一约束 409、外键/CHECK 与非法字面量 400、其余 500）；
//  2. 未登记的库层/网络/反序列化原文一律 500 通用码，响应体里不得出现驱动前缀、SQLSTATE、
//     约束名、SQL 片段、文件路径或内网地址（2026-09-19 第二轮架构报告 #15/#16 的回归断言）。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

// leakPattern 是绝不允许出现在错误响应体里的形状：驱动前缀、SQLSTATE、SQL 片段、
// 约束名、文件路径与内网地址。
var leakPattern = regexp.MustCompile(`pq:|SQLSTATE|SELECT|INSERT|UPDATE|DELETE|users_username_key|groups_code_key|password_hash|/|\\|dial tcp|127\.0\.0\.1|connection refused|permission denied`)

// respondOnce 直接把 respond 当纯函数调用，避免为错误映射起一整套 HTTP 服务。
func respondOnce(t *testing.T, err error) (int, string, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	respond(c, gin.H{"ok": true}, err)
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 JSON: %v / %s", err, w.Body.String())
	}
	return w.Code, body.Error, w.Body.String()
}

func TestRespondMapsErrorsToStableCodes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"success", nil, http.StatusOK, ""},
		{"no rows", sql.ErrNoRows, http.StatusNotFound, "not_found"},
		{"forbidden", errors.New("forbidden"), http.StatusForbidden, "forbidden"},
		{"banned", errors.New("account_banned"), http.StatusForbidden, "account_banned"},
		{"bad credentials", errors.New("invalid_credentials"), http.StatusUnauthorized, "invalid_credentials"},
		{"bad token", errors.New("invalid_token"), http.StatusUnauthorized, "invalid_token"},
		{"format", errors.New("invalid_credentials_format"), http.StatusBadRequest, "invalid_credentials_format"},
		// 带细节的复合码：状态码按首段判定，细节原样保留（前端按冒号分段查字典）。
		// group_not_found 的状态码保持接线前的 400：本次只收敛"原文不外发"，不动未要求的状态码。
		{"coded detail", errors.New("group_not_found: member"), http.StatusBadRequest, "group_not_found: member"},
		{"unknown token", errors.New("token_not_found"), http.StatusNotFound, "token_not_found"},
		// 唯一约束：撞名与撞组码是用户可自纠的冲突 → 409 + 稳定码。
		{"pq username unique", &pq.Error{Code: "23505", Constraint: "users_username_key",
			Message: "duplicate key value violates unique constraint users_username_key",
			Detail:  "Key (username)=(kana) already exists."}, http.StatusConflict, "username_or_email_taken"},
		{"pq group code unique", &pq.Error{Code: "23505", Constraint: "groups_code_key"}, http.StatusConflict, "group_exists"},
		{"pq other unique", &pq.Error{Code: "23505", Constraint: "user_groups_pkey"}, http.StatusConflict, "conflict"},
		{"pq foreign key", &pq.Error{Code: "23503", Constraint: "sessions_user_id_fkey"}, http.StatusBadRequest, "constraint_violation"},
		{"pq check", &pq.Error{Code: "23514", Constraint: "users_role_check"}, http.StatusBadRequest, "constraint_violation"},
		{"pq bad uuid", &pq.Error{Code: "22P02"}, http.StatusBadRequest, "invalid_id"},
		{"pq unavailable", &pq.Error{Code: "08006", Message: "connection failure"}, http.StatusInternalServerError, "database_error"},
		// 未登记的原文：连接被拒、context 取消、文档/响应反序列化、文件路径、SQL 片段。
		{"net refused", errors.New("dial tcp 10.0.0.5:5432: connect: connection refused"), http.StatusInternalServerError, "internal_error"},
		{"context canceled", context.Canceled, http.StatusInternalServerError, "internal_error"},
		{"context deadline", context.DeadlineExceeded, http.StatusInternalServerError, "internal_error"},
		{"conn done", sql.ErrConnDone, http.StatusInternalServerError, "internal_error"},
		{"bad conn", driver.ErrBadConn, http.StatusInternalServerError, "internal_error"},
		{"json decode", errors.New("invalid character 'x' looking for beginning of value"), http.StatusInternalServerError, "internal_error"},
		{"file path", errors.New("open /etc/metafusion/keys.json: permission denied"), http.StatusInternalServerError, "internal_error"},
		{"sql fragment", errors.New("SELECT id FROM auth.users WHERE username=$1"), http.StatusInternalServerError, "internal_error"},
		{"unknown code", errors.New("boom"), http.StatusBadRequest, "boom"},
	} {
		status, code, body := respondOnce(t, tc.err)
		if status != tc.wantStatus {
			t.Errorf("%s: status=%d want=%d (body=%s)", tc.name, status, tc.wantStatus, body)
		}
		if tc.err == nil {
			if code != "" {
				t.Errorf("%s: 成功响应不该带错误码，实际 %q", tc.name, code)
			}
			continue
		}
		if code != tc.wantCode {
			t.Errorf("%s: error=%q want=%q", tc.name, code, tc.wantCode)
		}
		if status >= http.StatusBadRequest && leakPattern.MatchString(body) {
			t.Errorf("%s: 响应体泄露了故障原文：%s", tc.name, body)
		}
	}
}

// 业务码必须保持可翻译：它们是机器码形状，不能被"原文不外发"误杀成 500。
func TestAuthStatusForKeepsBusinessCodes(t *testing.T) {
	for code, want := range map[string]int{
		"forbidden": http.StatusForbidden, "account_banned": http.StatusForbidden,
		"invalid_credentials": http.StatusUnauthorized, "invalid_token": http.StatusUnauthorized,
		"version_conflict": http.StatusConflict, "username_or_email_taken": http.StatusConflict,
		"group_exists":     http.StatusConflict,
		"client_not_found": http.StatusNotFound, "token_not_found": http.StatusNotFound,
		"invalid_payload": http.StatusBadRequest, "registration_closed": http.StatusBadRequest,
		"setup_complete": http.StatusBadRequest, "rate_limited": http.StatusBadRequest,
	} {
		if got := authStatusFor(code); got != want {
			t.Errorf("%s: status=%d want=%d", code, got, want)
		}
		if !machineCode(code) {
			t.Errorf("%s: 业务码必须是机器码形状", code)
		}
	}
}

// 首段是码、后面是细节的复合码同样要按首段定状态；首段不是码的原文一律算故障。
func TestFirstCodeAndMachineCode(t *testing.T) {
	if got := firstCode("group_not_found: member"); got != "group_not_found" {
		t.Errorf("firstCode=%q", got)
	}
	if got := firstCode("invalid_term"); got != "invalid_term" {
		t.Errorf("firstCode=%q", got)
	}
	for _, raw := range []string{
		"dial tcp 10.0.0.5:5432: connect: connection refused",
		"invalid character 'x' looking for beginning of value",
		"open /etc/metafusion/keys.json: permission denied",
		"SELECT 1",
	} {
		if machineCode(firstCode(raw)) {
			t.Errorf("%q 的首段不该是机器码形状", raw)
		}
	}
	for _, raw := range []string{
		"dial tcp 10.0.0.5:5432: connect: connection refused",
		"invalid character 'x' looking for beginning of value",
		"sql: connection is already closed",
		"open /etc/metafusion/keys.json: permission denied",
		"SELECT 1",
	} {
		if !internalFailure(errors.New(raw)) {
			t.Errorf("%q 应判定为后端故障原文", raw)
		}
	}
	for _, coded := range []string{"group_not_found: member", "invalid_setting: registration_enabled", "invalid_scope: openid profile"} {
		if internalFailure(errors.New(coded)) {
			t.Errorf("%q 是业务码 + 细节，不该被判成故障原文", coded)
		}
	}
	// 标准库/驱动的错误前缀与机器码同形，必须靠前缀表挡掉（只剩消息、拿不到哨兵值时也一样）。
	for _, infra := range []string{"sql: connection is already closed", "driver: bad connection", "pq: duplicate key value violates unique constraint"} {
		if !internalFailure(errors.New(infra)) {
			t.Errorf("%q 是驱动/标准库前缀，应判定为故障原文", infra)
		}
	}
}
