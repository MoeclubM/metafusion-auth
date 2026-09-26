package handler

// 并发注册同名（真实 PostgreSQL）：唯一索引 users_username_key 是裁判，
// 8 个 goroutine 同时注册必须恰好一个成功、其余拿到稳定的 username_or_email_taken（409）——
// 既不能 500，也不能把 "pq: duplicate key ... users_username_key" 这类驱动原文交给注册页
// （2026-09-19 第二轮架构报告 #9/#15/#16）。
//
// 两层验证：HTTP 层看状态码/错误码与响应体不泄露原文；仓储层直接看并发 Register 的返回错误
// 是不是干净的领域码（旧实现会把 *pq.Error 原样返回，那一层是能独立证伪的）。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

const raceRacers = 8

// raceRegister 起 n 个 goroutine 同时调用同一个入口，返回每个 racer 的结果。
func raceRegister(n int, fire func(i int) (int, string)) ([]int, []string) {
	start := make(chan struct{})
	codes := make([]int, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i], bodies[i] = fire(i)
		}(i)
	}
	close(start)
	wg.Wait()
	return codes, bodies
}

func TestConcurrentRegisterSameUsernameAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st).Register(r)

	// 注册默认关闭（受控站点）：用例显式打开，收尾删掉该行回到默认值 false。
	if err := st.UpdateSettings(ctx, map[string]any{store.SettingRegistrationEnabled: true}, settingsActor()); err != nil {
		t.Fatalf("打开注册开关: %v", err)
	}
	t.Cleanup(func() {
		if _, err := st.DB.Exec("DELETE FROM auth.instance_settings WHERE key=$1", store.SettingRegistrationEnabled); err != nil {
			t.Errorf("恢复注册开关: %v", err)
		}
	})

	// ── HTTP 层：并发注册同名 ──
	name := raceName("http")
	payload := fmt.Sprintf(`{"username":%q,"email":%q,"password":"race-test-password"}`, name, name+"@example.test")
	t.Cleanup(func() { deleteNamedUser(t, st, name) })

	codes, bodies := raceRegister(raceRacers, func(int) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	})

	ok, taken := 0, 0
	for i := 0; i < raceRacers; i++ {
		if leakPattern.MatchString(bodies[i]) {
			t.Errorf("第 %d 个响应泄露了故障原文：%s", i, bodies[i])
		}
		switch {
		case codes[i] == http.StatusOK:
			ok++
		case codes[i] == http.StatusConflict && strings.Contains(bodies[i], "username_or_email_taken"):
			taken++
		default:
			t.Errorf("第 %d 个响应既不是成功也不是稳定的撞名冲突：%d %s", i, codes[i], bodies[i])
		}
	}
	if ok != 1 || taken != raceRacers-1 {
		t.Fatalf("并发注册同名应当恰好 1 个成功、%d 个 409 username_or_email_taken，实际 ok=%d taken=%d codes=%v bodies=%v",
			raceRacers-1, ok, taken, codes, bodies)
	}

	var rows int
	if err := st.DB.QueryRow("SELECT count(*) FROM auth.users WHERE username=$1", name).Scan(&rows); err != nil {
		t.Fatalf("回查账号数: %v", err)
	}
	if rows != 1 {
		t.Fatalf("并发注册同名必须只落一行，实际 %d 行", rows)
	}

	// ── 仓储层：预检放行但 INSERT 撞唯一索引（并发竞态的确定性复现）──
	// 未提交的同名行对"先查后插"的预检不可见（READ COMMITTED），所以 Register 的预检必然通过，
	// 它的 INSERT 与这行撞唯一索引并阻塞；提交占位事务后 Register 必须回稳定码而不是 pq 原文。
	// 这条路径正是并发注册落败方走过的路径，不依赖 goroutine 调度运气（8 个 goroutine 那一段
	// 靠的是真实并发，但落败方也可能被预检先接住）。
	direct := raceName("store")
	t.Cleanup(func() { deleteNamedUser(t, st, direct) })
	tx, err := st.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("开启占位事务: %v", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash) VALUES($1,$2,$3,$4)",
		uuid.NewString(), direct, direct+"@example.test", "placeholder-not-a-hash"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("占位插入: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, rerr := st.Register(ctx, direct, direct+"@example.test", "race-test-password", "")
		done <- rerr
	}()
	// Register 已过预检并阻塞在这条 INSERT 上（等占位事务释放唯一索引），提交占位事务让它继续。
	time.Sleep(700 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交占位事务: %v", err)
	}
	registerErr := <-done
	if registerErr == nil {
		t.Fatal("同名已存在时必须失败，实际注册成功")
	}
	if registerErr.Error() != "username_or_email_taken" {
		var pg *pq.Error
		if errors.As(registerErr, &pg) {
			t.Errorf("仓储层把驱动错误原样返回了（SQLSTATE %s，约束 %s）：%v", pg.Code, pg.Constraint, registerErr)
		} else {
			t.Errorf("落败方拿到的不是稳定码：%v", registerErr)
		}
	}
}

func raceName(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
}

// deleteNamedUser 收尾清掉同名账号：正常路径只有一行，竞态万一落了两行也不会把脏数据留下。
func deleteNamedUser(t *testing.T, st *store.Store, name string) {
	t.Helper()
	rows, err := st.DB.Query("SELECT id FROM auth.users WHERE username=$1", name)
	if err != nil {
		t.Errorf("回查测试账号: %v", err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		testutil.DeleteUser(t, st.DB, id)
	}
}
