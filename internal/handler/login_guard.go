package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/audit"
)

// 登录失败凭据防护。层次关系是这次改动的前提，改这里之前先读完这段：
//
//	网关 nginx limit_req（/api/auth/ 5r/s burst=10）与账号服务的 rateLimiter（默认 15/分钟）
//	  都是「请求速率」层：只按来源 IP、不看请求内容，防的是接口被刷。
//	本层是「失败凭据」层：按账号标识 + 来源 IP 两个维度分别累计登录失败次数，
//	  防的是"请求速率完全合法、但凭据一直错"的试口令。
//	两层串行叠加、互不覆盖：请求先过速率层（429 rate_limited），本层只在其后按失败次数判定
//	  （429 login_blocked）；没有再造一套按请求速率的限流。
//
// 阈值/窗口/恢复（写死在代码里，不做成实例设置——再加一组可调上限，只会让"这次到底哪层拦的"更难查）：
//
//	账号维度：15 分钟固定窗口内失败满 5 次起拒绝，返回 429 + Retry-After（窗口剩余秒数），
//	  窗口结束自动恢复（新窗口从零开始）。计数写在"第 5 次失败"时，所以连续输错 4~5 次的
//	  普通用户仍能拿正确口令登录，不会被锁死。
//	IP 维度：同一窗口内失败满 20 次起拒绝，用于兜住"每个账号只试 4 次就换下一个"的口令喷洒——
//	  只按账号计数时这种打法永远不会触发。
//
// 递增延迟：失败 3 次起，后续登录在进业务之前先等 200ms/400ms/800ms…封顶 2s，
//
//	让每次猜测都变贵。只有在已有失败记录时才产生，无失败史的登录完全不被拖慢。
//
// 计数只放进程内存：登录路径不额外写库——失败次数落库等于给每次失败登录加一次写，
// 反而成了新的放大面。代价是进程重启清零、多副本不共享；对"基本防护"够用，
// 真要多副本共享再换成 Redis 计数。
const (
	loginGuardWindow            = 15 * time.Minute
	loginGuardAccountMaxFailure = 5
	loginGuardIPMaxFailure      = 20
	// 延迟从第 3 次失败起：阈值是 5，留两次余量，普通人手滑几下的体验不至于太差。
	loginGuardDelayAfterFailure = 3
	loginGuardDelayBase         = 200 * time.Millisecond
	loginGuardDelayMax          = 2 * time.Second
	// 与 rate_limited 区分：前端/日志据此分辨是"刷太快"还是"凭据一直在错"。
	loginGuardErrorCode = "login_blocked"
)

// loginBucket 是一个维度（账号标识或来源 IP）在固定窗口内的失败计数。
type loginBucket struct {
	start    time.Time
	failures int
	lastSeen time.Time
}

// loginGuard 是登录失败计数器。按 Register 建一份，状态随引擎存活；
// 不放进 Handler：它不用 store，也不该被多个引擎共享。
type loginGuard struct {
	window     time.Duration
	accountMax int
	ipMax      int
	// now 可被用例换成假时钟，窗口过期与递增延迟才能被确定性地断言。
	now func() time.Time

	mu       sync.Mutex
	accounts map[string]*loginBucket
	ips      map[string]*loginBucket
}

func newLoginGuard() *loginGuard {
	return &loginGuard{
		window:     loginGuardWindow,
		accountMax: loginGuardAccountMaxFailure,
		ipMax:      loginGuardIPMaxFailure,
		now:        time.Now,
		accounts:   map[string]*loginBucket{},
		ips:        map[string]*loginBucket{},
	}
}

// loginPayload 只取判定需要的标识字段：口令不参与计数，也就不进任何结构体、不落任何地方。
type loginPayload struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// loginIdentifiers 归一化账号标识：trim + 小写，username/email 都取（去重）。
// 登录查询优先用 username，但攻击者可以交替填 username / email 让计数落到不同的键上，
// 所以两个非空标识都计——宁可多算，不给绕过的口子。
func loginIdentifiers(in loginPayload) []string {
	keys := make([]string, 0, 2)
	for _, raw := range []string{in.Username, in.Email} {
		key := strings.ToLower(strings.TrimSpace(raw))
		if key == "" {
			continue
		}
		seen := false
		for _, have := range keys {
			if have == key {
				seen = true
				break
			}
		}
		if !seen {
			keys = append(keys, key)
		}
	}
	return keys
}

// check 判定这次登录是否该拒、退避多久、以及进业务前要不要先等一会。
// 全程在锁内做完（只算数，不 sleep），延迟不带进临界区。
func (g *loginGuard) check(keys []string, ip string) (blocked bool, retryAfter, delay time.Duration) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked(now)
	worst := 0
	for _, key := range keys {
		b := g.lookupLocked(g.accounts, key, now)
		if b == nil {
			continue
		}
		if b.failures >= g.accountMax && !blocked {
			blocked = true
			retryAfter = g.remainingLocked(b, now)
		}
		if b.failures > worst {
			worst = b.failures
		}
	}
	if ip != "" {
		if b := g.lookupLocked(g.ips, ip, now); b != nil {
			if b.failures >= g.ipMax {
				blocked = true
				if r := g.remainingLocked(b, now); r > retryAfter {
					retryAfter = r
				}
			}
			if b.failures > worst {
				worst = b.failures
			}
		}
	}
	if blocked {
		return true, retryAfter, 0
	}
	return false, 0, loginGuardDelay(worst)
}

// recordFailure 记一次凭据失败：账号与 IP 两个维度同时累加，任一维度到阈值都会拦。
func (g *loginGuard) recordFailure(keys []string, ip string) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked(now)
	for _, key := range keys {
		g.bumpLocked(g.accounts, key, now)
	}
	if ip != "" {
		g.bumpLocked(g.ips, ip, now)
	}
}

// recordSuccess 只清零账号维度。IP 维度不清零：否则攻击者拿一个能登录的账号，
// 每隔几次失败就"洗"一次自己的 IP 计数，IP 维度等于形同虚设；它只随窗口过期恢复。
func (g *loginGuard) recordSuccess(keys []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, key := range keys {
		delete(g.accounts, key)
	}
}

// lookupLocked 返回未过期的桶；不存在返回 nil（只读判定不建桶，免得随机标识把表撑大）。
// 已过期的桶就地复位：窗口一过就自动恢复，不需要后台清理任务。
func (g *loginGuard) lookupLocked(m map[string]*loginBucket, key string, now time.Time) *loginBucket {
	b := m[key]
	if b == nil {
		return nil
	}
	if now.Sub(b.start) > g.window {
		b.start, b.failures = now, 0
	}
	return b
}

func (g *loginGuard) bumpLocked(m map[string]*loginBucket, key string, now time.Time) {
	b := g.lookupLocked(m, key, now)
	if b == nil {
		m[key] = &loginBucket{start: now, failures: 1, lastSeen: now}
		return
	}
	b.failures++
	b.lastSeen = now
}

// remainingLocked 是窗口剩余时长，也是 Retry-After 的来源；不足 1 秒按 1 秒报，
// 免得客户端收到 0 立刻重试。
func (g *loginGuard) remainingLocked(b *loginBucket, now time.Time) time.Duration {
	left := b.start.Add(g.window).Sub(now)
	if left < time.Second {
		left = time.Second
	}
	return left
}

// pruneLocked 与 rateLimiter 同一口径：只在表超过 4096 项时清一次过期项，
// 不为每次请求付全表扫描的代价。
func (g *loginGuard) pruneLocked(now time.Time) {
	if len(g.accounts)+len(g.ips) <= 4096 {
		return
	}
	for k, b := range g.accounts {
		if now.Sub(b.lastSeen) > g.window {
			delete(g.accounts, k)
		}
	}
	for k, b := range g.ips {
		if now.Sub(b.lastSeen) > g.window {
			delete(g.ips, k)
		}
	}
}

// loginGuardDelay 把失败次数换算成递增延迟：3 次 200ms、4 次 400ms…封顶 2s。
// 左移可能溢出成负数，一律按封顶处理。
func loginGuardDelay(failures int) time.Duration {
	if failures < loginGuardDelayAfterFailure {
		return 0
	}
	delay := loginGuardDelayBase << (failures - loginGuardDelayAfterFailure)
	if delay <= 0 || delay > loginGuardDelayMax {
		delay = loginGuardDelayMax
	}
	return delay
}

// loginGuardMiddleware 是 POST /api/auth/login 上的唯一接线点。
func (h *Handler) loginGuardMiddleware() gin.HandlerFunc {
	// 工厂可能没接线（用例直接构造 Handler，例如 oauth_chain_test 的内存替身）：
	// 与 rateLimiter 的缺省策略同一口径——缺省仍按生产阈值生效，不会静默变成不设防。
	factory := h.loginGuardFactory
	if factory == nil {
		factory = newLoginGuard
	}
	guard := factory()
	return func(c *gin.Context) {
		in, ok := readLoginPayload(c)
		if !ok {
			// 读不出/解析不了的请求不计数：既没有可归属的账号标识，也试不出任何口令，
			// 交给业务里的 body() 照旧回 400（否则空体请求能把 IP 维度刷满）。
			c.Next()
			return
		}
		keys := loginIdentifiers(in)
		if len(keys) == 0 {
			// 没有标识的请求不按账号计数：空串会变成一个所有人共享的桶，谁都能把别人拦在外面。
			c.Next()
			return
		}
		ip := c.ClientIP()
		blocked, retryAfter, delay := guard.check(keys, ip)
		if blocked {
			c.Header("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			audit.Fail(c, loginGuardErrorCode)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": loginGuardErrorCode})
			return
		}
		// 已有失败记录才延迟；纯正常登录（无失败史）走不到这里。
		// time.Sleep 在这里可以接受：不持锁、封顶 2s，最坏只占一个请求 goroutine 两秒。
		if delay > 0 && !sleepOrAbort(c, delay) {
			// 客户端已断开，不必再回响应（写了也没人收）。
			return
		}
		c.Next()
		switch status := c.Writer.Status(); {
		case status >= 200 && status < 300:
			guard.recordSuccess(keys)
		case status == http.StatusUnauthorized:
			guard.recordFailure(keys, ip)
			// 403（account_banned）不计入失败：那种请求的口令是对的，不是猜口令的信号，
			// 计进去只会让"账号已停用"的提示被 login_blocked 盖掉。
			// 400（载荷不合法）同样不计：见 readLoginPayload 的说明。
		}
	}
}

// readLoginPayload 读出登录请求体并把 c.Request.Body 原样回填：
// 中间件先于业务 handler 执行，不回填的话后面的 body(c,&in) 只会读到 EOF（400）。
func readLoginPayload(c *gin.Context) (loginPayload, bool) {
	var in loginPayload
	if c.Request.Body == nil {
		return in, false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	raw, err := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return in, false
	}
	// 用 json.Decoder 而不是 json.Unmarshal：与 gin 绑定请求体的解码方式一致，
	// 免得"能通过业务解析、却绕过本层判定"的写法（如尾部多余字节）成为绕过口。
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&in); err != nil {
		return in, false
	}
	return in, true
}

// sleepOrAbort 用定时器而不是裸 time.Sleep：客户端中途断开时立刻返回，不白占 goroutine。
func sleepOrAbort(c *gin.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-c.Request.Context().Done():
		return false
	}
}
