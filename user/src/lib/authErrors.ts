// 账号服务把稳定错误码放在响应体的 error 字段（respond() 统一只给单一 error）。
// 这里把码映射成四语文案：前端只认 auth.error.* 字典，未知码回退到通用提示，
// 绝不把原始 code 抛给用户看。
//
// 同一句人话对应多个码时走别名表，避免为服务端的近义码各写一条文案。

// Explicit keys let dictionary sync/check cover error codes chosen at runtime.
const AUTH_ERROR_KEYS: Record<string, string> = {
  invalid_credentials: "auth.error.invalid_credentials",
  invalid_credentials_format: "auth.error.invalid_credentials_format",
  invalid_username: "auth.error.invalid_username",
  invalid_password_length: "auth.error.invalid_password_length",
  invalid_email: "auth.error.invalid_email",
  account_disabled: "auth.error.account_disabled",
  login_blocked: "auth.error.login_blocked",
  user_not_found: "auth.error.user_not_found",
  user_already_exists: "auth.error.user_already_exists",
  invalid_invite_code: "auth.error.invalid_invite_code",
  registration_closed: "auth.error.registration_closed",
  rate_limit_exceeded: "auth.error.rate_limit_exceeded",
  unauthorized: "auth.error.unauthorized",
  authentication_required: "auth.error.authentication_required",
  forbidden: "auth.error.forbidden",
  invalid_expiry: "auth.error.invalid_expiry",
  invalid_scope: "auth.error.invalid_scope",
  invalid_token_name: "auth.error.invalid_token_name",
  scope_not_granted: "auth.error.scope_not_granted",
  token_not_found: "auth.error.token_not_found",
  token_limit_reached: "auth.error.token_limit_reached",
  invalid_payload: "auth.error.invalid_payload",
  invalid_old_password: "auth.error.invalid_old_password",
  setup_complete: "auth.error.setup_complete",
  setup_needed: "auth.error.setup_needed",
  invite_required: "auth.error.invite_required",
  invite_exhausted: "auth.error.invite_exhausted",
  service_unavailable: "auth.error.service_unavailable",
};

const AUTH_ERROR_ALIASES: Record<string, string> = {
  // 注册撞名：服务端用 username_or_email_taken，历史上还有下面几种写法
  username_taken: "user_already_exists",
  username_or_email_taken: "user_already_exists",
  email_taken: "user_already_exists",
  // 邀请码无效：服务端 consumeInvite 给 invalid_invite_code
  invite_invalid: "invalid_invite_code",
  // 注册关闭：服务端 Register 给 registration_closed
  registration_disabled: "registration_closed",
  // 注册字段不合规：线上实测到的 invalid_username（前端此前只显示「请求失败」），
  // 以及服务端在别处用的 invalid_password / weak_password 写法。用户名格式与口令长度
  // 是两个不同的问题，分别指向两条文案，不合并成一句泛泛的"格式不对"。
  invalid_password: "invalid_password_length",
  weak_password: "invalid_password_length",
  // 账号停用：服务端 fail() 给的 banned（403），历史上还有 account_disabled 写法。
  banned: "account_disabled",
  account_banned: "account_disabled",
};

/** 读取响应错误对象上的状态码：只按字段探测，不 import api.ts 的错误类，避免跨模块耦合。 */
export function httpStatusOf(err: unknown): number | undefined {
  const status = (err as { status?: unknown } | null | undefined)?.status;
  return typeof status === "number" ? status : undefined;
}

/**
 * 读取 Retry-After（秒）。只有秒数形式能被解释：HTTP-date 形式在这里没有可靠的时区来源，
 * 与其算错不如不显示（回 undefined，调用方退回不承诺具体秒数的文案）。
 */
export function httpRetryAfterSecondsOf(err: unknown): number | undefined {
  const raw = (err as { retryAfter?: unknown } | null | undefined)?.retryAfter;
  const seconds = typeof raw === "string" ? Number.parseInt(raw.trim(), 10) : NaN;
  return Number.isFinite(seconds) && seconds > 0 ? seconds : undefined;
}

/**
 * 把账号服务错误码翻译成当前语言的人话；未知码回退到通用请求失败提示。
 * status 只用来兜住"路由不存在/上游不可用"这类没有业务码的情况
 * （例如账号服务尚未部署这些端点时返回的 404 纯文本）。
 *
 * 限流要分辨两层（见 metafusion-auth/internal/handler/login_guard.go 的注释）：
 *   · 请求速率层只回 rate_limited，没有"账号被锁多久"的语义；
 *   · 失败凭据层回 login_blocked，并带 Retry-After（秒）。
 * 所以 429 先看错误码，再看 retryAfterSeconds：有秒数就告诉用户还要等多久，
 * 没给（例如网关 nginx limit_req 直接回的 429）就退回通用限流文案。
 */
export function authErrorText(
  code: string | null | undefined,
  t: (key: string, vars?: Record<string, string | number>) => string,
  status?: number,
  fallbackKey = "auth.requestFailed",
  retryAfterSeconds?: number
): string {
  if (status === 404 || (status !== undefined && status >= 500)) {
    return t("auth.error.service_unavailable");
  }
  const raw = (code || "").trim();
  if (status === 429 || raw === "login_blocked") {
    const key = raw === "login_blocked" ? "auth.error.login_blocked" : "auth.error.rate_limit_exceeded";
    // Retry-After 是窗口剩余秒数：向上取整到分钟，给用户一个可读的等待预期。
    const minutes = retryAfterSeconds ? Math.max(1, Math.ceil(retryAfterSeconds / 60)) : 0;
    return t(key, minutes ? { minutes } : undefined);
  }
  if (!raw) return t(fallbackKey);
  for (const candidate of [raw, AUTH_ERROR_ALIASES[raw]]) {
    if (!candidate) continue;
    const key = AUTH_ERROR_KEYS[candidate];
    if (!key) continue;
    const translated = t(key);
    if (translated && translated !== key) return translated;
  }
  return t(fallbackKey);
}
