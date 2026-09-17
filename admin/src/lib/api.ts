"use client";

// 账号服务 API 的唯一出口：同源 /api/*（网关按路径分流到 metafusion-auth），
// 会话是账号服务签发的同域 Cookie mf_session（HttpOnly，前端读不到也不需要读）。
// basePath /admin/account 只作用于本应用自己的路由，不参与这里——apiFetch 传的是绝对路径。

/** 主站登录页：与本应用不同 basePath，永远用绝对路径，且不能带 basePath 前缀。 */
export const LOGIN_PATH = "/login";

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    // target 为 es5 时 Error 子类的原型链会断开，显式接回，保证 instanceof 判定仍可用。
    Object.setPrototypeOf(this, ApiError.prototype);
  }
}

export function readLocaleCookie(): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(/(?:^|;\s*)NEXT_LOCALE=([^;]+)/);
  return m ? decodeURIComponent(m[1]!) : null;
}

/** 当前页面地址（含 basePath），用于登录后跳回原处。 */
export function currentPath(): string {
  if (typeof window === "undefined") return "/admin/account";
  return window.location.pathname + window.location.search;
}

export function redirectToLogin(): void {
  if (typeof window === "undefined") return;
  window.location.href = `${LOGIN_PATH}?redirect=${encodeURIComponent(currentPath())}`;
}

export interface ApiOptions {
  /** 探活用：/api/auth/me 自己处理 401，不要在这里抢先跳走。 */
  redirectOn401?: boolean;
}

export async function apiFetch<T>(path: string, init: RequestInit = {}, options: ApiOptions = {}): Promise<T> {
  const headers: Record<string, string> = { ...((init.headers as Record<string, string> | undefined) ?? {}) };
  if (init.body != null && !(init.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  // 账号服务的错误文案与四语资源按 x-locale / Accept-Language 选语言（同意页同口径）。
  const locale = readLocaleCookie();
  if (locale) {
    if (!headers["x-locale"] && !headers["X-Locale"]) headers["x-locale"] = locale;
    if (!headers["Accept-Language"]) headers["Accept-Language"] = locale;
  }

  const res = await fetch(path, { cache: "no-store", ...init, credentials: "include", headers });

  if (res.status === 401) {
    if (options.redirectOn401 !== false) redirectToLogin();
    throw new ApiError("authentication_required", 401);
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({} as { error?: unknown }));
    const code = typeof body?.error === "string" && body.error ? body.error : `HTTP ${res.status}`;
    throw new ApiError(code, res.status);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function getJson<T>(path: string): Promise<T> {
  return apiFetch<T>(path);
}

export function sendJson<T>(path: string, method: "POST" | "PUT" | "DELETE", body?: unknown): Promise<T> {
  return apiFetch<T>(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
