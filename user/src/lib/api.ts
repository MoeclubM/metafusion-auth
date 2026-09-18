"use client";

// 账号自助应用的 API 唯一出口：同源 /api/*（网关按路径分流回账号服务）。
// 会话是账号服务签发的同域 Cookie mf_session（HttpOnly，前端读不到也不需要读）：
// 登录/注册成功即由服务端 Set-Cookie，后续请求 credentials:include 自动携带。
// 本应用不设 localStorage 令牌、不发 Authorization 头（冻结契约 v0.1 §1）。

import { APP_PATHS, LOGIN_PATH } from "./paths";

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    Object.setPrototypeOf(this, ApiError.prototype);
  }
}

export function readLocaleCookie(): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(/(?:^|;\s*)NEXT_LOCALE=([^;]+)/);
  return m ? decodeURIComponent(m[1]!) : null;
}

/** 当前页面地址，用于登录后跳回原处。 */
export function currentPath(): string {
  if (typeof window === "undefined") return "/";
  return window.location.pathname + window.location.search;
}

let loginRedirectIssued = false;

/**
 * 401 回跳登录页。自身就是登录/初始化应用：在自家页面上不跳转（由页面就地显示），
 * 只在其它同源路径上才拼 ?redirect= 回跳——避免 /login → /login 的自循环。
 */
export function redirectToLogin(): void {
  if (typeof window === "undefined" || loginRedirectIssued) return;
  loginRedirectIssued = true;
  const pathname = window.location.pathname;
  const insideApp = APP_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"));
  if (insideApp) {
    if (pathname !== LOGIN_PATH) window.location.href = LOGIN_PATH;
    return;
  }
  window.location.href = LOGIN_PATH + "?redirect=" + encodeURIComponent(currentPath());
}

export interface ApiOptions {
  redirectOn401?: boolean;
}

export async function apiFetch<T>(path: string, init: RequestInit = {}, options: ApiOptions = {}): Promise<T> {
  const headers: Record<string, string> = { ...((init.headers as Record<string, string> | undefined) ?? {}) };
  if (init.body != null && !(init.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
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
    const code = typeof body?.error === "string" && body.error ? body.error : "HTTP " + res.status;
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
