"use client";

// 自助面契约的薄封装（Cookie 会话口径）：登录/注册/初始化成功后凭据已在 Cookie 里，
// 身份一律再读 GET /api/auth/me（唯一来源），不消费响应体里的令牌字段。

import { ApiError, apiFetch, getJson, sendJson } from "./api";

/** /api/auth/me 的账号投影；password_hash 永不出现在 JSON 里。 */
export interface MeUser {
  id: string;
  username: string;
  email?: string;
  role?: string;
  groups?: string[];
  permissions?: string[];
  banned?: boolean;
}

export interface SetupStatusResponse {
  is_initialized: boolean;
  has_admin: boolean;
  total_users: number;
}

export interface PublicAuthSettings {
  registration_enabled: boolean;
  invite_required: boolean;
  require_email_verification: boolean;
  email_verification_enabled: boolean;
  rate_limit_enabled?: boolean;
  auth_rate_limit_enabled?: boolean;
}

export interface AuthSession {
  user: MeUser;
}

/** 探活：401 的处置权交给调用方（登录页就地处理），这里不抢先跳。 */
export function fetchMe(): Promise<MeUser> {
  return apiFetch<MeUser>("/api/auth/me", {}, { redirectOn401: false });
}

export function logout(): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>("/api/auth/logout", "POST");
}

export function fetchAuthSettings(): Promise<PublicAuthSettings> {
  return getJson<PublicAuthSettings>("/api/auth/settings");
}

export async function fetchSetupStatus(): Promise<SetupStatusResponse> {
  try {
    const res = await fetch("/api/setup", { credentials: "include" });
    if (res.ok) {
      const data = await res.json();
      return { is_initialized: !data.needed, has_admin: !data.needed, total_users: 1 };
    }
  } catch {}
  return { is_initialized: true, has_admin: true, total_users: 1 };
}

/**
 * 登录 / 注册直调（不用 apiFetch）：401 在这里是预期的凭据失败（错误码 invalid_credentials
 * / login_blocked + Retry-After），必须把服务端原码透给调用方做文案映射，不能收敛成
 * authentication_required——那是会话探活才用的码。Cookie 由服务端 Set-Cookie 下发。
 */
async function postAuth<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const code =
      typeof (data as { error?: unknown }).error === "string" && (data as { error: string }).error
        ? (data as { error: string }).error
        : "request_failed";
    const failed = new ApiError(code, res.status);
    (failed as Error & { retryAfter?: string }).retryAfter = res.headers.get("Retry-After") || undefined;
    throw failed;
  }
  return data as T;
}

/** 登录：成功即建会话（Cookie），身份以随后一次 /me 为准。 */
export async function loginAccount(input: { username: string; password: string }): Promise<AuthSession> {
  await postAuth<unknown>("/api/auth/login", input);
  return { user: await fetchMe() };
}

/** 注册：成功即建会话（Cookie），同样以 /me 为准。 */
export async function registerAccount(input: {
  username: string;
  email?: string;
  password: string;
  invite_code?: string;
}): Promise<AuthSession> {
  await postAuth<unknown>("/api/auth/register", input);
  return { user: await fetchMe() };
}

export interface InitialSetupPayload {
  username: string;
  email: string;
  password: string;
}

/** 首次初始化：POST /api/setup 只收 username/email/password 三字段，随后走登录闭环。 */
export async function performInitialSetup(payload: InitialSetupPayload): Promise<AuthSession> {
  const setupRes = await fetch("/api/setup", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: payload.username,
      email: payload.email,
      password: payload.password,
    }),
  });
  if (!setupRes.ok) {
    const err = await setupRes.json().catch(() => ({} as { error?: unknown }));
    throw new Error(typeof err.error === "string" && err.error ? err.error : "setup_failed");
  }
  return loginAccount({ username: payload.username, password: payload.password });
}
