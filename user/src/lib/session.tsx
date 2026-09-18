"use client";

// 会话状态：账号服务签发的同域 Cookie 是唯一凭据，GET /api/auth/me 是唯一来源。
//
// 未登录或 401 → 跳主站登录页 /login?redirect=<当前路径>；其余错误不跳，就地显示并允许重试
// （账号服务不可达时把人赶去登录页只会更糟）。

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useI18n } from "@/i18n/I18nProvider";
import { redirectToLogin } from "./api";
import { fetchMe, type MeUser } from "./endpoints";
import { describeApiError } from "./errors";

export type SessionStatus = "loading" | "ready" | "error";

interface SessionCtx {
  status: SessionStatus;
  user: MeUser | null;
  error: string | null;
  reload: () => void;
}

const Ctx = createContext<SessionCtx>({ status: "loading", user: null, error: null, reload: () => {} });

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  const [status, setStatus] = useState<SessionStatus>("loading");
  const [user, setUser] = useState<MeUser | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let alive = true;
    setStatus("loading");
    fetchMe()
      .then((me) => {
        if (!alive) return;
        setUser(me);
        setError(null);
        setStatus("ready");
      })
      .catch((err) => {
        if (!alive) return;
        // 探活请求自己处理 401：fetchMe 传 redirectOn401=false，这里才决定跳不跳。
        if (typeof err === "object" && err !== null && (err as { status?: number }).status === 401) {
          setStatus("ready");
          setUser(null);
          redirectToLogin();
          return;
        }
        setError(describeApiError(err, t, "auth.users.manage"));
        setStatus("error");
      });
    return () => {
      alive = false;
    };
  }, [nonce, t]);

  const value = useMemo<SessionCtx>(() => ({ status, user, error, reload }), [status, user, error, reload]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession() {
  return useContext(Ctx);
}
