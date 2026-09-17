"use client";

import { useCallback, useEffect, useState } from "react";
import { useI18n } from "@/i18n/I18nProvider";
import { describeApiError } from "./errors";

export interface Resource<T> {
  loading: boolean;
  /** 已翻译的错误文案；null 表示这一次取数成功。 */
  error: string | null;
  /** HTTP 状态码，调用方据此区分 403 与上游不可用；非 HTTP 错误为 null。 */
  status: number | null;
  data: T;
  reload: () => void;
}

/**
 * 独立的只读资源加载器：**一个端点一个实例**。
 *
 * 管理面各接口所需的权限码不同（users / groups / invites / oauth / settings），
 * 任何一个 403 只应让它自己那一块降级，不能把整页拖黑——所以刻意不做"统一取数"。
 * loader 必须是稳定引用（直接传模块级函数），initial 必须是模块级常量，否则每次渲染都会重新取数。
 */
export function useResource<T>(
  loader: () => Promise<T>,
  initial: T,
  requiredPermission: string
): Resource<T> {
  const { t } = useI18n();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<number | null>(null);
  const [data, setData] = useState<T>(initial);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    loader()
      .then((next) => {
        if (!alive) return;
        setData(next);
        setError(null);
        setStatus(null);
      })
      .catch((err) => {
        // 失败时保留上一次成功的数据，但错误必须如实显示。
        if (!alive) return;
        setError(describeApiError(err, t, requiredPermission));
        setStatus(typeof err === "object" && err !== null ? ((err as { status?: number }).status ?? null) : null);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [loader, nonce, t, requiredPermission]);

  return { loading, error, status, data, reload };
}
