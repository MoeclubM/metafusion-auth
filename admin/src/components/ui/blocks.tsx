"use client";

// 各面板共用的呈现原语。取数失败一律用 ErrorNotice 如实显示并给重试，
// 权限不足用它而不是"空列表"——空列表会被读成"这里真的没有数据"。

import React from "react";
import { AlertTriangle, Inbox, Loader2, RefreshCw, ShieldAlert } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";

export function SectionHeader({
  icon,
  title,
  desc,
  actions,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 p-4 rounded-card bg-surfaceSubtle border border-line-subtle">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-text-strong flex items-center gap-2">
          {icon}
          <span>{title}</span>
        </h2>
        <p className="text-[11px] text-text-muted leading-relaxed mt-1 max-w-3xl">{desc}</p>
      </div>
      {actions ? <div className="flex items-center gap-2 shrink-0">{actions}</div> : null}
    </div>
  );
}

export function RefreshButton({ onClick, loading }: { onClick: () => void; loading: boolean }) {
  const { t } = useI18n();
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={loading}
      title={t("action.refresh")}
      aria-label={t("action.refresh")}
      className="p-2 rounded-control bg-surfaceSubtle hover:bg-surfaceHover border border-line text-text-body transition-colors duration-fast ease-soft cursor-pointer disabled:opacity-50"
    >
      <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-primary" : ""}`} />
    </button>
  );
}

export function ErrorNotice({
  message,
  onRetry,
  permissionHint,
}: {
  message: string;
  onRetry?: () => void;
  /** 中立的"本块需要什么权限"说明：无论 403 还是上游不可用都成立。 */
  permissionHint?: string;
}) {
  const { t } = useI18n();
  return (
    <div className="p-3 rounded-card bg-rose-500/10 border border-rose-500/30 space-y-2">
      <div className="flex items-start gap-2 text-rose-300 text-xs leading-relaxed">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
        <span>{message}</span>
      </div>
      {permissionHint ? <p className="text-[11px] text-rose-300/70 leading-relaxed">{permissionHint}</p> : null}
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="px-2.5 py-1 rounded-chip bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 text-[11px] font-medium transition-colors duration-fast ease-soft cursor-pointer"
        >
          {t("action.retry")}
        </button>
      ) : null}
    </div>
  );
}

/** 整块降级：当前身份没有进入这一块的权限码。页面不崩，只有本块换成这张卡。 */
export function ForbiddenBlock({ permission }: { permission: string }) {
  const { t } = useI18n();
  return (
    <div className="p-6 rounded-card bg-amber-500/[0.06] border border-amber-500/25 space-y-2">
      <div className="flex items-center gap-2 text-amber-300 text-sm font-semibold">
        <ShieldAlert className="w-4 h-4 shrink-0" />
        <span>{t("permission.deniedTitle")}</span>
      </div>
      <p className="text-[11px] text-amber-100/70 leading-relaxed">{t("permission.deniedDesc", { code: permission })}</p>
      <p className="text-[11px] text-amber-100/50 leading-relaxed">{t("permission.serverSideHint")}</p>
    </div>
  );
}

export function LoadingBlock() {
  const { t } = useI18n();
  return (
    <div className="py-10 text-center text-xs text-text-faint font-mono flex items-center justify-center gap-2">
      <Loader2 className="w-4 h-4 animate-spin text-primary" />
      <span>{t("state.loading")}</span>
    </div>
  );
}

export function EmptyBlock({ text }: { text?: string }) {
  const { t } = useI18n();
  return (
    <div className="p-6 rounded-card border border-dashed border-line text-center text-xs text-text-faint font-mono flex items-center justify-center gap-2">
      <Inbox className="w-4 h-4" />
      <span>{text ?? t("state.empty")}</span>
    </div>
  );
}

export function StatusMessage({ kind, text }: { kind: "ok" | "err"; text: string }) {
  return (
    <div
      role="status"
      className={`p-2.5 rounded-control text-[11px] font-mono leading-relaxed ${
        kind === "ok" ? "bg-emerald-500/15 text-emerald-300" : "bg-rose-500/20 text-rose-300"
      }`}
    >
      {text}
    </div>
  );
}

export function Chip({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "neutral" | "ok" | "warn" | "danger" }) {
  const tones: Record<string, string> = {
    neutral: "bg-surfaceSubtle text-text-muted border-line",
    ok: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    warn: "bg-amber-500/15 text-amber-300 border-amber-500/30",
    danger: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded-chip border text-[10px] font-mono ${tones[tone]}`}>
      {children}
    </span>
  );
}

export const inputClass =
  "w-full px-2.5 py-1.5 rounded-control bg-surfaceSubtle border border-line text-xs text-text-strong placeholder:text-text-faint focus:border-primary outline-none";
export const labelClass = "block text-[11px] font-mono text-text-body font-medium mb-1";
export const primaryButtonClass =
  "px-4 py-1.5 rounded-control bg-primary hover:bg-primary-hover text-white text-xs font-semibold transition-colors duration-fast ease-soft disabled:opacity-50 cursor-pointer";
