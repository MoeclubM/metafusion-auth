"use client";

import React, { useCallback, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ArrowLeft,
  KeyRound,
  LogOut,
  ScrollText,
  ServerCog,
  Shapes,
  ShieldCheck,
  Ticket,
  Users,
} from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useSession } from "@/lib/session";
import { can, canEnterAdmin, SECTION_PERMISSIONS, type SectionKey } from "@/lib/permissions";
import { logout } from "@/lib/endpoints";
import { stripBasePath } from "@/lib/paths";
import { LocaleSwitcher } from "./LocaleSwitcher";
import { ErrorNotice, ForbiddenBlock, LoadingBlock } from "./ui/blocks";

const NAV: { key: SectionKey; href: string; icon: React.ReactNode }[] = [
  { key: "users", href: "/", icon: <Users className="w-3.5 h-3.5" /> },
  { key: "groups", href: "/groups", icon: <Shapes className="w-3.5 h-3.5" /> },
  { key: "invites", href: "/invites", icon: <Ticket className="w-3.5 h-3.5" /> },
  { key: "oauth", href: "/oauth-clients", icon: <KeyRound className="w-3.5 h-3.5" /> },
  { key: "instance", href: "/instance", icon: <ServerCog className="w-3.5 h-3.5" /> },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  const { status, user, error, reload } = useSession();
  const pathname = stripBasePath(usePathname());
  const [signingOut, setSigningOut] = useState(false);

  const handleLogout = useCallback(async () => {
    setSigningOut(true);
    try {
      await logout();
    } catch {
      // 登出失败也要把用户带回主站：会话可能本来就已失效，卡在原页只会更困惑。
    } finally {
      window.location.href = "/";
    }
  }, []);

  const visibleNav = NAV.filter((item) => can(user, SECTION_PERMISSIONS[item.key]));

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-line-subtle bg-surface/70 backdrop-blur supports-[backdrop-filter]:bg-surface/50 sticky top-0 z-40">
        <div className="max-w-page mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <ShieldCheck className="w-5 h-5 text-primary shrink-0" />
            <div className="min-w-0">
              <div className="text-sm font-semibold text-text-strong truncate">{t("app.title")}</div>
              <div className="text-[10px] font-mono text-text-faint truncate">{t("app.subtitle")}</div>
            </div>
          </div>

          <div className="flex-1" />

          <LocaleSwitcher />

          <Link
            href="/"
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-chip bg-surfaceSubtle hover:bg-surfaceHover border border-line text-[11px] text-text-body transition-colors duration-fast ease-soft"
          >
            <ArrowLeft className="w-3 h-3" />
            <span>{t("app.backToSite")}</span>
          </Link>

          {user ? (
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-text-muted max-w-[10rem] truncate" title={user.username}>
                {user.username}
              </span>
              <button
                type="button"
                onClick={() => void handleLogout()}
                disabled={signingOut}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-chip bg-surfaceSubtle hover:bg-surfaceHover border border-line text-[11px] text-text-body transition-colors duration-fast ease-soft cursor-pointer disabled:opacity-50"
              >
                <LogOut className="w-3 h-3" />
                <span>{t("session.logout")}</span>
              </button>
            </div>
          ) : null}
        </div>

        {status === "ready" && canEnterAdmin(user) ? (
          <nav className="max-w-page mx-auto px-4 sm:px-6 pb-2 flex flex-wrap items-center gap-1.5">
            {visibleNav.map((item) => {
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.key}
                  href={item.href}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-control text-xs transition-colors duration-fast ease-soft ${
                    active
                      ? "bg-primary/15 text-primary font-semibold"
                      : "text-text-muted hover:text-text-strong hover:bg-surfaceSubtle"
                  }`}
                >
                  {item.icon}
                  <span>{t(`nav.${item.key}`)}</span>
                </Link>
              );
            })}
          </nav>
        ) : null}
      </header>

      <main className="flex-1 w-full max-w-page mx-auto px-4 sm:px-6 py-6 space-y-4">
        {status === "loading" ? <LoadingBlock /> : null}
        {status === "error" ? (
          <ErrorNotice message={error ?? t("session.failed")} onRetry={reload} permissionHint={t("session.failedHint")} />
        ) : null}
        {status === "ready" && !user ? (
          <div className="p-6 rounded-card bg-surfaceSubtle border border-line-subtle space-y-2">
            <div className="text-sm font-semibold text-text-strong">{t("session.loginRequiredTitle")}</div>
            <p className="text-[11px] text-text-muted leading-relaxed">{t("session.loginRequiredDesc")}</p>
          </div>
        ) : null}
        {status === "ready" && user && !canEnterAdmin(user) ? (
          <div className="space-y-3">
            <ForbiddenBlock permission={t("permission.anyAdminCode")} />
            <p className="text-[11px] text-text-faint font-mono leading-relaxed">{t("permission.adminCodes")}</p>
          </div>
        ) : null}
        {status === "ready" && user && canEnterAdmin(user) ? children : null}
      </main>

      <footer className="border-t border-line-subtle">
        <div className="max-w-page mx-auto px-4 sm:px-6 py-4 text-[10px] font-mono text-text-faint flex items-center gap-2">
          <ScrollText className="w-3 h-3" />
          <span>{t("app.footer")}</span>
        </div>
      </footer>
    </div>
  );
}
