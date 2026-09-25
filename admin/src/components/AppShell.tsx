"use client";

import React, { useCallback, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  ArrowLeft, FileClock, KeyRound, LogOut, ScrollText, ServerCog,
  Shapes, ShieldCheck, Ticket, Users,
} from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useSession } from "@/lib/session";
import { can, canEnterAdmin, SECTION_PERMISSIONS, type SectionKey } from "@/lib/permissions";
import { logout } from "@/lib/endpoints";
import { stripBasePath } from "@/lib/paths";
import { LocaleSwitcher } from "./LocaleSwitcher";
import { ErrorNotice, ForbiddenBlock, LoadingBlock } from "./ui/blocks";

const NAV_GROUPS: { labelKey: string; items: { key: SectionKey; href: string; icon: React.ReactNode }[] }[] = [
  { labelKey: "nav.groupIdentity", items: [
    { key: "users", href: "/", icon: <Users className="h-4 w-4" /> },
    { key: "groups", href: "/groups", icon: <Shapes className="h-4 w-4" /> },
    { key: "invites", href: "/invites", icon: <Ticket className="h-4 w-4" /> },
  ] },
  { labelKey: "nav.groupSystem", items: [
    { key: "oauth", href: "/oauth-clients", icon: <KeyRound className="h-4 w-4" /> },
    { key: "audit", href: "/audit", icon: <FileClock className="h-4 w-4" /> },
    { key: "instance", href: "/instance", icon: <ServerCog className="h-4 w-4" /> },
  ] },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  const { status, user, error, reload } = useSession();
  const router = useRouter();
  const pathname = stripBasePath(usePathname());
  const [signingOut, setSigningOut] = useState(false);

  const handleLogout = useCallback(async () => {
    setSigningOut(true);
    try { await logout(); } catch { /* 会话失效时仍返回主站。 */ }
    finally { window.location.href = "/"; }
  }, []);

  const visibleGroups = NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => can(user, SECTION_PERMISSIONS[item.key])),
  })).filter((group) => group.items.length > 0);
  const visibleNav = visibleGroups.flatMap((group) => group.items);
  const activeHref = visibleNav.find((item) => item.href === "/" ? pathname === "/" : pathname.startsWith(item.href))?.href ?? visibleNav[0]?.href;

  return (
    <div className="min-h-screen flex flex-col bg-background text-text-strong">
      <header className="border-b border-line-subtle bg-surface/90 backdrop-blur sticky top-0 z-40">
        <div className="max-w-page mx-auto px-4 sm:px-6 min-h-16 flex flex-wrap items-center gap-3 py-2">
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-control bg-primary/10 text-primary"><ShieldCheck className="h-5 w-5" /></span>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-text-strong truncate">{t("app.title")}</div>
              <div className="text-[11px] text-text-muted truncate">{t("app.subtitle")}</div>
            </div>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <LocaleSwitcher />
            <a href="/admin" className="inline-flex items-center gap-1.5 px-3 py-2 rounded-control border border-line text-xs text-text-body hover:bg-surfaceHover">
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />{t("app.backToHub")}
            </a>
            {user ? (
              <>
                <span className="hidden max-w-[9rem] truncate text-xs text-text-muted sm:inline" title={user.username}>{user.username}</span>
                <button type="button" onClick={() => void handleLogout()} disabled={signingOut} className="inline-flex items-center gap-1.5 px-3 py-2 rounded-control border border-line text-xs text-text-body hover:bg-surfaceHover disabled:opacity-50">
                  <LogOut className="h-4 w-4" aria-hidden="true" />{t("session.logout")}
                </button>
              </>
            ) : null}
          </div>
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-page flex-1 flex-col gap-6 px-4 py-6 sm:px-6 lg:flex-row">
        {status === "ready" && canEnterAdmin(user) && visibleNav.length > 0 ? (
          <aside className="w-full shrink-0 lg:w-56">
            <div className="lg:hidden rounded-card border border-line-subtle bg-surfaceSubtle p-3">
              <label htmlFor="account-admin-section" className="mb-2 block text-xs font-medium text-text-muted">{t("nav.section")}</label>
              <select id="account-admin-section" value={activeHref} onChange={(e) => router.push(e.target.value)} className="w-full rounded-control border border-line bg-surface px-3 py-2.5 text-sm text-text-strong">
                {visibleGroups.map((group) => (
                  <optgroup key={group.labelKey} label={t(group.labelKey)}>
                    {group.items.map((item) => <option key={item.key} value={item.href}>{t(`nav.${item.key}`)}</option>)}
                  </optgroup>
                ))}
              </select>
            </div>
            <nav aria-label={t("nav.section")} className="hidden lg:block sticky top-24 rounded-card border border-line-subtle bg-surfaceSubtle p-2">
              {visibleGroups.map((group) => (
                <div key={group.labelKey} className="py-1 first:pt-0 last:pb-0">
                  <div className="px-3 py-2 text-[11px] font-semibold tracking-wide text-text-faint">{t(group.labelKey)}</div>
                  {group.items.map((item) => {
                    const active = activeHref === item.href;
                    return <Link key={item.key} href={item.href} aria-current={active ? "page" : undefined} className={`flex items-center gap-3 rounded-control px-3 py-2.5 text-sm transition-colors ${active ? "bg-primary/15 font-semibold text-primary" : "text-text-muted hover:bg-surfaceHover hover:text-text-strong"}`}>
                      {item.icon}<span>{t(`nav.${item.key}`)}</span>
                    </Link>;
                  })}
                </div>
              ))}
            </nav>
          </aside>
        ) : null}

        <main className="min-w-0 flex-1 space-y-4">
          {status === "loading" ? <LoadingBlock /> : null}
          {status === "error" ? <ErrorNotice message={error ?? t("session.failed")} onRetry={reload} permissionHint={t("session.failedHint")} /> : null}
          {status === "ready" && !user ? (
            <div className="p-6 rounded-card bg-surfaceSubtle border border-line-subtle space-y-2">
              <div className="text-sm font-semibold text-text-strong">{t("session.loginRequiredTitle")}</div>
              <p className="text-xs text-text-muted leading-relaxed">{t("session.loginRequiredDesc")}</p>
            </div>
          ) : null}
          {status === "ready" && user && !canEnterAdmin(user) ? (
            <div className="space-y-3">
              <ForbiddenBlock permission={t("permission.anyAdminCode")} />
              <p className="text-xs text-text-faint leading-relaxed">{t("permission.adminCodes")}</p>
            </div>
          ) : null}
          {status === "ready" && user && canEnterAdmin(user) ? children : null}
        </main>
      </div>

      <footer className="border-t border-line-subtle">
        <div className="max-w-page mx-auto px-4 sm:px-6 py-4 text-[10px] font-mono text-text-faint flex items-center gap-2">
          <ScrollText className="w-3 h-3" /><span>{t("app.footer")}</span>
        </div>
      </footer>
    </div>
  );
}
