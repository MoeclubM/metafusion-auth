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
import { ThemeModeSwitcher } from "./ThemeModeSwitcher";
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
      <header className="sticky top-0 z-30 border-b border-line bg-surface/90 backdrop-blur">
        <div className="mx-auto flex h-14 w-full max-w-page items-center justify-between gap-3 px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <a href="/admin" className="inline-flex shrink-0 items-center gap-1 text-xs text-text-muted hover:text-text-strong"><ArrowLeft className="h-4 w-4" />{t("app.backToHub")}</a>
            <span className="text-text-faint">/</span>
            <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-text-strong"><ShieldCheck className="h-4 w-4 shrink-0 text-primary" /><span className="truncate">{t("app.title")}</span></div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <LocaleSwitcher />
            <ThemeModeSwitcher />
            {user ? <span className="hidden max-w-[9rem] truncate rounded border border-primary/30 bg-primary/20 px-2 py-0.5 font-mono text-xs text-primary sm:inline-flex" title={user.username}>{user.username}</span> : null}
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
              {user ? <button type="button" onClick={() => void handleLogout()} disabled={signingOut} className="mt-3 inline-flex items-center gap-2 text-xs text-text-muted disabled:opacity-50"><LogOut className="h-4 w-4" />{t("session.logout")}</button> : null}
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
              {user ? <button type="button" onClick={() => void handleLogout()} disabled={signingOut} className="mt-2 flex w-full items-center gap-3 border-t border-line-subtle px-3 py-3 text-left text-xs text-text-muted hover:text-text-strong disabled:opacity-50"><LogOut className="h-4 w-4" />{t("session.logout")}</button> : null}
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
