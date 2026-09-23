"use client";

// 自助登录/注册页：Cookie 会话口径（冻结契约 v0.1 §1）。
// 与主站 frontend/src/app/login/page.tsx 同流程：setup 门控、实例设置门控、邀请码、
// ?notice= 白名单、凭据错误映射；差异仅三处：
//  1. 会话经 useSession（mf_session Cookie + /me），不写 localStorage；
//  2. 外部 SSO 分支（AUTH_PAGES_ENABLED）与 ?token= 回跳已随拆分删除——本应用就是登录页；
//  3. ThemePicker 暂不搬运（换肤上下文是主站共享层），首版只留 LocaleSwitcher。

import React, { useEffect, useState, Suspense } from "react";
import { LoadingFallback } from "@/components/common/LoadingFallback";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { useSession } from "@/lib/session";
import { safeLoginRedirect } from "@/lib/redirect";
import {
  fetchSetupStatus,
  fetchAuthSettings,
  registerAccount,
  loginAccount,
  PublicAuthSettings,
} from "@/lib/endpoints";
import { authErrorText, httpStatusOf, httpRetryAfterSecondsOf } from "@/lib/authErrors";
import { useI18n } from "@/i18n/I18nProvider";
import { BrandMark } from "@/components/Logo";
import { PageContainer } from "@/components/ui/PageShell";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";
import {
  User,
  Mail,
  Lock,
  KeyRound,
  ArrowRight,
  AlertCircle,
  Sparkles,
  Eye,
  EyeOff,
} from "lucide-react";

type AuthMode = "login" | "register";

const LOGIN_NOTICES: Record<string, string> = {
  password_changed: "auth.passwordChangedSignedOut",
  sessions_revoked: "auth.sessionsRevokedSignedOut",
};

const inputClass =
  "w-full pl-11 pr-3.5 h-11 max-sm:min-h-[44px] bg-black/[0.03] dark:bg-black/20 border border-line rounded-control text-text-strong text-sm placeholder:text-text-muted focus:outline-none focus:border-primary";

const passwordInputClass = inputClass.replace("pr-3.5", "pr-11");

const USERNAME_MAX_LENGTH = 80;

function LoginInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, status, reload } = useSession();
  const { t } = useI18n();

  const tabParam = searchParams.get("tab");
  const inviteParam = searchParams.get("invite") || "";

  const [mode, setMode] = useState<AuthMode>("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [inviteCode, setInviteCode] = useState(inviteParam);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [hasAdmin, setHasAdmin] = useState<boolean | null>(null);
  const [authSettings, setAuthSettings] = useState<PublicAuthSettings | null>(null);
  const [settingsState, setSettingsState] = useState<"loading" | "ready" | "unavailable">("loading");

  useEffect(() => {
    fetchSetupStatus()
      .then((s) => setHasAdmin(s.has_admin))
      .catch(() => setHasAdmin(true));
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchAuthSettings()
      .then((s) => {
        if (cancelled) return;
        setAuthSettings(s);
        setSettingsState("ready");
        const wantsRegister = tabParam === "register" || inviteParam !== "";
        if (!wantsRegister) return;
        if (s.registration_enabled === false) {
          setNotice(t("auth.registrationClosed"));
          return;
        }
        setMode("register");
      })
      .catch(() => {
        if (cancelled) return;
        setSettingsState("unavailable");
        if (tabParam === "register" || inviteParam !== "") setMode("register");
      });
    return () => {
      cancelled = true;
    };
  }, [t, tabParam, inviteParam]);

  useEffect(() => {
    const code = searchParams.get("notice");
    const key = code ? LOGIN_NOTICES[code] : undefined;
    if (key) setNotice(t(key));
  }, [searchParams, t]);

  useEffect(() => {
    if (status !== "loading" && user) {
      const redirectUrl = safeLoginRedirect(searchParams.get("redirect"));
      router.replace(redirectUrl);
    }
  }, [status, user, router, searchParams]);

  const registrationClosed = authSettings?.registration_enabled === false;
  const inviteRequired = authSettings?.invite_required === true;
  const showInviteField = inviteRequired || inviteCode !== "";

  const switchTo = (next: AuthMode) => {
    setError(null);
    setNotice(null);
    setPasswordVisible(false);
    if (next === "register" && hasAdmin === false) {
      router.push("/setup");
      return;
    }
    if (next === "register" && registrationClosed) {
      setNotice(t("auth.registrationClosed"));
      return;
    }
    setMode(next);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      const redirectUrl = safeLoginRedirect(searchParams.get("redirect"));
      if (mode === "register") {
        await registerAccount({
          username: username.trim(),
          email: email.trim(),
          password,
          invite_code: inviteCode.trim() || undefined,
        });
        reload();
        router.replace(redirectUrl);
        return;
      }
      await loginAccount({ username: username.trim(), password });
      reload();
      router.replace(redirectUrl);
    } catch (err: unknown) {
      const e = err as { message?: string; status?: number; retryAfter?: string };
      setError(authErrorText(e?.message, t, httpStatusOf(err), undefined, httpRetryAfterSecondsOf(err)));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="h-[100dvh] max-h-[100dvh] overflow-hidden bg-background relative flex flex-col p-4 sm:p-5">
      <PageContainer as="header" width="narrow" className="relative z-10 shrink-0">
        <div className="flex items-center justify-between gap-4">
          <Link href="/" title="MetaFusion" className="flex items-center gap-2.5 group">
            <BrandMark size={28} idSuffix="login" />
            <span className="font-display text-xl tracking-[-0.03em] text-text-strong">MetaFusion</span>
          </Link>
          <div className="flex items-center gap-2">
            <LocaleSwitcher />
          </div>
        </div>
      </PageContainer>

      <PageContainer as="main" width="narrow" className="mf-enter relative z-10 flex-1 min-h-0 grid place-items-center py-3">
        <div className="w-full max-w-md max-h-full overflow-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden space-y-3">
          {hasAdmin === false && (
            <Link
              href="/setup"
              className="p-3.5 rounded-panel bg-primary/10 border border-primary/25 text-primary text-xs font-mono font-medium flex items-center justify-between gap-2 hover:bg-primary/15 transition-colors duration-fast group mf-focus"
            >
              <div className="flex items-center gap-2 min-w-0">
                <Sparkles className="w-4 h-4 shrink-0 text-primary animate-pulse" />
                <span className="truncate">{t("login.oobeBanner")}</span>
              </div>
              <ArrowRight className="w-4 h-4 shrink-0 group-hover:translate-x-0.5 transition-transform duration-base ease-soft" />
            </Link>
          )}
          <div className="rounded-card border border-line bg-surface shadow-soft overflow-hidden animate-scale-in">
            <div className="p-4 sm:p-5 pb-3 border-b border-line-subtle">
              <div className="min-w-0">
                <h1 className="font-display text-xl sm:text-2xl font-bold tracking-tight text-text-strong">
                  {mode === "register" ? t("auth.joinTitle") : t("auth.welcomeBack")}
                </h1>
                <p className="font-mono text-sm text-text-muted mt-0.5">
                  {mode === "register" ? t("auth.joinSubtitle") : t("auth.loginSubtitle")}
                </p>
              </div>
              <div className="flex gap-2 mt-3.5 bg-black/[0.04] dark:bg-white/[0.04] p-1 rounded-lg border border-line-subtle">
                <button
                  type="button"
                  onClick={() => switchTo("login")}
                  className={"flex-1 py-2 rounded-md text-sm font-medium transition-colors duration-fast mf-focus " + (mode === "login" ? "bg-surface text-text-strong shadow-xs font-semibold" : "text-text-muted hover:text-text-strong")}
                >
                  {t("nav.login")}
                </button>
                <button
                  type="button"
                  onClick={() => switchTo("register")}
                  className={"flex-1 py-2 rounded-md text-sm font-medium transition-colors duration-fast mf-focus " + (mode === "register" ? "bg-surface text-text-strong shadow-xs font-semibold" : "text-text-muted hover:text-text-strong") + (registrationClosed ? " opacity-60" : "")}
                >
                  {t("auth.gate.genesisRegister")}
                </button>
              </div>
            </div>
            {error && (
              <div className="mx-4 sm:mx-5 mt-3.5 p-3.5 rounded-control bg-red-500/10 border border-red-500/20 text-red-500 dark:text-danger-soft font-mono text-sm flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            {notice && (
              <div className="mx-4 sm:mx-5 mt-3.5 p-3.5 rounded-control bg-amber-500/10 border border-amber-500/20 text-amber-600 dark:text-warn-soft font-mono text-sm flex items-start gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                <span className="min-w-0">{notice}</span>
              </div>
            )}
            <form onSubmit={handleSubmit} className="p-4 sm:p-6 space-y-4">
              <div className="space-y-1.5">
                <label htmlFor="login-username" className="font-mono text-xs sm:text-sm text-text-muted">
                  {mode === "register" ? t("auth.username") : t("auth.gate.emailOrUsername")}
                </label>
                <div className="relative">
                  <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" strokeWidth={1.5} />
                  <input
                    id="login-username"
                    type="text"
                    required
                    maxLength={mode === "register" ? USERNAME_MAX_LENGTH : undefined}
                    autoComplete="username"
                    placeholder={mode === "register" ? t("auth.gate.usernamePlaceholderRegister") : t("auth.gate.usernamePlaceholderLogin")}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className={inputClass}
                  />
                </div>
              </div>
              {mode === "register" && (
                <div className="space-y-1.5 animate-fade-in">
                  <label htmlFor="login-email" className="font-mono text-xs sm:text-sm text-text-muted">{t("auth.email")}</label>
                  <div className="relative">
                    <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" strokeWidth={1.5} />
                    <input
                      id="login-email"
                      type="email"
                      required
                      autoComplete="email"
                      placeholder={t("auth.emailPlaceholder")}
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className={inputClass}
                    />
                  </div>
                </div>
              )}
              <div className="space-y-1.5">
                <label htmlFor="login-password" className="font-mono text-xs sm:text-sm text-text-muted flex items-center justify-between gap-2">
                  <span>{t("auth.password")}</span>
                  {mode === "register" && (
                    <span className="text-xs text-text-faint font-normal">{t("auth.registerPasswordHint")}</span>
                  )}
                </label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" strokeWidth={1.5} />
                  <input
                    id="login-password"
                    type={passwordVisible ? "text" : "password"}
                    required
                    minLength={mode === "register" ? 12 : undefined}
                    maxLength={72}
                    autoComplete={mode === "register" ? "new-password" : "current-password"}
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className={passwordInputClass}
                  />
                  <button
                    type="button"
                    onClick={() => setPasswordVisible((v) => !v)}
                    aria-label={passwordVisible ? t("auth.passwordHide") : t("auth.passwordShow")}
                    aria-pressed={passwordVisible}
                    aria-controls="login-password"
                    title={passwordVisible ? t("auth.passwordHide") : t("auth.passwordShow")}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 w-9 h-9 max-sm:min-h-[44px] max-sm:h-11 grid place-items-center rounded-control text-text-muted hover:text-text-strong hover:bg-black/[0.04] dark:hover:bg-white/[0.06] transition-colors duration-fast mf-focus cursor-pointer"
                  >
                    {passwordVisible ? <EyeOff className="w-4 h-4" strokeWidth={1.5} aria-hidden="true" /> : <Eye className="w-4 h-4" strokeWidth={1.5} aria-hidden="true" />}
                  </button>
                </div>
              </div>
              {mode === "register" && showInviteField && (
                <div className="space-y-1.5 animate-fade-in">
                  <label htmlFor="login-invite-code" className="font-mono text-xs sm:text-sm text-amber-600 dark:text-warn-soft flex items-center justify-between gap-2">
                    <span>{t("auth.inviteCode")}</span>
                    <span className="text-xs text-text-faint font-normal">
                      {inviteRequired ? t("auth.required") : t("auth.optional")}
                    </span>
                  </label>
                  <div className="relative">
                    <KeyRound className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-amber-500" strokeWidth={1.5} />
                    <input
                      id="login-invite-code"
                      type="text"
                      required={inviteRequired}
                      placeholder={t("auth.inviteCodePlaceholder")}
                      value={inviteCode}
                      onChange={(e) => setInviteCode(e.target.value)}
                      className="w-full pl-11 pr-3.5 h-11 max-sm:min-h-[44px] bg-black/[0.03] dark:bg-black/20 border border-amber-500/30 rounded-control text-amber-600 dark:text-warn-soft font-mono text-sm placeholder:text-text-faint focus:outline-none focus:border-amber-400"
                    />
                  </div>
                </div>
              )}
              {mode === "register" && settingsState === "unavailable" && (
                <p className="font-mono text-xs text-text-faint">{t("auth.settingsUnavailable")}</p>
              )}
              <button
                type="submit"
                disabled={submitting}
                className="w-full h-11 max-sm:min-h-[44px] rounded-control bg-primary text-white keep-white font-semibold text-sm flex items-center justify-center gap-2 hover:opacity-90 transition-opacity duration-fast shadow-xs disabled:opacity-50 mt-2 mf-focus"
              >
                {submitting ? (
                  <div className="w-4 h-4 border-2 border-emphasis/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <>
                    <span>{mode === "register" ? t("auth.gate.createAccount") : t("auth.gate.secureLogin")}</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>
          </div>
        </div>
      </PageContainer>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<LoadingFallback className="h-[100dvh] bg-background grid place-items-center font-mono text-sm text-text-faint" />}>
      <LoginInner />
    </Suspense>
  );
}
