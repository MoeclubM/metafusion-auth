"use client";

// 首次初始化页。账号服务完成初始化后签发同源 HttpOnly Cookie，会话通过 /me 同步。

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  fetchSetupStatus,
  performInitialSetup,
  SetupStatusResponse,
  MeUser,
} from "@/lib/endpoints";
import { useSession } from "@/lib/session";
import { useI18n } from "@/i18n/I18nProvider";
import { BrandMark } from "@/components/Logo";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";
import {
  Server,
  User,
  Mail,
  Lock,
  Eye,
  EyeOff,
  KeyRound,
  CheckCircle2,
  AlertCircle,
  ArrowRight,
  Loader2,
  Sparkles,
} from "lucide-react";
import { PageShell, PageContainer } from "@/components/ui/PageShell";

export default function SetupPage() {
  const { reload } = useSession();
  const { t } = useI18n();

  const [status, setStatus] = useState<SetupStatusResponse | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successResult, setSuccessResult] = useState<{ user: MeUser } | null>(null);

  useEffect(() => {
    fetchSetupStatus()
      .then((res) => {
        setStatus(res);
      })
      .catch(() => {
        setStatus({
          is_initialized: false,
          has_admin: false,
          total_users: 0,
        });
      })
      .finally(() => {
        setLoadingStatus(false);
      });
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const trimmedUser = username.trim();
    const trimmedEmail = email.trim();
    if (!trimmedUser || !trimmedEmail) {
      setError(t("setup.requiredMissing", { fields: t("setup.usernameLabel") + " / " + t("setup.emailLabel") }));
      return;
    }
    if (password.length < 12 || password.length > 72) {
      setError(t("auth.error.invalid_password_length"));
      return;
    }
    if (password !== confirmPassword) {
      setError(t("setup.passwordsMismatch"));
      return;
    }
    setSubmitting(true);
    try {
      const res = await performInitialSetup({
        username: trimmedUser,
        email: trimmedEmail,
        password,
      });
      reload();
      setSuccessResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("setup.setupFailed"));
    } finally {
      setSubmitting(false);
    }
  };

  if (loadingStatus) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center font-mono text-sm text-text-faint">
        <Loader2 className="w-8 h-8 animate-spin text-primary mb-3" />
        <span>{t("common.loading")}</span>
      </div>
    );
  }

  if (status?.is_initialized && !successResult) {
    return (
      <div className="min-h-screen bg-background relative flex flex-col items-center justify-center p-6 selection:bg-primary selection:text-white">
        <div className="w-full max-w-md p-8 rounded-2xl bg-card border border-border shadow-2xl text-center space-y-6 animate-fade-in">
          <div className="space-y-2">
            <h1 className="text-2xl font-extrabold text-text-strong font-mono">
              {t("setup.notFoundTitle")}
            </h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">
              {t("setup.notFoundDesc")}
            </p>
          </div>
          <Link
            href="/"
            className="inline-flex items-center justify-center px-6 h-11 rounded-xl bg-primary text-white keep-white font-semibold text-sm hover:opacity-90 transition-all shadow-md cursor-pointer"
          >
            <span>{t("setup.goToHome")}</span>
          </Link>
        </div>
      </div>
    );
  }

  if (successResult) {
    return (
      <div className="min-h-screen bg-background relative flex flex-col items-center justify-center p-6 selection:bg-primary selection:text-white">
        <div className="absolute top-5 right-5 z-20 flex items-center gap-2">
          <LocaleSwitcher />
        </div>
        <div className="w-full max-w-lg p-8 rounded-3xl bg-card border border-emerald-500/30 shadow-2xl text-center space-y-6 animate-scale-up relative overflow-hidden">
          <div className="absolute -top-24 -right-24 w-48 h-48 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="w-20 h-20 rounded-3xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-500 grid place-items-center mx-auto shadow-lg shadow-emerald-500/10">
            <CheckCircle2 className="w-10 h-10" />
          </div>
          <div className="space-y-2">
            <div className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-success font-mono text-xs font-semibold">
              <Sparkles className="w-3.5 h-3.5" />
              <span>OOBE READY</span>
            </div>
            <h1 className="text-3xl font-extrabold text-text-strong tracking-tight">
              {t("setup.successTitle")}
            </h1>
            <p className="text-sm text-text-body leading-relaxed max-w-md mx-auto">
              {t("setup.successDesc")}
            </p>
          </div>
          <div className="p-4 rounded-2xl bg-surfaceSubtle border border-line font-mono text-xs text-left space-y-2">
            <div className="flex justify-between items-center text-text-faint">
              <span>Admin Username:</span>
              <span className="font-bold text-text-strong">{successResult.user.username}</span>
            </div>
            <div className="flex justify-between items-center text-text-faint">
              <span>Admin Email:</span>
              <span className="font-bold text-text-strong">{successResult.user.email || email}</span>
            </div>
            <div className="flex justify-between items-center text-text-faint">
              <span>Admin Role:</span>
              <span className="text-primary font-bold">{successResult.user.role}</span>
            </div>
          </div>
          <div className="flex flex-col sm:flex-row gap-3 pt-2">
            <Link
              href="/admin"
              className="flex-1 inline-flex items-center justify-center gap-2 h-12 rounded-xl bg-primary text-white keep-white font-semibold text-sm hover:opacity-90 transition-all shadow-lg shadow-primary/25 cursor-pointer"
            >
              <span>{t("setup.enterAdmin")}</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/"
              className="flex-1 inline-flex items-center justify-center gap-2 h-12 rounded-xl dark:bg-white/[0.06] border border-line text-text-strong hover:bg-black/10 dark:hover:bg-white/[0.12] font-medium text-sm transition-all cursor-pointer"
            >
              <span>{t("setup.enterHome")}</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background relative flex flex-col justify-between overflow-clip p-4 sm:p-8 selection:bg-primary selection:text-white">
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-primary/8 rounded-full blur-[140px] pointer-events-none" />
      <aside className="absolute top-5 right-5 z-20 flex items-center gap-2">
        <LocaleSwitcher />
      </aside>
      <PageContainer as="header" width="narrow" className="relative z-10 pt-6 text-center space-y-4">
        <div className="inline-block relative">
          <BrandMark size={56} withGlow={true} idSuffix="setup-header" className="mx-auto drop-shadow-md" />
        </div>
        <div className="space-y-1.5">
          <div className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-primary font-semibold">
            <Server className="w-3.5 h-3.5" />
            <span>{t("setup.tagline")}</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-text-strong">
            {t("setup.title")}
          </h1>
          <p className="text-sm text-gray-600 dark:text-gray-400 max-w-lg mx-auto">
            {t("setup.subtitle")}
          </p>
        </div>
      </PageContainer>
      <PageShell width="narrow" spacing="none" className="my-8">
        <form
          onSubmit={handleSubmit}
          className="p-6 sm:p-8 rounded-3xl bg-card border border-border shadow-2xl space-y-8"
        >
          <div className="p-4 rounded-2xl bg-primary/5 border border-primary/20 flex items-start gap-3.5">
            <Server className="w-5 h-5 text-primary shrink-0 mt-0.5" />
            <div className="text-xs space-y-0.5">
              <div className="font-bold text-text-strong">
                {t("setup.instanceHealthy")}
              </div>
              <div className="text-text-muted">
                {t("setup.instanceHealthyDesc")}
              </div>
            </div>
          </div>
          <div className="space-y-4">
            <div className="border-b border-border pb-2.5 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-primary" />
              <h2 className="font-bold text-sm text-text-strong uppercase tracking-wider font-mono">
                {t("setup.adminSectionTitle")}
              </h2>
            </div>
            <p className="text-xs text-text-faint">
              {t("setup.adminSectionDesc")}
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-text-body mb-1.5">
                  {t("setup.usernameLabel")} <span className="text-rose-500">*</span>
                </label>
                <div className="relative">
                  <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={t("setup.usernamePlaceholder")}
                    className="w-full h-11 pl-10 pr-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.04] border border-line text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                  />
                </div>
              </div>
              <div className="sm:col-span-2">
                <label className="block text-xs font-semibold text-text-body mb-1.5">
                  {t("setup.emailLabel")} <span className="text-rose-500">*</span>
                </label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder={t("setup.emailPlaceholder")}
                    className="w-full h-11 pl-10 pr-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.04] border border-line text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-text-body mb-1.5">
                  {t("setup.passwordLabel")} <span className="text-rose-500">*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    minLength={12}
                    maxLength={72}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={t("setup.passwordPlaceholder12")}
                    className="w-full h-11 pl-10 pr-10 rounded-xl bg-black/[0.02] dark:bg-white/[0.04] border border-line text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-gray-600 dark:hover:text-gray-200"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-text-body mb-1.5">
                  {t("setup.confirmPasswordLabel")} <span className="text-rose-500">*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    minLength={12}
                    maxLength={72}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder={t("setup.confirmPasswordPlaceholder")}
                    className="w-full h-11 pl-10 pr-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.04] border border-line text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                  />
                </div>
              </div>
            </div>
          </div>
          <div className="p-4 rounded-2xl bg-surfaceSubtle border border-line flex items-start gap-3">
            <AlertCircle className="w-4 h-4 text-text-muted shrink-0 mt-0.5" />
            <div className="text-xs space-y-0.5">
              <div className="font-bold text-text-strong">
                {t("setup.siteSettingsTitle")}
              </div>
              <div className="text-text-faint">
                {t("catalog.unavailable")}
              </div>
            </div>
          </div>
          {error && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/25 text-rose-600 dark:text-danger text-xs font-mono flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="w-full h-12 rounded-2xl bg-primary text-white keep-white font-semibold text-sm hover:opacity-95 active:scale-[0.99] transition-all flex items-center justify-center gap-2 shadow-xl shadow-primary/25 disabled:opacity-50 cursor-pointer"
          >
            {submitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>{t("setup.submitting")}</span>
              </>
            ) : (
              <>
                <span>{t("setup.submitBtn")}</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>
      </PageShell>
      <PageContainer as="footer" width="narrow" className="relative z-10 text-center font-mono text-xs text-text-muted dark:text-white/30 py-4">
        © 2026 MetaFusion · Out-of-Box Initialization Wizard
      </PageContainer>
    </div>
  );
}
