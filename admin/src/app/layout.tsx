import type { Metadata } from "next";
import { cookies } from "next/headers";
import "@/shared/theme/globals.css";
import { getMessages } from "@/i18n/getMessages";
import { I18nProvider } from "@/i18n/I18nProvider";
import { localeCookieName, normalizeLocale } from "@/i18n/routing";
import { SessionProvider } from "@/lib/session";
import { AppShell } from "@/components/AppShell";

const themeScript = `(function () {
  try {
    var mode = localStorage.getItem("metafusion_theme_mode") || "dark";
    var effective = mode === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : mode;
    var root = document.documentElement;
    root.setAttribute("data-theme-mode", effective);
    var accent = localStorage.getItem("metafusion_theme_accent");
    var tone = localStorage.getItem("metafusion_theme_tone");
    if (accent) root.setAttribute("data-theme-accent", accent);
    if (tone) root.setAttribute("data-theme-tone", tone);
    root.classList.toggle("dark", effective === "dark");
    root.classList.toggle("light", effective === "light");
    root.style.colorScheme = effective;
  } catch (e) {}
})();`;

// 语言与登录态都按请求决定（NEXT_LOCALE cookie + 同域会话），因此不做静态预渲染。
export const dynamic = "force-dynamic";

// cookies() 是异步请求 API（Next 15 起返回 Promise，Next 16 不再接受同步取值）。
export async function generateMetadata(): Promise<Metadata> {
  const messages = getMessages((await cookies()).get(localeCookieName)?.value);
  return {
    title: messages["app.title"] ?? "MetaFusion auth-admin",
    description: messages["app.description"] ?? "",
    robots: { index: false, follow: false },
  };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = normalizeLocale((await cookies()).get(localeCookieName)?.value);
  return (
    <html lang={locale} className="dark" data-theme-mode="dark" suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: themeScript }} /></head>
      <body className="antialiased">
        <I18nProvider initialLocale={locale}>
          <SessionProvider>
            <AppShell>{children}</AppShell>
          </SessionProvider>
        </I18nProvider>
      </body>
    </html>
  );
}
