import type { Metadata } from "next";
import { cookies } from "next/headers";
import "@/shared/theme/globals.css";
import { getMessages } from "@/i18n/getMessages";
import { I18nProvider } from "@/i18n/I18nProvider";
import { localeCookieName, normalizeLocale } from "@/i18n/routing";
import { SessionProvider } from "@/lib/session";
import { AppShell } from "@/components/AppShell";

// 语言与登录态都按请求决定（NEXT_LOCALE cookie + 同域会话），因此不做静态预渲染。
export const dynamic = "force-dynamic";

export function generateMetadata(): Metadata {
  const messages = getMessages(cookies().get(localeCookieName)?.value);
  return {
    title: messages["app.title"] ?? "MetaFusion auth-admin",
    description: messages["app.description"] ?? "",
    robots: { index: false, follow: false },
  };
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = normalizeLocale(cookies().get(localeCookieName)?.value);
  return (
    <html lang={locale} className="dark">
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
