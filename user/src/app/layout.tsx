import type { Metadata } from "next";
import { cookies } from "next/headers";
import "@/shared/theme/globals.css";
import { getMessages } from "@/i18n/getMessages";
import { I18nProvider } from "@/i18n/I18nProvider";
import { SessionProvider } from "@/lib/session";
import { localeCookieName, normalizeLocale } from "@/i18n/routing";

// 语言按请求决定（NEXT_LOCALE cookie），因此不做静态预渲染。
// 默认深色（与管理台一致）；换肤控件随页面搬运后补，本轮只保证语言与布局契约。
export const dynamic = "force-dynamic";

export async function generateMetadata(): Promise<Metadata> {
  const messages = getMessages((await cookies()).get(localeCookieName)?.value);
  return {
    title: messages["app.title"] ?? "MetaFusion Account",
    description: messages["app.description"] ?? "",
    icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
    robots: { index: false, follow: false },
  };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = normalizeLocale((await cookies()).get(localeCookieName)?.value);
  return (
    <html lang={locale} className="dark">
      <body className="antialiased">
        <I18nProvider initialLocale={locale}>
          <SessionProvider>{children}</SessionProvider>
        </I18nProvider>
      </body>
    </html>
  );
}
