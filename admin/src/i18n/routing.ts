// 语言路由契约：语言写在 NEXT_LOCALE cookie 里（与主站同名同值），不放到 URL 上——
// 四个应用共用一份 cookie，用户切一次语言在网关聚合的四个站点上一致。
export const locales = ["zh-CN", "en-US", "zh-TW", "ja-JP"] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = "zh-CN";
export const localeCookieName = "NEXT_LOCALE";
export const validLocales = new Set<string>(locales);

export function normalizeLocale(input?: string | null): Locale {
  if (!input) return defaultLocale;
  const v = input.trim();
  if (validLocales.has(v)) return v as Locale;
  const low = v.toLowerCase().replace(/_/g, "-");
  if (low.startsWith("ja")) return "ja-JP";
  if (low.startsWith("zh-tw") || low.startsWith("zh-hk") || low.includes("hant")) return "zh-TW";
  if (low.startsWith("zh")) return "zh-CN";
  if (low.startsWith("en")) return "en-US";
  return defaultLocale;
}
