// 展示层格式化。接口给的时间是 UTC RFC3339：解析不了就原样显示，不猜。

export function formatStamp(value: string | undefined, locale: string): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(locale, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function sortGroups<T extends { code: string; sort_order?: number }>(groups: T[]): T[] {
  return [...groups].sort((a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.code.localeCompare(b.code));
}

/** 接口给的四语名称里取当前语言；缺了按 zh-CN → 第一个非空回落，不显示空串。 */
export function pickLocalizedName(
  names: Record<string, string> | undefined,
  locale: string,
  fallback: string
): string {
  if (!names) return fallback;
  const direct = names[locale]?.trim();
  if (direct) return direct;
  const zh = names["zh-CN"]?.trim();
  if (zh) return zh;
  const first = Object.values(names).map((v) => v?.trim()).find((v) => v);
  return first || fallback;
}
