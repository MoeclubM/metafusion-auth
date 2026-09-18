import { normalizeLocale } from "./routing";
import zhCN from "@/messages/zh-CN.json";
import enUS from "@/messages/en-US.json";
import zhTW from "@/messages/zh-TW.json";
import jaJP from "@/messages/ja-JP.json";

// 四语整文件静态引入：键集合由 scripts/check-i18n.mjs 断言完全一致，缺键不会静默变成英文。
const catalog: Record<string, Record<string, string>> = {
  "zh-CN": zhCN as Record<string, string>,
  "en-US": enUS as Record<string, string>,
  "zh-TW": zhTW as Record<string, string>,
  "ja-JP": jaJP as Record<string, string>,
};

export function getMessages(locale?: string | null): Record<string, string> {
  const loc = normalizeLocale(locale);
  return catalog[loc] ?? catalog["zh-CN"]!;
}

export function translate(
  messages: Record<string, string>,
  key: string,
  vars?: Record<string, string | number>
): string {
  let s = messages[key];
  if (s == null) return key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      s = s.split(`{${k}}`).join(String(v));
    }
  }
  return s;
}

/** 缺键时返回后备值而不是裸 key：用于"接口给了就翻译、没给就原样显示"的覆盖层。 */
export function translateOr(
  messages: Record<string, string>,
  key: string,
  fallback: string,
  vars?: Record<string, string | number>
): string {
  if (messages[key] == null) return fallback;
  return translate(messages, key, vars);
}
