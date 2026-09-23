/** 登录后只允许跳回本站的绝对路径。 */
export function safeLoginRedirect(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
  if (/[\\\u0000-\u001f\u007f]/.test(value)) return "/";

  try {
    const decoded = decodeURIComponent(value);
    if (decoded.startsWith("//") || /[\\\u0000-\u001f\u007f]/.test(decoded)) return "/";
  } catch {
    return "/";
  }

  return value;
}
