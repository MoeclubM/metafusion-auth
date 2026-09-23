/** 登录回跳可为同源 URL 或路径，返回供 router 使用的站内路径。 */
export function safeLoginRedirect(value: string | null, origin: string): string {
  if (!value || /[\\\u0000-\u001f\u007f]/.test(value) || value.startsWith("//")) return "/";

  try {
    const base = new URL(origin);
    const target = new URL(value, base);
    if (
      target.origin !== base.origin ||
      (target.protocol !== "https:" && target.protocol !== "http:") ||
      target.username !== "" ||
      target.password !== ""
    ) {
      return "/";
    }
    const decodedPath = decodeURIComponent(target.pathname);
    if (!decodedPath.startsWith("/") || decodedPath.startsWith("//") || /[\\\u0000-\u001f\u007f]/.test(decodedPath)) return "/";
    return `${target.pathname}${target.search}${target.hash}`;
  } catch {
    return "/";
  }
}
