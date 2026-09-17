// 应用挂载点：必须与 next.config.mjs 的 basePath 一致（跨仓库契约的一部分，改一处等于改网关上游）。
// 只用于 usePathname() 的回落比较——next/link 与 next/navigation 会自动带上 basePath，
// 不需要（也不应该）在 href 里手写它。
export const BASE_PATH = "/admin/account";

/** 去掉 basePath 的当前路径，用于导航高亮判定；根路径归一成 "/"。 */
export function stripBasePath(pathname: string | null | undefined): string {
  if (!pathname) return "/";
  if (pathname === BASE_PATH) return "/";
  if (pathname.startsWith(BASE_PATH + "/")) return pathname.slice(BASE_PATH.length);
  return pathname;
}
