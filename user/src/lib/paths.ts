// 本应用无 basePath：网关用精确路径 = /login 与 = /setup 直接指到这里，
// 页面路由保持 /login、/setup 的绝对形态。
export const BASE_PATH = "";

/** 本应用自己的登录页：与其它应用的回跳目标同地址，永远用绝对路径。 */
export const LOGIN_PATH = "/login";

/** 首次初始化页：实例无管理员时注册入口交接给它。 */
export const SETUP_PATH = "/setup";

/** 本应用内的页面（含登录与初始化）：401 时不跳转，由页面就地处理。 */
export const APP_PATHS = [LOGIN_PATH, SETUP_PATH] as const;
