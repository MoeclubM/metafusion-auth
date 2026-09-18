/** @type {import('next').NextConfig} */
// 账号自助应用（登录/注册/初始化）：独立应用，无 basePath。
// 网关用精确路径 location = /login 与 = /setup 指到这里（见主仓库 deploy/nginx.conf），
// 因此页面路由保持 /login、/setup 的绝对形态，不挂任何前缀。
// 数据请求走同源 /api/*（网关按域分流回账号服务），不配 rewrites。
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  output: "standalone",
};

export default nextConfig;
