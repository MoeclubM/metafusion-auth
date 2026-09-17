/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // 独立应用形态（解耦审计 §7.3 D1）：容器内只监听 3000，网关按路径 /admin/account 聚合，
  // 主仓库 compose 注册的上游名为 auth-admin:3000。basePath 与端口是跨仓库契约，不要在这里改。
  output: "standalone",
  basePath: "/admin/account",
};

export default nextConfig;
