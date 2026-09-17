// 来源：MetaFusion/frontend（等共享包落地后替换）。
// 只留这一处接线：设计 token 的 Tailwind 配置收敛在 src/shared/theme，根目录不再放第二份。
const config = {
  plugins: {
    tailwindcss: { config: "./src/shared/theme/tailwind.config.ts" },
    autoprefixer: {},
  },
};

export default config;
