// user 字典同步：源码 t("...") 字面量键 + 手工键的四语取值，来源按序取
// 主站 frontend/src/messages（页面文案）→ admin/src/messages（error./locale.）。
// 主站位置按 MF_MAIN_DIR 或并列检出推导；admin 与本应用同仓，相对路径稳定。
// 跑完后必须 bun run i18n:check 全绿。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOCALES = ["zh-CN", "en-US", "zh-TW", "ja-JP"];
const MANUAL = ["locale.label", "locale.zh-CN", "locale.en-US", "locale.zh-TW", "locale.ja-JP"];
function findMain() {
  const cands = [process.env.MF_MAIN_DIR, path.resolve(ROOT, "..", "..", "MetaFusion", "frontend", "src", "messages"), path.resolve(ROOT, "..", "MetaFusion", "frontend", "src", "messages")].filter(Boolean);
  for (const c of cands) { try { if (fs.statSync(c).isDirectory()) return c; } catch {} }
  return null;
}
const MAIN = findMain();
const ADMIN = path.join(ROOT, "..", "admin", "src", "messages");
function walk(dir, out) {
  out = out || [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const f = path.join(dir, e.name);
    if (e.isDirectory()) walk(f, out);
    else if (/\.(ts|tsx)$/.test(e.name)) out.push(f);
  }
  return out;
}
const keys = new Set(MANUAL);
const re = /\bt\(\s*"([^"]+)"/g;
for (const f of walk(path.join(ROOT, "src"))) {
  const text = fs.readFileSync(f, "utf8");
  for (const m of text.matchAll(re)) keys.add(m[1]);
}
const load = (dir, loc) => JSON.parse(fs.readFileSync(path.join(dir, loc + ".json"), "utf8"));
const missing = [];
for (const loc of LOCALES) {
  const main = MAIN ? load(MAIN, loc) : {};
  const admin = load(ADMIN, loc);
  const cur = load(path.join(ROOT, "src", "messages"), loc);
  for (const k of keys) {
    if (cur[k] !== undefined) continue;
    if (main[k] !== undefined) cur[k] = main[k];
    else if (admin[k] !== undefined) cur[k] = admin[k];
    else missing.push(loc + " 缺 " + k);
  }
  fs.writeFileSync(path.join(ROOT, "src", "messages", loc + ".json"), JSON.stringify(cur, null, 2) + "\n");
  console.log(loc + ": " + Object.keys(cur).length + " keys");
}
if (missing.length) { console.error("无来源的键："); for (const m of missing) console.error("  - " + m); process.exit(1); }
console.log("sync ok: " + keys.size + " literal+manual keys");
