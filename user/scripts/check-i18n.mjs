// 四语字典一致性断言（CI 与本地同一条命令：bun run i18n:check）。
//
// 三条断言：
//   1. 四语键集合完全一致（差集为空）——缺键会让界面回退显示裸 key；
//   2. 没有空串值——空串在界面上等于"这里什么都没有"，比缺键更难发现；
//   3. 源码里 t("...") 的字面量键在四语字典里都存在——挡住"新增文案忘了补字典"。
//
// 动态键（模板串、字符串拼接，如 instance.setting.<key>）不参与第 3 条：它们自带回落值。

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOCALES = ["zh-CN", "en-US", "zh-TW", "ja-JP"];
const MESSAGES = path.join(ROOT, "src", "messages");

const read = (locale) => JSON.parse(fs.readFileSync(path.join(MESSAGES, locale + ".json"), "utf8"));
const dicts = Object.fromEntries(LOCALES.map((l) => [l, read(l)]));

const problems = [];

// ── 1. 键集合一致 ──
const base = LOCALES[0];
const baseKeys = Object.keys(dicts[base]).sort();
for (const locale of LOCALES.slice(1)) {
  const keys = new Set(Object.keys(dicts[locale]));
  const missing = baseKeys.filter((k) => !keys.has(k));
  const extra = [...keys].filter((k) => !(k in dicts[base])).sort();
  if (missing.length) problems.push(`${locale} 缺 ${missing.length} 个键：${missing.slice(0, 10).join(", ")}`);
  if (extra.length) problems.push(`${locale} 多 ${extra.length} 个键：${extra.slice(0, 10).join(", ")}`);
}

// ── 2. 无空值 ──
for (const locale of LOCALES) {
  for (const [key, value] of Object.entries(dicts[locale])) {
    if (typeof value !== "string") problems.push(`${locale} 的 ${key} 不是字符串`);
    else if (value.trim() === "") problems.push(`${locale} 的 ${key} 是空串`);
  }
}

// ── 3. 源码里的字面量键都要有 ──
const walk = (dir) => {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (/\.(ts|tsx)$/.test(entry.name)) out.push(full);
  }
  return out;
};

const literal = /\bt\(\s*"([^"]+)"\s*[,)]/g;
const usedKeys = new Map();
for (const file of walk(path.join(ROOT, "src"))) {
  const text = fs.readFileSync(file, "utf8");
  for (const match of text.matchAll(literal)) {
    const key = match[1];
    if (!usedKeys.has(key)) usedKeys.set(key, path.relative(ROOT, file));
  }
}
for (const [key, where] of usedKeys) {
  for (const locale of LOCALES) {
    if (!(key in dicts[locale])) problems.push(`源码用到但 ${locale} 缺失的键 ${key}（${where}）`);
  }
}

if (problems.length) {
  console.error("i18n 校验失败：");
  for (const p of problems) console.error("  - " + p);
  process.exit(1);
}
console.log(`i18n OK：四语各 ${baseKeys.length} 键，键集合一致，源码引用的 ${usedKeys.size} 个字面量键全部存在`);
