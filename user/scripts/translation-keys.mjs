// Literal translation calls and explicit auth maps/notice/fallback keys.
export function translationKeys(text) {
  return new Set([
    ...Array.from(text.matchAll(/\bt\(\s*["']([^"']+)["']/g), (m) => m[1]),
    ...Array.from(text.matchAll(/["'](auth\.(?:error\.[A-Za-z0-9_]+|passwordChangedSignedOut|sessionsRevokedSignedOut|requestFailed))["']/g), (m) => m[1]),
  ]);
}
