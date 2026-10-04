// Vitest stubs CSS imports (even `?raw`) to "", so read the stylesheet from
// disk. The specifier is a variable so tsc (which has no Node types here)
// treats the module as `any`.
const [FS, URL_MOD] = ["node:fs", "node:url"];
const { readFileSync } = (await import(/* @vite-ignore */ FS)) as {
  readFileSync(path: string, enc: "utf8"): string;
};
const { fileURLToPath } = (await import(/* @vite-ignore */ URL_MOD)) as {
  fileURLToPath(url: string): string;
};
const css = readFileSync(
  fileURLToPath(import.meta.url).replace(/glass\.test\.ts$/, "glass.css"),
  "utf8",
);

/** Declarations of the rule whose selector list is exactly `selector`. */
function rule(selector: string): Record<string, string> {
  const flat = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const re = /([^{}]+)\{([^{}]*)\}/g;
  for (const m of flat.matchAll(re)) {
    if (m[1].trim() === selector) {
      const decls: Record<string, string> = {};
      for (const d of m[2].split(";")) {
        const i = d.indexOf(":");
        if (i > 0) decls[d.slice(0, i).trim()] = d.slice(i + 1).trim();
      }
      return decls;
    }
  }
  throw new Error(`no rule for ${selector}`);
}

function luminance(hex: string): number {
  const n = parseInt(hex.replace("#", ""), 16);
  const ch = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

test("out-of-scope warning text meets WCAG AA contrast on the white gate card", () => {
  const color = rule(".scope-bad").color;
  expect(color).toMatch(/^#[0-9a-f]{6}$/i);
  expect(contrast(color, "#ffffff")).toBeGreaterThanOrEqual(4.5);
});

test("the 340px feed cap applies only inside the aside", () => {
  expect(rule(".feed")["max-height"]).toBeUndefined();
  expect(rule(".side .feed")["max-height"]).toBe("340px");
});

test("the full-page audit feed gets a viewport-based cap", () => {
  expect(rule(".main .feed")["max-height"]).toBe("calc(100vh - 220px)");
});
