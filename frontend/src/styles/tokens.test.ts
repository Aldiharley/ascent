// Vitest stubs CSS imports (even `?raw`) to "", so read the stylesheets from
// disk. The specifiers are variables so tsc (which has no Node types here)
// treats the modules as `any`.
const [FS, URL_MOD] = ["node:fs", "node:url"];
const { readFileSync } = (await import(/* @vite-ignore */ FS)) as {
  readFileSync(path: string, enc: "utf8"): string;
};
const { fileURLToPath } = (await import(/* @vite-ignore */ URL_MOD)) as {
  fileURLToPath(url: string): string;
};
function load(name: string): string {
  return readFileSync(
    fileURLToPath(import.meta.url).replace(/tokens\.test\.ts$/, name),
    "utf8",
  );
}
const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "");

const tokensCss = stripComments(load("tokens.css"));
const componentsCss = stripComments(load("components.css"));
const screensCss = stripComments(load("screens.css"));

/** Declarations of the rule whose selector list is exactly `selector`. */
function rule(css: string, selector: string): Record<string, string> {
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
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

/** Every custom property declared in tokens.css `:root`. */
const tokens = rule(tokensCss, ":root");

/** Resolve a `--token` / `var(--token)` chain to a #rrggbb value. */
function resolve(spec: string): string {
  let v = spec.trim();
  for (let hops = 0; hops < 8; hops++) {
    const m = v.match(/^(?:var\()?(--[a-z0-9-]+)\)?$/i);
    if (!m) break;
    const next = tokens[m[1]];
    if (next === undefined) throw new Error(`undefined token ${m[1]}`);
    v = next.trim();
  }
  if (!/^#[0-9a-f]{6}$/i.test(v)) {
    throw new Error(`"${spec}" does not resolve to a #rrggbb colour (got "${v}")`);
  }
  return v.toLowerCase();
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

// [foreground, background, spec-measured ratio, what it is]. A `--name` is read from
// tokens.css; a #hex is a surface that is derived (blended, worst-case pixel) and so has no token.
type Row = [fg: string, bg: string, measured: number, label: string];

// Spec 5.2, text pairs: WCAG AA needs 4.5:1.
const TEXT: Row[] = [
  ["--ink", "--bg", 10.81, "page title on the canvas"],
  ["--ink", "#acb7c1", 6.89, "page title over the darkest fabric pixel"],
  ["--ink", "--surface-solid", 13.05, "body text on a card"],
  ["--ink-2", "#f0f2f4", 6.1, "secondary on a card over worst fabric"],
  ["--ink-3", "#f0f2f4", 5.14, "meta on a card over worst fabric"],
  ["--ink-3", "--coral-50", 4.79, "meta on the FAIL tint"],
  ["--ink-2", "--coral-50", 5.68, "policy body on the FAIL tint"],
  ["--link", "--coral-50", 6.23, "links on the FAIL tint"],
  ["--ink-3", "--surface-raised", 5.77, "placeholder on an input"],
  ["--ink-on-dark", "--slate-700", 7.74, "wordmark / nav on sidebar top"],
  ["--ink-on-dark-2", "--slate-700", 5.39, "nav labels on sidebar top"],
  ["--ink-on-dark-3", "--slate-600", 5.27, "policy line on the sidebar card"],
  ["--ink", "#e6eff0", 12.02, "active nav label"],
  ["#f4f7f9", "--slate-650", 7.3, "hero greeting"],
  ["--ink-on-dark-3", "--slate-550", 4.75, "hero sub-lines on the lightest stop"],
  ["--ink", "--teal-200", 9.54, "teal tile label and number"],
  ["--ink-tile", "--teal-200", 5.76, "teal tile sub-line"],
  ["--ink-tile", "--bg-tile-200", 5.47, "blue-grey tile sub-line"],
  ["--ink-tile", "--ice-200", 6.77, "ice tile sub-line"],
  ["--ink-tile", "--lav-200", 5.17, "lavender tile sub-line"],
  ["--white", "--teal-550", 4.71, "primary button label, lightest stop"],
  ["--white", "--teal-600", 5.33, "primary button hover"],
  ["--ink-on-dark", "#516476", 5.58, "ghost button over the hero"],
  ["--coral-800", "--coral-75", 6.55, "Deny button"],
  ["--ink", "--surface-raised", 14.05, "secondary button, toasts"],
  ["--sev-crit-ink", "--sev-crit-bg", 5.78, "CRITICAL chip"],
  ["--v-tp-ink", "--v-tp-bg", 5.78, "True positive chip"],
  ["--sev-high-ink", "--sev-high-bg", 5.69, "HIGH chip"],
  ["--sev-med-ink", "--sev-med-bg", 6.03, "MEDIUM chip"],
  ["--v-hu-ink", "--v-hu-bg", 6.03, "Needs human chip"],
  ["--sev-low-ink", "--sev-low-bg", 5.97, "LOW chip"],
  ["--sev-info-ink", "--sev-info-bg", 6.49, "INFO chip"],
  ["--v-fp-ink", "--v-fp-bg", 6.08, "Likely noise chip"],
  ["--p-pass-ink", "--p-pass", 4.88, "PASS pill"],
  ["--p-cond-ink", "--p-cond", 6.65, "CONDITIONAL pill"],
  ["--p-fail-ink", "--p-fail", 5.65, "FAIL pill / chain FAIL"],
  ["--badge-count-ink", "--badge-count-bg", 5.65, "count badges"],
  ["--p-inc-ink", "--p-inc", 7.13, "INCOMPLETE / NOT EVALUATED pill"],
  ["--code-ink", "--code-bg", 8.29, "command / code block"],
  ["--coral-750", "--white", 6.84, "out-of-scope text"],
  ["--teal-650", "--surface-solid", 5.87, "in-scope text"],
  ["--ok-ink", "--ok-bg", 6.29, "count pill, DETECT-ONLY, ok card"],
  ["--err-ink", "--err-bg", 6.66, "error callout"],
  ["--ink", "--sand-200", 10.64, "banner title on the dark stop"],
  ["--ink-2", "--sand-200", 5.18, "banner sub-line on the dark stop"],
  ["--sand-800", "--sand-50", 7.78, "Active-profile warning callout"],
];

// Spec 5.2, non-text pairs: WCAG 1.4.11 needs 3:1.
const NON_TEXT: Row[] = [
  ["--focus", "--surface-solid", 4.95, "focus ring on a card"],
  ["--focus", "--lav-200", 3.25, "focus ring on the lavender tile"],
  ["--focus-on-dark", "--slate-750", 5.62, "focus ring on the sidebar"],
  ["--focus-on-dark", "--slate-650", 4.61, "focus ring on the hero"],
  ["--border-input", "--surface-raised", 3.81, "input boundary"],
  ["--sev-crit", "--surface-solid", 4.02, "CRITICAL bar / donut fill"],
  ["--sev-high", "--surface-solid", 3.34, "HIGH bar fill"],
  ["--sev-med", "--surface-solid", 3.23, "MEDIUM bar fill"],
  ["--sev-low", "--surface-solid", 3.32, "LOW bar fill"],
  ["--sev-info", "--surface-solid", 3.4, "INFO bar fill"],
  ["--cat-sast", "--surface-solid", 4.77, "SAST donut fill"],
  ["#6fd0c1", "--slate-700", 4.63, "active status dot on the sidebar"],
];

const pair = (r: Row) => [resolve(r[0]), resolve(r[1])] as const;

describe("text contrast (spec 5.2): every pair clears WCAG AA 4.5:1", () => {
  test.each(TEXT)("%s on %s", (fg, bg, _measured, label) => {
    const [f, b] = pair([fg, bg, 0, label]);
    expect(contrast(f, b), `${label} (${f} on ${b})`).toBeGreaterThanOrEqual(4.5);
  });
});

describe("non-text contrast (spec 5.2): every pair clears 3:1", () => {
  test.each(NON_TEXT)("%s vs %s", (fg, bg, _measured, label) => {
    const [f, b] = pair([fg, bg, 0, label]);
    expect(contrast(f, b), `${label} (${f} vs ${b})`).toBeGreaterThanOrEqual(3);
  });
});

test("the tokens still match the ratios the spec measured (guards silent palette drift)", () => {
  // Rows whose spec figure used a slightly different surface (e.g. the LOW chip) are not pinned
  // exactly; every other row must match to within 0.1.
  const loose = new Set(["LOW chip", "Needs human chip", "True positive chip"]);
  for (const r of [...TEXT, ...NON_TEXT]) {
    if (loose.has(r[3])) continue;
    const [f, b] = pair(r);
    expect(Math.abs(contrast(f, b) - r[2]), `${r[3]} ${f}/${b}`).toBeLessThan(0.1);
  }
});

test("why only --ink may sit on the bare canvas: --ink-2 misses AA over the darkest fabric pixel", () => {
  // Spec 5.2 rule: worst case 3.36 for --ink-2 on the canvas over the fabric texture.
  const worst = "#acb7c1";
  expect(contrast(resolve("--ink-2"), worst)).toBeLessThan(4.5);
  expect(contrast(resolve("--ink"), worst)).toBeGreaterThanOrEqual(4.5);
});

test("out-of-scope warning text meets WCAG AA contrast on the white gate card", () => {
  const color = rule(componentsCss, ".scope-bad").color;
  expect(color).toBeTruthy();
  expect(contrast(resolve(color), "#ffffff")).toBeGreaterThanOrEqual(4.5);
});

test("the audit feed caps: page feed is viewport-based, compact feed is uncapped", () => {
  expect(rule(screensCss, ".feed")["max-height"]).toBeUndefined();
  expect(rule(screensCss, ".feed--page")["max-height"]).toBe("calc(100vh - 280px)");
  expect(rule(screensCss, ".feed--compact")["max-height"]).toBe("none");
});

test("tokens.css defines the typography, radius and layout tokens the spec names", () => {
  for (const name of [
    "--font-display", "--font-ui", "--font-mono", "--t-page", "--t-micro", "--r-xl", "--r-pill",
    "--shadow-card", "--shadow-clay", "--sidebar-w", "--rail-w", "--content-max", "--d-chart",
  ]) {
    expect(tokens[name], name).toBeTruthy();
  }
  expect(tokens["--t-micro"]).toMatch(/^700 12px\//); // text floor is 12px
});
