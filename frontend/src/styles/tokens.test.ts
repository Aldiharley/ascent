// Vitest stubs CSS imports (even `?raw`) to "", so read the stylesheets from
// disk. The specifiers are variables so tsc (which has no Node types here)
// treats the modules as `any`.
const [FS, URL_MOD] = ["node:fs", "node:url"];
const fsExtra = (await import(/* @vite-ignore */ FS)) as {
  readFileSync(path: string, enc: "utf8"): string;
  existsSync(path: string): boolean;
};
const { readFileSync } = fsExtra;
const { fileURLToPath } = (await import(/* @vite-ignore */ URL_MOD)) as {
  fileURLToPath(url: string): string;
};
/** Absolute path of a file next to this test (`../x` for the src folder). */
function path(name: string): string {
  return fileURLToPath(import.meta.url).replace(/tokens\.test\.ts$/, name);
}
function load(name: string): string {
  return readFileSync(path(name), "utf8");
}
const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "");

const tokensCss = stripComments(load("tokens.css"));
const componentsCss = stripComments(load("components.css"));
const baseCss = stripComments(load("base.css"));
const shellCss = stripComments(load("shell.css"));
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
  // Only the LOW chip's spec figure used a slightly different surface, so it is the one row not
  // pinned; every other row must match to within 0.1.
  const loose = new Set(["LOW chip"]);
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

/** Alpha-blend `#rrggbb` `top` at `alpha` over opaque `base`. */
function blend(top: string, alpha: number, base: string): string {
  const t = parseInt(top.slice(1), 16);
  const b = parseInt(base.slice(1), 16);
  const out = [16, 8, 0].map((sh) => {
    const c = Math.round(((t >> sh) & 255) * alpha + ((b >> sh) & 255) * (1 - alpha));
    return c.toString(16).padStart(2, "0");
  });
  return `#${out.join("")}`;
}

test("the sidebar engagement chip text clears AA over the whole blended sidebar gradient", () => {
  const chip = rule(shellCss, ".sb-chip");
  const m = chip.background.match(/^rgba\(\s*255\s*,\s*255\s*,\s*255\s*,\s*(\.?\d*\.?\d+)\s*\)$/);
  expect(m, `chip background "${chip.background}" is white at some alpha`).not.toBeNull();
  const alpha = Number(m![1]);
  const ink = resolve(chip.color);
  // --surface-dark runs from --slate-700 (top, lightest) to --slate-800 (bottom, darkest); the
  // chip is translucent white over whichever point of that gradient it sits on.
  for (const stop of ["--slate-700", "--slate-800"]) {
    const surface = blend("#ffffff", alpha, resolve(stop));
    expect(contrast(ink, surface), `chip text ${ink} over ${surface} (${stop})`).toBeGreaterThanOrEqual(4.5);
  }
  // the gradient the chip sits on is still the one this test assumes
  expect(tokens["--surface-dark"]).toContain("var(--slate-700)");
  expect(tokens["--surface-dark"]).toContain("var(--slate-800)");
});

test("the prefers-reduced-motion override is a single block, last in the last-loaded sheet", () => {
  const blocks = (css: string) => css.match(/@media \(prefers-reduced-motion:\s*reduce\)/g) ?? [];
  expect(blocks(screensCss)).toHaveLength(1);
  for (const [name, css] of [["base", baseCss], ["components", componentsCss], ["shell", shellCss]] as const) {
    expect(blocks(css), `${name}.css must not carry its own copy`).toHaveLength(0);
  }
  // nothing but that block follows the first reduced-motion at-rule in screens.css
  const tail = screensCss.slice(screensCss.search(/@media \(prefers-reduced-motion/));
  expect(tail.match(/@media/g)).toHaveLength(1);
});

test("the report section-index title uses --ink on the bare canvas", () => {
  expect(rule(screensCss, ".report-index .idx-title").color).toBe("var(--ink)");
});

test("the audit feed caps: page feed is viewport-based, compact feed is uncapped", () => {
  expect(rule(screensCss, ".feed")["max-height"]).toBeUndefined();
  expect(rule(screensCss, ".feed--page")["max-height"]).toBe("calc(100vh - 280px)");
  expect(rule(screensCss, ".feed--compact")["max-height"]).toBe("none");
});

test("the legacy glass sheet is gone: no file, no import, and no module-level reference to it", () => {
  const { existsSync } = fsExtra;
  expect(existsSync(path("glass.css"))).toBe(false);
  const main = readFileSync(path("../main.tsx"), "utf8");
  expect(main).not.toMatch(/glass/i);
  // the five sheets that remain load in cascade order, reduced-motion's home (screens.css) last
  const imports = [...main.matchAll(/import "\.\/styles\/([a-z]+)\.css"/g)].map((m) => m[1]);
  expect(imports).toEqual(["tokens", "base", "components", "shell", "screens"]);
});

test("no sheet reads a custom property that only the deleted glass sheet defined", () => {
  const legacy = [
    "--muted", "--faint", "--accent", "--stroke", "--stroke-soft", "--glass", "--glass-2",
    "--shadow", "--radius", "--crit", "--high", "--med", "--ok", "--violet", "--font", "--mono",
    "--field-1", "--field-2", "--field-3",
  ];
  for (const [name, css] of [
    ["tokens", tokensCss], ["base", baseCss], ["components", componentsCss], ["shell", shellCss], ["screens", screensCss],
  ] as const) {
    for (const token of legacy) {
      expect(css, `${name}.css uses var(${token})`).not.toMatch(new RegExp(`var\\(${token}[,)]`));
    }
  }
});

test("toasts no longer position themselves: the stack in shell.css owns placement", () => {
  const toast = rule(componentsCss, ".toast");
  expect(toast.position).toBeUndefined();
  expect(shellCss).toMatch(/\.toast-stack\{position:fixed/);
});

test("the New scan and Report layouts are styled: two-column grid, sticky index, active-section bar", () => {
  expect(rule(screensCss, ".newscan-grid")["grid-template-columns"]).toBe("minmax(0,7fr) minmax(0,5fr)");
  expect(screensCss).toMatch(/\.report-index\{position:sticky/);
  expect(screensCss).toMatch(/\.report-index\{display:none\}/); // hidden (and out of the a11y tree) below 1280
  expect(screensCss).toMatch(/\.report-index a\[aria-current\]\{[^}]*border-left-color:var\(--teal-500\)/);
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
