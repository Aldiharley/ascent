# Ascent Console UI redesign: "Watchdog" clay theme

Date: 2026-10-31
Status: design spec, ready for build
Scope: frontend only (`frontend/`). A re-skin plus a layout and UX redesign. No backend change, no
new endpoint, no new npm dependency, no feature removed.
References: `images/1.jpg` (moodboard: sea-glass teal, slate blue-grey, sand, cream, flowing
fabric, soft donuts, pill buttons) and `images/2.jpg` (layout: dark slate rounded sidebar with a 3D
avatar and greeting, hero banner with a character and CTA, four pastel KPI tiles, bar and donut
cards, "See all" list cards, bottom CTA banner).

---

## 0. Non-negotiables (carried over unchanged)

These rules hold in every section below. Any visual choice that conflicts with them loses.

1. **Scanned data is text.** Every string from `/api/*` (titles, rule ids, URLs, paths, commands,
   targets, reasons, policy names, gate ids, hashes, report markdown) renders as React text. No
   `dangerouslySetInnerHTML`, no `rehype-raw`. Class names, colours and icons are chosen from fixed
   lookup tables keyed by enums, never from data.
2. **No `<img>` element in any data-rendering component.** All mascot and texture art is applied
   as a CSS `background-image` on an `aria-hidden` element (see `Mascot`, section 4.12). This keeps
   the existing "container has no img" test invariants trivially true and means a malicious report
   can never be confused with app art.
3. **Approve records consent and never runs anything.** The sentence "Every decision is written to
   the audit log. Approving records consent; it does not run the command." stays visible under
   every Approve button, on every screen where one appears.
4. **The policy verdict is read-only.** The card says "Read-only verdict from out/gate.json".
   No control on the console evaluates a policy.
5. **New Scan never launches a scan.** The screen keeps "defines scope — does not launch", the
   "Creating a scan writes a scope file. Running it is a separate, explicit step…" note, and the
   copyable `ascent run …` command. The hero CTA reads "Define a new scan", never "Start" or "Run".
6. **CSP is unchanged** (`src/bin/dashboard.rs`): scripts and connections self-only; images
   self or `data:`; styles self + inline + Google Fonts; fonts from fonts.gstatic.com. All art
   ships in `frontend/public/` (served from self); chevrons and wave shapes are inline SVG or
   `data:` URIs.
7. **No inert controls.** Every button, input and clickable surface below has a stated function.
   Nothing gets `cursor:pointer` or a hover lift unless it does something.

---

## 1. Visual direction and design tokens

### 1.1 Visual direction

A calm, tactile "clay and fabric" console: a cool blue-grey frosted canvas, cards that sit on it
like soft moulded clay (generous 24–32px radii, a light inner top highlight and a low, wide drop
shadow), one dark slate sidebar that anchors the page, and a muted sea-glass / slate / sand /
lavender palette taken directly from the moodboard. Data colour (severity, verdict, policy) is
deliberately muted (coral, amber, ochre, teal, slate) so it reads as information, not alarm, while
still clearing WCAG AA. Personality comes from one recurring character, a white fluffy "watchdog"
in over-ear headphones and a navy hoodie, who appears in the sidebar avatar, the Overview hero, and
the empty and error states. Headlines use rounded Nunito for warmth; all UI text uses
Plus Jakarta Sans; code, hashes and locations use JetBrains Mono. Light theme only in this pass
(see 1.10).

### 1.2 Fonts (Google Fonts, replaces the current `<link>` in `frontend/index.html`)

```html
<link rel="stylesheet"
  href="https://fonts.googleapis.com/css2?family=Nunito:wght@700;800&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" />
```

Keep the two existing `preconnect` lines. Plus Jakarta Sans weight 800 is dropped (Nunito 800
replaces every former 800 use).

### 1.3 Token file

New file `frontend/src/styles/tokens.css`. Everything else references these names; no raw hex
outside this file except the contrast test.

```css
:root{
  color-scheme: light;

  /* ---------- raw palette ---------- */
  /* slate (sidebar, hero, ink) */
  --slate-900:#1f2d3a; --slate-800:#2e4153; --slate-750:#33475b; --slate-700:#3a4f63;
  --slate-650:#3e5468; --slate-600:#445b70; --slate-550:#4a6276; --slate-500:#5d7488;
  --slate-400:#71879b; --slate-300:#8fa3b5; --slate-250:#c3d0db; --slate-200:#c9d3da;
  --slate-175:#d6e0e8; --slate-150:#dbe3e8; --slate-100:#e9eef1; --slate-50:#f2f5f7;
  /* sea-glass teal */
  --teal-700:#1f5e57; --teal-650:#276a62; --teal-600:#2f766f; --teal-550:#357f78;
  --teal-500:#4b9289; --teal-400:#6fb8ae; --teal-300:#8fd3c9; --teal-250:#a9d8cf;
  --teal-200:#b9dcd5; --teal-150:#d3ebe6; --teal-100:#dcefeb; --teal-50:#e3f1ee;
  /* sand / cream */
  --sand-800:#5e460c; --sand-700:#6e5310; --sand-500:#a8832a; --sand-300:#d9c3a0;
  --sand-200:#eadfca; --sand-150:#f0ddb0; --sand-100:#f3ebdc; --sand-75:#f4ead0;
  --sand-50:#f6efdf; --cream:#f5efe4;
  /* frosted ice */
  --ice-500:#5f8fa8; --ice-300:#9cc6da; --ice-200:#d9e8f0; --ice-100:#eaf2f6;
  /* lavender */
  --lav-600:#3f4766; --lav-500:#7f76b8; --lav-400:#a9a1d8; --lav-200:#ccc6e7; --lav-100:#dedaf0;
  /* blue-grey tile */
  --bg-tile-200:#c5d1dc; --bg-tile-100:#d5dee6;
  /* coral (critical / true positive / fail) */
  --coral-800:#9a2e28; --coral-750:#a3332d; --coral-700:#b0433c; --coral-500:#c25750;
  --coral-200:#efc9c5; --coral-100:#f6dcd9; --coral-75:#fbeceb; --coral-50:#f8e6e3;
  /* amber (high) */
  --amber-700:#8a4614; --amber-500:#c27234; --amber-100:#f7e3d2;
  /* violet (SAST category only) */
  --violet-500:#6a63b0;
  --white:#ffffff;

  /* ---------- semantic: surfaces ---------- */
  --bg:#dbe3e8;                               /* page canvas */
  --bg-glow-teal:#cfe5e1; --bg-glow-sand:#ece3d3; --bg-glow-lav:#e2dff0;
  --surface: rgba(247,249,250,.90);           /* frosted card; effective #f4f7f8 on --bg */
  --surface-solid:#f4f7f8;                    /* fallback when backdrop-filter unsupported */
  --surface-raised:#ffffff;                   /* rows, inputs, toasts, nested cards */
  --surface-sunken:#e9eef1;                   /* tracks, code, segmented-control well */
  --surface-dark: linear-gradient(180deg,var(--slate-700) 0%,var(--slate-800) 100%); /* sidebar */
  --surface-dark-2: linear-gradient(160deg,var(--slate-600) 0%,#3d5266 100%);       /* sidebar card */
  --surface-hero: linear-gradient(120deg,var(--slate-550) 0%,var(--slate-650) 55%,var(--slate-750) 100%);
  --surface-banner: linear-gradient(100deg,var(--sand-100) 0%,var(--sand-200) 100%);
  --code-bg:#e3efee; --code-ink:#1d4a52; --code-border:#c4dedb;

  /* ---------- semantic: text ---------- */
  --ink:var(--slate-900);          /* primary text, any light surface, and the bare page canvas */
  --ink-2:#4a5d6b;                 /* secondary text: cards, tints, tiles. NOT on bare --bg */
  --ink-3:#566876;                 /* tertiary/meta: hashes, timestamps, placeholders */
  --ink-tile:#3b5058;              /* KPI tile sub-lines on every tint */
  --ink-on-dark:#f2f5f7;           /* sidebar, hero, dark buttons */
  --ink-on-dark-2:#c3d0db;         /* sidebar secondary */
  --ink-on-dark-3:#d6e0e8;         /* sidebar policy card secondary, hero sub-line (#d3dee6 ok too) */
  --link:var(--teal-700);          /* every text link and text-only teal accent */

  /* ---------- semantic: lines and focus ---------- */
  --border:rgba(31,45,58,.08);     /* card hairline */
  --border-soft:var(--slate-200);  /* dividers, secondary-button border */
  --border-input:#748593;          /* input/select boundary: 3.81:1 on white */
  --focus:var(--teal-600);         /* 3px ring on light surfaces */
  --focus-on-dark:var(--teal-300); /* 3px ring on sidebar / hero */

  /* ---------- KPI tints (gradient top-left -> bottom-right) ---------- */
  --tile-teal: linear-gradient(145deg,var(--teal-150) 0%,var(--teal-200) 100%);
  --tile-bluegrey: linear-gradient(145deg,var(--bg-tile-100) 0%,var(--bg-tile-200) 100%);
  --tile-ice: radial-gradient(120% 90% at 85% 10%,rgba(255,255,255,.75) 0%,rgba(255,255,255,0) 55%),
              linear-gradient(145deg,var(--ice-100) 0%,var(--ice-200) 100%);
  --tile-lav: linear-gradient(145deg,var(--lav-100) 0%,var(--lav-200) 100%);
  /* matching clay icon-badge gradients */
  --badge-teal: linear-gradient(145deg,var(--teal-400) 0%,#3f8f86 100%);
  --badge-bluegrey: linear-gradient(145deg,var(--slate-300) 0%,var(--slate-500) 100%);
  --badge-ice: linear-gradient(145deg,var(--ice-300) 0%,var(--ice-500) 100%);
  --badge-lav: linear-gradient(145deg,var(--lav-400) 0%,var(--lav-500) 100%);
  --badge-sand: linear-gradient(145deg,var(--sand-300) 0%,var(--sand-500) 100%);
  --badge-coral: linear-gradient(145deg,#d98a84 0%,var(--coral-700) 100%);

  /* ---------- data colours ---------- */
  /* severity: fill (charts, stripe) / chip bg / chip text */
  --sev-crit:var(--coral-500); --sev-crit-bg:var(--coral-100); --sev-crit-ink:var(--coral-800);
  --sev-high:var(--amber-500); --sev-high-bg:var(--amber-100); --sev-high-ink:var(--amber-700);
  --sev-med:var(--sand-500);   --sev-med-bg:var(--sand-75);    --sev-med-ink:var(--sand-700);
  --sev-low:var(--teal-500);   --sev-low-bg:var(--teal-100);   --sev-low-ink:#245f57;
  --sev-info:var(--slate-400); --sev-info-bg:#e1e7ed;          --sev-info-ink:#3d5266;
  /* verdict */
  --v-tp:var(--coral-500);  --v-tp-bg:var(--coral-100);  --v-tp-ink:var(--coral-800);
  --v-hu:var(--sand-500);   --v-hu-bg:var(--sand-75);    --v-hu-ink:var(--sand-700);
  --v-fp:var(--slate-400);  --v-fp-bg:#e3e8ec;           --v-fp-ink:#46566a;
  /* category (donut "Category" mode) */
  --cat-dast:var(--teal-500); --cat-sast:var(--violet-500); --cat-sca:var(--amber-500); --cat-none:var(--slate-400);
  /* policy decision: solid pill bg / pill text / card tint / headline ink */
  --p-pass:#2f7d74;       --p-pass-ink:#ffffff;  --p-pass-tint:var(--teal-50);   --p-pass-head:var(--teal-700);
  --p-cond:var(--sand-150); --p-cond-ink:var(--sand-800); --p-cond-tint:var(--sand-50); --p-cond-head:var(--sand-800);
  --p-fail:var(--coral-700); --p-fail-ink:#ffffff; --p-fail-tint:var(--coral-50); --p-fail-head:var(--coral-800);
  --p-inc:#e1e6ea;        --p-inc-ink:#3d4b57;   --p-inc-tint:var(--slate-100);  --p-inc-head:var(--ink);
  /* status */
  --ok-bg:var(--teal-100); --ok-ink:var(--teal-700); --ok-border:var(--teal-250);
  --err-bg:#f8e1de; --err-ink:#8f2a24; --err-border:var(--coral-200);
  --badge-count-bg:var(--coral-700); --badge-count-ink:#ffffff;

  /* ---------- radii ---------- */
  --r-xs:8px; --r-sm:12px; --r-md:16px; --r-lg:22px; --r-xl:28px; --r-2xl:32px; --r-pill:999px;

  /* ---------- elevation (clay recipe) ---------- */
  /* card: top inner highlight + faint bottom inner shade + wide soft drop */
  --shadow-card:
    inset 0 1px 0 rgba(255,255,255,.85),
    inset 0 -1px 0 rgba(31,45,58,.04),
    0 2px 6px -2px rgba(31,45,58,.10),
    0 14px 32px -16px rgba(31,45,58,.30);
  /* clay: moulded, for icon badges, primary buttons, avatar disc, KPI tiles */
  --shadow-clay:
    inset 0 2px 3px rgba(255,255,255,.55),
    inset 0 -3px 6px rgba(20,35,50,.22),
    0 8px 16px -6px rgba(20,35,50,.35);
  /* float: sidebar and hero */
  --shadow-float:
    inset 0 1px 0 rgba(255,255,255,.10),
    0 4px 12px -4px rgba(24,38,52,.18),
    0 28px 56px -24px rgba(24,38,52,.50);
  --shadow-pressed: inset 0 2px 6px rgba(20,35,50,.20);
  --shadow-toast: 0 18px 40px -16px rgba(31,45,58,.40), 0 2px 6px rgba(31,45,58,.08);
  --glyph-shadow: drop-shadow(0 1px 1px rgba(0,0,0,.18));   /* white glyphs inside clay badges */
  --blur-card: blur(18px) saturate(140%);

  /* ---------- spacing (4px base) ---------- */
  --s-1:4px; --s-2:8px; --s-3:12px; --s-4:16px; --s-5:20px; --s-6:24px; --s-8:32px;
  --s-10:40px; --s-12:48px; --s-16:64px;

  /* ---------- typography ---------- */
  --font-display:"Nunito",ui-rounded,system-ui,sans-serif;
  --font-ui:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace;
  /* size / line-height / weight / family */
  --t-page:   800 30px/1.15 var(--font-display);  /* top-bar page title */
  --t-hero:   800 28px/1.2  var(--font-display);  /* hero greeting */
  --t-kpi:    800 34px/1    var(--font-display);  /* KPI number, donut centre */
  --t-report: 800 30px/1.2  var(--font-display);  /* report title */
  --t-h2:     700 17px/1.3  var(--font-ui);       /* card titles */
  --t-h3:     700 15px/1.35 var(--font-ui);       /* gate titles, list-row titles */
  --t-body:   400 14px/1.55 var(--font-ui);
  --t-body-strong: 600 14px/1.55 var(--font-ui);
  --t-small:  500 13px/1.45 var(--font-ui);       /* hints, meta, sub-lines */
  --t-micro:  700 12px/1.3  var(--font-ui);       /* chips, badges, axis labels (floor: 12px) */
  --t-mono:   400 12.5px/1.5 var(--font-mono);
  --t-mono-sm:400 12px/1.45 var(--font-mono);     /* hashes */
  --tracking-tight:-.015em; --tracking-caps:.05em;

  /* ---------- motion ---------- */
  --ease-out:cubic-bezier(.22,1,.36,1);
  --ease-in-out:cubic-bezier(.65,0,.35,1);
  --d-1:120ms; --d-2:200ms; --d-3:320ms; --d-4:480ms; --d-chart:600ms;

  /* ---------- layout ---------- */
  --sidebar-w:256px; --rail-w:88px; --gutter:24px; --content-max:1184px;
  --topbar-h:72px; --tabbar-h:64px;
}
```

### 1.4 Page canvas

```css
body{
  margin:0; font:var(--t-body); color:var(--ink); -webkit-font-smoothing:antialiased;
  background:
    radial-gradient(55% 45% at 8% 0%, var(--bg-glow-teal) 0%, transparent 60%),
    radial-gradient(45% 40% at 95% 6%, var(--bg-glow-lav) 0%, transparent 60%),
    radial-gradient(60% 55% at 100% 100%, var(--bg-glow-sand) 0%, transparent 60%),
    var(--bg);
  background-attachment:fixed;
}
body::before{ /* moodboard fabric, decorative */
  content:""; position:fixed; inset:auto 0 0 auto; width:min(1400px,90vw); height:min(470px,40vh);
  background:url(/textures/fabric-wave.jpg) right bottom / cover no-repeat;
  opacity:.28; pointer-events:none; z-index:-1;
  -webkit-mask-image:linear-gradient(to top,#000 40%,transparent 100%);
          mask-image:linear-gradient(to top,#000 40%,transparent 100%);
}
```

The drifting "blob" field (`.field`, `.blob`) and its keyframes are deleted.

### 1.5 Card primitive (replaces `.glass`)

```css
.card{
  background:var(--surface); border:1px solid var(--border); border-radius:var(--r-xl);
  box-shadow:var(--shadow-card); backdrop-filter:var(--blur-card); -webkit-backdrop-filter:var(--blur-card);
  padding:var(--s-5) var(--s-6);
}
@supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))){
  .card{background:var(--surface-solid)}
}
.card-head{display:flex;align-items:center;gap:var(--s-3);margin-bottom:var(--s-4);flex-wrap:wrap}
.card-title{font:var(--t-h2);letter-spacing:var(--tracking-tight);margin:0}   /* rendered as <h2> */
```

Card titles become real `<h2>` elements (they are spans today), under the page `<h1>` (2.3). Inner
section titles inside a card are `<h3>`.

### 1.6 Clay icon badge recipe

`IconBadge` (4.11): a rounded square holding a white line glyph.

```css
.ibadge{width:48px;height:48px;border-radius:16px;display:grid;place-items:center;flex:none;
  background:var(--badge-teal); box-shadow:var(--shadow-clay); color:#fff}
.ibadge svg{width:24px;height:24px;stroke:currentColor;stroke-width:2.2;fill:none;
  stroke-linecap:round;stroke-linejoin:round;filter:var(--glyph-shadow)}
.ibadge::after{ /* glossy top-left highlight */
  content:"";position:absolute;inset:3px 50% 55% 3px;border-radius:13px 8px 14px 8px;
  background:linear-gradient(160deg,rgba(255,255,255,.55),rgba(255,255,255,0));pointer-events:none}
.ibadge{position:relative}
.ibadge--sm{width:36px;height:36px;border-radius:12px}.ibadge--sm svg{width:18px;height:18px}
.ibadge--lg{width:56px;height:56px;border-radius:18px}.ibadge--lg svg{width:28px;height:28px}
```

Variants set `background` from `--badge-{teal|bluegrey|ice|lav|sand|coral}`. Badges are always
`aria-hidden`; the adjacent label carries meaning, so the white glyph has no contrast requirement.

### 1.7 Typography rules

- One `<h1>` per screen: the top-bar page title (2.3). Card titles `<h2>`; card sub-sections `<h3>`.
- Floor is 12px for any text. The current 10–11.5px sizes (`.tag`, `.badge-detect`, `.ev .h`,
  `.note`, `.sev`) all move up to 12px.
- All counts and numbers: `font-variant-numeric:tabular-nums`.
- The mockup leftover `h1{font-size:0;margin:0}` is deleted.

### 1.8 Spacing rules

Card padding 20/24. Gap between cards 20px (`--s-5`). Grid gutter between the sidebar and main
24px. Inside cards: 16px between blocks, 12px between related lines, 8px inside chips/rows.

### 1.9 Motion

| What | Spec |
|---|---|
| Hover on interactive surfaces (buttons, KPI tiles, nav items) | `transform:translateY(-1px)`, shadow +2px, `var(--d-1) var(--ease-out)` |
| Press | `translateY(1px)` + `--shadow-pressed`, `var(--d-1)` |
| Card enter (first data paint) | opacity 0→1, translateY 6px→0, `var(--d-3) var(--ease-out)`, stagger 40ms by grid order, max 6 |
| Bar chart | each bar `transform:scaleY(0→1)` from baseline (`transform-origin:bottom; transform-box:fill-box`), `var(--d-chart) var(--ease-out)`, 40ms stagger |
| Donut | each segment `stroke-dashoffset` from full circumference to its target, `var(--d-chart) var(--ease-out)` |
| Hero mascot | idle float `translateY(0 → -4px → 0)`, 6s `var(--ease-in-out)` infinite |
| Skeleton | shimmer gradient sweep 1.4s linear infinite |
| Toast | in: translateY(12px)+opacity, `var(--d-2)`; out: opacity, `var(--d-1)` |
| Sidebar collapse (breakpoint change) | no animation (layout only) |

```css
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;
    transition-duration:.001ms!important;scroll-behavior:auto!important}
  .mascot--float{animation:none}
  .skeleton{background:var(--surface-sunken)}
}
```

Charts render at their final geometry first in the DOM; animation is purely CSS, so reduced-motion
users and tests see final values immediately.

### 1.10 Dark mode

Not included in this pass. The references are light, and the sidebar and hero already supply the
dark anchor. All colours flow through the semantic tokens in 1.3, so a later dark theme is a
second token block under `[data-theme="dark"]` with no component changes. No theme toggle ships
(it would be an inert control until then).

---

## 2. App shell

### 2.1 Structure (one DOM, reflowed by CSS at every breakpoint)

```
<div class="app">
  <nav class="sidebar" aria-label="Primary">
    <div class="sb-id">        avatar disc · "Ascent" · engagement status chip </div>
    <ul class="sb-nav">         6 nav buttons </ul>
    <section class="sb-card">   policy gate mini-card (2.2.4) </section>
  </nav>
  <div class="main">
    <header class="topbar">     <h1> page title · search · refresh · approvals bell </header>
    <div class="screen">        the active screen </div>
  </div>
  <div class="toast-stack">…</div>
</div>
```

The nav buttons exist exactly once. Mobile does not render a second nav; CSS moves the same
`<ul>` into a fixed bottom tab bar (2.4). This keeps the button count stable for tests and avoids
duplicate tab stops.

`Shell` stays presentational. New props (all optional, so `Shell.test` can render it bare):

```ts
interface ShellProps {
  children?: ReactNode;
  active?: NavId;
  onNavigate?: (id: NavId) => void;
  status?: string;                       // existing: "engagement: X" | "no engagement loaded"
  title?: string;                        // page title, defaults from NAV label of `active`
  pendingGates?: number;                 // bell badge + nav badge; undefined = unknown (no badge)
  policy?: { decision: GateDecisionKind; exit_code: number; policy: string } | null; // null = not evaluated
  query?: string; onQueryChange?: (q: string) => void; onSearchSubmit?: () => void;
  onRefresh?: () => void;
}
```

The `aside` prop is removed (no right rail in the new layout; see 3.1).

### 2.2 Sidebar (desktop, ≥1280px)

- Box: `position:sticky; top:16px; height:calc(100vh - 32px); width:var(--sidebar-w)` (256px),
  `border-radius:var(--r-2xl)` (32px), `background:var(--surface-dark)`, `box-shadow:var(--shadow-float)`,
  padding `28px 16px 16px`, flex column, `gap:24px`, `overflow-y:auto` (thin scrollbar).
- Text colour `--ink-on-dark`.

#### 2.2.1 Identity block (`.sb-id`), centred column, gap 10px

- **Avatar disc** `<span class="avatar mascot mascot--avatar" aria-hidden="true">`: 116×116 circle.
  ```css
  .avatar{width:116px;height:116px;border-radius:50%;
    background:url(/mascot/watchdog-avatar.png) center 58% / 92% no-repeat,
               radial-gradient(circle at 35% 30%,#eef5f5 0%,#b9d3d6 68%,#8fb3ba 100%);
    box-shadow:0 0 0 4px var(--slate-550), var(--shadow-clay)}
  ```
  If the PNG is missing the gradient disc still renders (no broken-image icon).
- **Wordmark** "Ascent", `font:800 22px/1.2 var(--font-display)`, `--ink-on-dark`. This is the
  reference's "Hi, Aryan!" slot. Ascent has no user identity, so the greeting with a time of day
  lives in the hero; the sidebar names the product.
- **Engagement chip** (keeps the existing status string and `.dot` / `.dot.idle` classes):
  `display:inline-flex; gap:8px; max-width:100%; padding:6px 12px; border-radius:var(--r-pill);
  background:rgba(255,255,255,.08); font:var(--t-small); color:var(--ink-on-dark-2)`.
  Text truncates with ellipsis; the full string is also in a `title` attribute (plain text).
  `.dot` 8px: active `#6fd0c1` with `0 0 0 4px rgba(111,208,193,.18)`; idle `--slate-300`.

#### 2.2.2 Nav (`.sb-nav`, `<ul role="list">`, gap 6px)

Six items in this order, each `<li><button type="button" aria-label="{label}" aria-current="page"?>`:

| id | Label (aria-label, exact) | Mobile short label | Icon (24px, stroke 1.9, round caps) |
|---|---|---|---|
| overview | Overview | Overview | 2×2 rounded squares (current) |
| newscan | New scan | Scan | crosshair circle (current) |
| findings | Findings | Findings | magnifier with 3 list lines inside the lens |
| gates | Approval gates | Gates | shield with tick (current) |
| report | Report | Report | document with folded corner (current) |
| audit | Audit | Audit | chain links (two rounded links), replaces the clock |

Button content: `<svg aria-hidden> <span class="nav-label">{label}</span> <span class="nav-short" aria-hidden="true">{short}</span>`
plus, for `gates` only, `<span class="nav-badge" aria-hidden="true">{n}</span>` when
`pendingGates > 0` (the accessible count lives on the bell, 2.3). `aria-label` stays equal to the
full label so the accessible name never changes between breakpoints (and every visible short label
is contained in it, satisfying WCAG 2.5.3).

- Size: height 48px, full width, `border-radius:var(--r-md)` (16px), padding `0 14px`, gap 14px,
  `font:600 14.5px/1 var(--font-ui)`, colour `--ink-on-dark-2`, icon colour `--ink-on-dark-2`.
- Hover: `background:rgba(255,255,255,.08); color:var(--ink-on-dark)`.
- **Active (the light pill):** `background:linear-gradient(180deg,#eef4f5 0%,#dbe7e9 100%);
  color:var(--ink); box-shadow:var(--shadow-clay)`; icon colour `--teal-600`.
- Focus: `outline:3px solid var(--focus-on-dark); outline-offset:2px`.
- `.nav-badge`: min-width 22px, height 22px, `border-radius:var(--r-pill)`, `margin-left:auto`,
  `background:var(--badge-count-bg); color:#fff; font:var(--t-micro)`, centred.
- `.nav-short` is `display:none` above 640px.

#### 2.2.3 Spacer

`flex:1` between nav and the bottom card.

#### 2.2.4 Policy gate mini-card (`.sb-card`, replaces "Go Premium")

Rendered only when `policy !== undefined` (i.e. `/api/gate` loaded). Box: `border-radius:var(--r-lg)`
(22px), `background:var(--surface-dark-2)`, padding 16px, inner highlight
`inset 0 1px 0 rgba(255,255,255,.10)`, centred column, gap 10px.

- Clay badge 48px (shield-check glyph) tinted by decision: PASS `--badge-teal`, CONDITIONAL
  `--badge-sand`, FAIL `--badge-coral`, INCOMPLETE / none `--badge-bluegrey`.
- Title `<h2 class="sb-card-title">Policy gate</h2>` `font:700 15px/1.3 var(--font-ui)`, `--ink-on-dark`.
- **Verdict present:** the `VerdictPill` (4.3.3) with the decision text, then one line
  `exit {exit_code} · {policy}` in `font:var(--t-small); color:var(--ink-on-dark-3)` (policy name as
  text, ellipsis). Button "View verdict" (`.btn-ghost-dark`, sm): navigates to Overview and moves
  focus to the Overview policy card heading (`#policy-gate-title`, `tabIndex={-1}`), scrolling it
  into view (`block:"start"`, smooth unless reduced motion).
- **Not evaluated (`null`):** line "No verdict yet" (`--ink-on-dark`, 600) + "Add --policy to
  `ascent run` for a CI exit code." (`--ink-on-dark-3`) and button "Copy --policy flag" that copies
  `--policy ascent-policy.yaml` to the clipboard; label flips to "Copied" for 1.5s (same pattern as
  New Scan's Copy).
- Load error: card not rendered.

### 2.3 Top bar (`<header class="topbar">`)

Not a card: it sits directly on the canvas like the reference ("Dashboard" + search + round icon
buttons). Height 72px, flex row, `align-items:center`, gap 16px, padding `0 4px`.

1. **Page title** `<h1 class="page-title"><span class="sr-only">Ascent Console: </span>{title}</h1>`,
   `font:var(--t-page); letter-spacing:var(--tracking-tight); color:var(--ink)`. Titles: Overview,
   New scan, Findings, Approval gates, Report, Audit log.
2. **Search** (margin-left:auto), a real client-side filter of findings:
   - Markup: `<form role="search" class="search" onSubmit>` containing a magnifier icon (aria-hidden),
     `<input type="search" aria-label="Search findings" placeholder="Search findings, rules, CWEs, paths…">`,
     and a `kbd` hint "/" (aria-hidden, hidden while focused or non-empty).
   - Box: width 360px, height 44px, `border-radius:var(--r-pill)`, `background:rgba(255,255,255,.78)`,
     `border:1px solid var(--border-soft)`, inset `0 2px 4px rgba(31,45,58,.06)`, padding `0 16px`.
     Focus-within: `outline:3px solid var(--focus); outline-offset:2px`.
   - Matching: lower-cased query split on whitespace; every term must be a substring of
     `title | rule_id | locus | cwe | category | tool` (lower-cased, joined by space). Pure function
     `matchFinding(item, query)` in `src/data/search.ts`.
   - Behaviour: the query lives in `App` state and survives navigation. On **Findings** it filters the
     table live. On **Overview** it filters the "Top findings" list card live. On every other screen,
     typing does nothing visible until **Enter**, which navigates to Findings with the query applied;
     while focused there, a 1-line hint under the field reads "Press Enter to search findings"
     (`role="status"`, `--ink-2` on a white popover 12px radius, no data in it).
   - Keys: "/" focuses search when focus is not in an input/textarea/select; Esc clears and keeps focus.
3. **Refresh** icon button (`aria-label="Refresh data"`): bumps every resource version (5.2), so all
   visible cards refetch. Icon: circular arrow. While any refetch is in flight the icon spins (1s
   linear; static under reduced motion) and the button has `aria-busy="true"`.
4. **Approvals bell** icon button: `aria-label="Pending approvals: {n}"` (or "Pending approvals"
   while unknown). Click navigates to Approval gates. Badge: 20px circle top-right, `--badge-count-bg`,
   white `font:var(--t-micro)`, `aria-hidden`; hidden when n is 0 or unknown.

Icon button: 44×44 circle, `background:linear-gradient(180deg,#ffffff 0%,#eef2f5 100%)`,
`border:1px solid var(--border-soft)`, `box-shadow:var(--shadow-clay)` at 60% strength
(`0 6px 12px -6px rgba(20,35,50,.30), inset 0 2px 2px rgba(255,255,255,.9), inset 0 -2px 4px rgba(20,35,50,.10)`),
glyph 20px `--ink`. There is deliberately no profile/avatar button (no user model exists).

### 2.4 Responsive behaviour

| Breakpoint | Sidebar | Top bar | Content |
|---|---|---|---|
| ≥1280px | 256px expanded (2.2) | as 2.3 | `.main` max-width `--content-max` 1184px, centred in remaining space |
| 1024–1279px (laptop ~1040) | **88px icon rail**: avatar 56px, wordmark and engagement text visually hidden (still in DOM; status chip collapses to its dot with `title`), nav = 56×48 icon buttons, `.nav-label` becomes a hover/focus tooltip (absolutely positioned pill right of the rail, `--slate-800` bg, `--ink-on-dark`, 13px, shown on `:hover`/`:focus-visible`, otherwise clipped with the `.sr-only` technique so the name persists), nav badge becomes an 10px dot top-right of the icon; policy mini-card becomes a 56px round button showing its clay badge only, `aria-label="Policy gate: {decision}"` or "Policy gate: not evaluated", same click behaviour as "View verdict" / copy | search width 280px | grids per section 3 |
| 641–1023px | 88px icon rail as above | title 26px; search wraps to its own full-width row under the title (`flex-wrap`) | KPI 2×2; all other cards full width |
| ≤640px | Becomes two bars. **Top app bar** (`.sb-id`): sticky top, 60px, full width, radius `0 0 24px 24px`, `--surface-dark`, row: avatar 40px, "Ascent" 18px, status chip (ellipsis) flex 1. **Bottom tab bar** (`.sb-nav`): `position:fixed; left:12px; right:12px; bottom:calc(12px + env(safe-area-inset-bottom))`, height 64px, radius 24px, `--surface-dark`, `--shadow-float`, 6 equal columns, each button a 44px-min-height column with 22px icon over `.nav-short` (12px, 600); `.nav-label` visually hidden. Active = light pill behind icon only (40×32, radius 12). Policy mini-card hidden. | Not sticky. Row 1: title (24px) + refresh + bell; row 2: full-width search | single column, gutter 16px, `padding-bottom:96px` so the tab bar never covers content; KPI 2×2 (tiles 148px tall); tables become stacked cards (4.7) |

Toast stack: bottom-right 24px on desktop; ≤640px full width with 12px side gutters and
`bottom:calc(88px + env(safe-area-inset-bottom))` (above the tab bar).

---

## 3. Screens

### 3.0 Data layer (applies to every screen)

New `frontend/src/data/resources.ts`: a tiny cache with no dependency.

```ts
type Key = "findings" | "gates" | "audit" | "report" | "engagement" | "gate";
// Module-level Map<`${key}@${version}`, Promise<T>>; useResource(key, version) returns
// { status: "loading" } | { status: "error"; retry(): void } | { status: "ready"; data: T }.
export function __resetResourceCache(): void;   // called in src/test/setup.ts afterEach
```

`App` owns `versions: Record<Key, number>` and exposes `bump(...keys)`. Rules:

- Refresh button: bump all six.
- Gate decision recorded (or 409 "already decided"): bump `gates` and `audit` (replaces
  `auditVersion`; also updates the bell and hero counts).
- New scan created: bump `engagement` (replaces `engVersion`), plus `report`, `findings`, `gates`,
  `audit`, `gate` so the console reflects the newly loaded engagement.
- Each existing screen component keeps working standalone (tests render `<Findings />`,
  `<Gates />`, `<Audit />`, `<Report />`, `<PolicyGate />` alone): each calls `useResource` with
  version 0 when no version prop is passed.
- Every card is wrapped in its own `ErrorBoundary` (as today) so one malformed payload fails one
  card. Exactly one component per screen renders finding titles, and exactly one renders gate
  titles (the App tests rely on a single "This view failed to render.").

`App` additionally owns `query` (2.3) and `verdictFilter: Verdict | "ALL"` (3.3), both preserved
across navigation.

### 3.1 Overview

Content column is a 12-column CSS grid, gap 20px. No right rail: the old rail contents (approval
gates and audit feed) become list cards in row 5.

| Row | ≥1280px | 1024–1279 | 641–1023 | ≤640 |
|---|---|---|---|---|
| 1 | Hero (12) | Hero (12) | Hero (12) | Hero |
| 2 | 4 KPI tiles (3 each) | 4 KPI (3) | KPI (6) ×4 | KPI 2×2 |
| 3 | Policy gate card (12) | (12) | (12) | full |
| 4 | Severity bar chart (7) + Verdict donut (5) | 7 + 5 | 12 + 12 | stacked |
| 5 | Top findings (4) + Pending approvals (4) + Recent audit (4) | Top findings (6) + Pending approvals (6); Recent audit (12) | 12 each | stacked |
| 6 | Report banner (12) | (12) | (12) | full |

#### 3.1.1 Hero banner (`OverviewHero`)

- Box: `min-height:184px` (≥1024), `border-radius:var(--r-2xl)`, `background:var(--surface-hero)`,
  `box-shadow:var(--shadow-float)`, `overflow:visible` (the mascot breaks the top edge), `position:relative`,
  padding `28px 32px 28px 280px`.
- **Mascot** `<span class="mascot mascot--hero mascot--float" aria-hidden="true">`:
  232×232, `position:absolute; left:28px; bottom:0`, `background:url(/mascot/watchdog-hero.png) center bottom/contain no-repeat`,
  `filter:drop-shadow(0 16px 18px rgba(20,35,50,.35))`. Its head overlaps the top edge by 48px.
- **Waves** (replaces the reference plant): inline `<svg aria-hidden="true" class="hero-waves">`
  absolutely positioned right 0, bottom 0, 46% wide, full height, clipped by a wrapper with the
  same radius; three stacked wave paths:
  `M0 120 C 80 90 160 150 260 118 S 420 80 520 110 V 184 H 0 Z` (fill `--slate-500`, opacity .35),
  the same path translated +22px y (fill `--teal-500`, opacity .28), +44px y (fill `--slate-300`,
  opacity .22). `viewBox="0 0 520 184" preserveAspectRatio="none"`. A `<pattern>` of 1px horizontal
  lines every 4px (`stroke:#fff`, opacity .06) fills the top wave to suggest knitted fabric. No text
  ever sits on the waves: the text column ends at 58% width.
- **Text column** (max-width 520px), colours on dark:
  1. `<p class="hero-greet">Good {morning|afternoon|evening}!</p>` `font:var(--t-hero); color:var(--ink-on-dark)`.
     Morning 05:00–11:59, afternoon 12:00–17:59, evening 18:00–04:59, local time, computed on render.
  2. `<p class="hero-eng">` `font:600 15px/1.4 var(--font-ui); color:var(--ink-on-dark-3)`:
     engagement loaded → "Watching **{name}**" (name as text, bold `--ink-on-dark`, ellipsis at one line);
     none → "Define a scope to get started."; engagement fetch error → line omitted.
  3. `<p class="hero-sum">` `font:var(--t-small); color:var(--ink-on-dark-3)`, built only from loaded
     data, parts joined by " · ": `{hu} need your review` (when findings loaded and hu > 0),
     `{n} approval(s) pending` (when gates loaded and n > 0), `policy {DECISION}` (when a verdict
     exists). If findings and gates are loaded and both counts are 0 and no verdict: "All quiet. Nothing
     needs you right now." Never a finding title.
  4. CTA row, gap 12px, margin-top 16px: primary pill **"Define a new scan"** (crosshair icon,
     44px) → `onNavigate("newscan")`; when n > 0, ghost-on-dark pill **"Review approvals"** → gates.
- 641–1023: padding-left 220px, mascot 184px. ≤640: height auto, padding `24px 20px`, mascot 120px
  absolute top-right (`right:12px; top:-20px`), text column `padding-right:110px` for the first two
  lines, CTAs full-width stacked.

#### 3.1.2 KPI row (`KpiTile` ×4, see 4.1)

| Tile | Tint / badge | Icon glyph | Label (`.l`, exact) | Number (`.n`) | Sub-line (`.sub`) | Click |
|---|---|---|---|---|---|---|
| 1 | teal | radar sweep (circle + arc + dot) | Findings | total | "from {k} scanners" when ≥1 finding has `tool` (k = distinct tools), else "triaged by Crux" | Findings, filter ALL |
| 2 | blue-grey | target with tick | True positive | tp | "{p}% · confirmed by triage" | Findings, filter TRUE_POSITIVE |
| 3 | frosted ice | hand raised / person with "?" | Needs human | hu | "{p}% · awaiting your review" | Findings, filter ABSTAIN |
| 4 | lavender | funnel with a slash | Likely noise | fp | "{p}% · cut by Crux" | Findings, filter LIKELY_FALSE_POSITIVE |

No deltas: the API has no history, so there are no "+16% this week" lines. `p` = rounded share of
total (0 when total is 0). Loading: 4 skeleton tiles. Error: one alert card spanning the row,
"Could not load findings" + Retry.

#### 3.1.3 Policy gate card

The restyled `PolicyGate` (4.4), full width. Its `<h2>` gets `id="policy-gate-title" tabIndex={-1}`
(target of the sidebar "View verdict").

#### 3.1.4 Charts

- **Findings by severity** (`SeverityBarChart`, 4.2.1). Header right: segmented control
  "All" / "Confirmed" (Confirmed = TRUE_POSITIVE only). Real client-side switch.
- **Verdict mix** (`DonutCard`, 4.2.2). Header right: segmented control "Verdict" / "Category".
  Verdict mode: True positive / Needs human / Likely noise. Category mode: DAST / SAST / SCA /
  Uncategorised (finding with no `category`). Title text switches to "Category mix".
- Both share the findings resource; loading = skeleton chart; error = card-level alert with Retry;
  empty (0 findings) = chart drawn empty (4.2) with the sub-line "No findings yet".

#### 3.1.5 List cards (4.6)

1. **Top findings**: first 5 of the existing order (TP first, then needs-human, then noise;
   confidence desc), filtered by the search query. Row: `SeverityChip`, title (`--t-h3`, 1 line
   ellipsis, `title` attribute = title text), meta line `rule_id` (mono, `--ink-3`), trailing
   `VerdictChip`. Header: "Top findings", count pill "{total} triaged" (or "{m} of {total} match" with
   a query), "See all" → Findings. Rows are not interactive. Empty: rest mascot 96px + "No findings
   yet". With a query and no match: "No findings match “{query}”" (query as text) + text button
   "Clear search".
2. **Pending approvals**: the `Gates` component in `variant="compact"` (4.5). Header title
   "Approval required" (exact, kept), count pill "{n} pending", "See all" → Approval gates. Shows the
   first 3 gates; if more, a footer link-button "{n-3} more in Approval gates". Approve / Deny work
   here exactly as today and call `onDecided` (bump gates + audit). Empty: rest mascot 96px +
   "No actions awaiting approval".
3. **Recent audit**: header "Recent audit", the chain chip ("Hash chain OK", `role="status"`, or the
   coral alert "Hash chain FAIL: log may have been tampered with", `role="alert"`), "See all" → Audit.
   Body: last 5 entries newest first, using the shared `AuditEntryRow` (3.6) in compact density.
   Empty: "No audit entries yet".

#### 3.1.6 Report banner (bottom CTA)

Full-width card variant: height 112px (auto on mobile), `border-radius:var(--r-xl)`,
`background:var(--surface-banner)`, `--shadow-card`, padding `0 28px`, row layout: clay badge 56px
(`--badge-sand`, document glyph), text block, CTA at right. Decorative fabric: `::after` with
`/textures/fabric-wave.jpg` on the right 38%, `opacity:.55`, masked `linear-gradient(to right,transparent,#000 40%)`;
the CTA button sits on it with its own solid background; text never overlaps it.

- Report non-empty: title "Your report is ready" (`--t-h2`, `--ink`), sub "Findings, the policy
  verdict and DAST coverage in one markdown report." (`--t-small`, `--ink-2`), CTA primary
  "Open report" → Report.
- Report empty: "No report yet" / "Run `ascent run` on a defined scope and the report lands here.",
  CTA primary "Define a new scan" → New scan.
- Loading: skeleton bar. Error: banner not rendered.

### 3.2 New scan

Two-column grid at ≥1024px: form card (7 cols) + guidance card (5 cols), `align-items:start`.
Single column below 1024 (form first).

**Form card** (`<section class="card">`, `<h2>` "Define a new scan", head pill "defines scope — does
not launch" kept verbatim as a `.count` pill). Form `noValidate`, fields stacked with 20px gap:

| Field | Control | Label (exact) | Hint (`--t-small`, `--ink-2`) |
|---|---|---|---|
| name | `input` | Engagement name | none; placeholder "e.g. Acme staging — Q4" |
| targets | `textarea` mono, min-height 148px | Targets | "One per line: a hostname, IP, CIDR, or URL. Authorised scope only — Ascent will refuse to test anything outside this list. Subdomains of a listed host are included." |
| source | `input` | Source directory for SAST (optional) | existing hint text |
| dast profile | native `select` (4.8) | DAST profile | dynamic per option (below) |
| auth header | `input` in fieldset | Auth header name | placeholder "Authorization" |
| auth env | `input` in fieldset | Env var holding its value | placeholder "ASCENT_DAST_AUTH" |

- DAST profile options, in order: "Passive", "Standard" (default, selected), "Active". The hint
  under the select changes with the value:
  Passive "Fingerprinting and passive checks only. Sends no attack payloads.";
  Standard "Known-vulnerability and misconfiguration templates. The default.";
  Active "Adds parameter fuzzing — use only on targets you may actively test." Active's hint renders
  inside a sand callout (`background:var(--sand-50); border:1px solid var(--sand-300); color:var(--sand-800)`,
  radius 12px, warning-triangle icon, `aria-live="polite"` on the hint container).
  Option values and the posted field names follow whatever the in-flight DAST work defines
  (`docs/superpowers/specs/2026-10-31-dast-coverage-design.md`, "Dashboard" section); this spec only
  styles them.
- The two auth inputs sit in `<fieldset class="fieldset">` with `<legend>` "Authenticated scanning
  (optional)" (`--t-h3`) and the note "The header value never enters the console. Ascent reads it from
  this environment variable at run time." Side by side at ≥1024 (1fr 1fr, gap 16px), stacked below.
- Under the fields, the existing note, verbatim, in an info row with a small info icon:
  "Creating a scan writes a scope file. Running it is a separate, explicit step, and every exploit
  action still requires your approval in the gates."
- Error (`role="alert"`): `--err-bg`/`--err-ink`/`--err-border` callout, radius 16px, alert-circle
  icon, message text, then rejected targets as mono chips (`code`, wrapping). If the error carries
  `field`, the matching control gets `aria-invalid="true"`, `aria-describedby` pointing at the
  callout, and a 2px `--coral-700` border.
- Submit: primary pill "Create scan" (44px, `align-self:flex-start`); busy label "Creating…",
  `disabled`, `aria-busy`.

**Guidance card** (right), `background:var(--surface)`:
- Before success: `<h2>` "What happens next", three numbered steps, each a row with a 32px clay
  number disc (`--badge-teal`, white Nunito 800 15px) and text:
  1 "**Define the scope here.** Ascent writes a validated engagement file and refuses anything
  outside it." 2 "**Run it from your terminal.** You get the exact `ascent run` command to copy."
  3 "**Approve or deny each gate.** Approving records consent; nothing runs from this console."
  Bottom: avatar-size mascot (96px circle, the avatar art) beside the line "Scope first, always."
  (`--ink-2`). All copy is static.
- After success the card is replaced by the **success card** (`role="status"`), keeping current
  content: `<h3>` "Scan defined: {name}", scope lists (Hosts / CIDRs / URLs as mono chips, SAST
  source), "Run it from your terminal:", command block (4.5 command style, full text, wraps) with a
  secondary pill "Copy" → "Copied" for 1.5s, the `--policy samples/ascent-policy.example.yaml` hint,
  and the "The console now reflects this engagement…" note. Card tint `--ok-bg`, border
  `--ok-border`, heading `--ok-ink`, clay tick badge 40px top-left.

### 3.3 Findings

Stack, gap 20px:

1. **KPI row**: the same four `KpiTile`s as Overview, but here they are **filter toggles**:
   `<button aria-pressed>`; "Findings" = ALL. Pressed state: 2px `--teal-600` inner ring
   (`box-shadow: inset 0 0 0 2px var(--teal-600), var(--shadow-clay)`) and a small tick in the
   badge corner. Clicking the pressed tile resets to ALL. Height 132px here (compact: badge 40px,
   number 30px).
2. **Table card**: header `<h2>` "Findings", count pill "{total} triaged"; when a filter or query is
   active, a second pill "{m} shown" and a text button "Clear filters" (resets verdict filter and
   query). Table per 4.7. Empty (0 findings): rest mascot 160px, "No findings yet" (exact), sub
   "Define a scan, run it, and triaged findings land here.", primary pill "Define a new scan" when an
   `onNavigate` prop is supplied. No match: "No findings match these filters" + "Clear filters".
3. Loading: `role="status"` card with three skeleton rows and visible caption "Loading findings…".
   Error: `role="alert"` `ErrorState` "Could not load findings", "Check that the Ascent backend is
   running.", Retry.

Order and the location/locus logic are unchanged.

### 3.4 Approval gates

1. **Intro strip** (card, `background:var(--ice-100)`, border `var(--ice-200)`, radius 22px, row):
   clay shield badge 48px (`--badge-ice`), `<h2>` "Approval required" (exact) with count pill
   "{n} pending", and the line "Detect-only verification gates. Approving records your consent in
   the hash-chained audit log. It never runs anything from this console." (`--ink-2`).
2. **Gate grid**: `display:grid; grid-template-columns:repeat(auto-fill,minmax(420px,1fr)); gap:20px`
   (single column ≤640). Each item is the full `GateCard` (4.5).
3. Empty: rest mascot 180px centred in a card, "No actions awaiting approval" (exact), sub "When
   triage proposes a verification step, it waits here for you."
4. Loading: two skeleton gate cards + `role="status"` "Loading approval gates…". Error: `role="alert"`
   `ErrorState` "Could not load approval gates", "check that the Ascent backend is running", Retry
   (existing behaviour).
5. Toasts: unchanged logic (4.10).

### 3.5 Report

- Layout ≥1280: report card (max-width 820px) + sticky section index (220px) to its right, gap 24px.
  Below 1280 the index is hidden (`display:none`, so it leaves the a11y tree too).
- Report card: padding `40px 48px` (≤640: `24px 20px`), `background:var(--surface-raised)` at 96%
  (long reading surface, maximum contrast).
- Typography (all under `.report`): `.report-title` (still a `div`, not an h1) `font:var(--t-report)`;
  `h2` `800 22px/1.3 var(--font-display)`, margin `32px 0 12px`, padding-top 20px, top border
  `1px solid var(--border-soft)` (none on the first); `h3` `--t-h3` margin `20px 0 8px`; `p, li`
  `400 15px/1.7 var(--font-ui)`; links `--link`, 600, underline offset 3px; inline `code`
  `--t-mono` on `--surface-sunken`, radius 6px, padding `1px 6px`; `pre` `--code-bg`, radius 16px,
  padding `14px 16px`, overflow auto; `blockquote` 4px left bar `--teal-300`, `--ink-2`.
- Tables (the new "DAST coverage" table and others): wrapper `display:block; overflow:auto;
  border-radius:16px; border:1px solid var(--border-soft)`; `th` `--surface-sunken`,
  `font:var(--t-micro)` uppercase tracking `--tracking-caps`, `--ink-2`; `td` 13.5px, padding
  `10px 14px`; zebra rows `#f7f9fa`. Cells are plain markdown text; no status colouring is inferred
  from cell content.
- **Section index** (`<nav aria-label="Report sections">`): after render, a `useEffect` reads the
  `textContent` of each `.report h2`, assigns `id="r-{slug}"` (slug = lower-case, `[^a-z0-9]+` → "-",
  de-duplicated with `-2`, `-3`), and renders a list of in-page links `href="#r-{slug}"` with the
  heading text as React text. Card style, title "On this page" `--t-micro` caps `--ink-2`, links
  13.5px `--ink`, active section (IntersectionObserver) gets a 3px `--teal-500` left bar.
- The existing safety rules in `Report.tsx` stay verbatim (no raw HTML, `img` → "[image: alt]",
  external links `target="_blank" rel="noopener noreferrer"`). The Report screen renders **no** mascot
  when content is present.
- Empty: card with rest mascot 160px, "No report yet. Run a scan to generate one." (exact).
  Loading/error as other screens.

### 3.6 Audit

1. **Chain status card** (row, full width): clay badge 56px (chain glyph; `--badge-teal` when OK,
   `--badge-coral` when FAIL) and the status element:
   OK → `<div role="status" class="chain chain-ok">Hash chain OK</div>` (`--ok-bg`, `--ok-ink`,
   pill, 14px 700); FAIL → `<div role="alert" class="chain chain-fail">Hash chain FAIL: log may have
   been tampered with</div>` (solid `--p-fail`, white, 15px 700, `--shadow-clay`). To the right,
   "{N} entries" (`--ink-2`).
2. **Type filter**: segmented control (4.9) labelled "Show": `All {N}` · `Verdicts {a}` ·
   `Decisions {b}` · `Policy {c}` · `Runs {d}` (triage, gate_decision, gate_evaluation,
   gate_execution). Options with 0 are `disabled`. The labels deliberately avoid the row titles
   ("Triage", "Human decision", "Policy gate", "Verification run") so text queries stay unambiguous.
3. **Timeline card**: entries in log order (oldest first, as today) inside `.feed`
   (`max-height:calc(100vh - 280px)`, overflow auto; ≤640 no cap). Shared `AuditEntryRow`:
   - 32px node on a 2px vertical rail (`--border-soft`): clay disc 28px with glyph per type: triage
     (magnifier, `--badge-teal`), human decision (hand, `--badge-lav`), policy gate (shield,
     `--badge-sand`), verification run (play-in-circle, `--badge-ice`).
   - Line 1 (`--t-body`): `<b>{Title}</b> · {detail}` with today's exact strings, e.g.
     "Triage · finding {id} → {verdict} ({conf})", "Human decision · gate {id} → {decision}",
     "Policy gate · {decision} (exit {code})", "Verification run · gate {id} → {outcome}".
   - Line 2: `ts` raw string (`--t-mono-sm`, `--ink-3`) and the 12-char hash in a mono chip
     (`--surface-sunken`, radius 8px). No `aria-label`: the visible hash text is the name.
   - Compact density (Overview): no rail, 24px disc, 8px row gap.
4. Empty: "No audit entries yet" (exact) with rest mascot 120px. Loading/error as elsewhere.

### 3.7 Mascot placements (complete list)

| Where | Asset | Size (CSS px) | Notes |
|---|---|---|---|
| Sidebar avatar | watchdog-avatar.png | 116 (rail 56, mobile 40) | disc background, 2.2.1 |
| Overview hero | watchdog-hero.png | 232 (tablet 184, mobile 120) | floats, breaks top edge |
| New scan guidance card | watchdog-avatar.png | 96 circle | static |
| Empty states (Top findings, Pending approvals, Findings, Gates, Report, Audit) | watchdog-rest.png | 96–180 per section | `EmptyState` |
| Error states (`ErrorState`, `ErrorBoundary`) | watchdog-puzzled.png | 96 | `ErrorState` |

Every placement is an `aria-hidden` element with a CSS background (non-negotiable 2).

---

## 4. Component specs

### 4.1 `KpiTile` (replaces `Kpi`)

```ts
interface KpiTileProps { label: string; value: number; sub: string;
  tone: "teal" | "bluegrey" | "ice" | "lav"; icon: ReactNode;
  pressed?: boolean; onClick?: () => void; compact?: boolean }
```

- Root: `<button type="button" class="kpi kpi--{tone}" aria-pressed?>` when `onClick` is set, else
  `<div class="kpi …">`. Keeps the class names `.kpi`, `.l`, `.n`, `.sub` (tests query them).
- Box: `min-height:168px` (compact 132px), radius 24px, `background:var(--tile-{tone})`,
  `border:1px solid rgba(255,255,255,.55)`, `box-shadow:var(--shadow-clay)` softened
  (`inset 0 1px 0 rgba(255,255,255,.8), 0 10px 22px -12px rgba(20,35,50,.30)`), padding 20px, column,
  `justify-content:space-between`, text-align left.
- Contents: `IconBadge` 48px (compact 40px) with `--badge-{tone}`; label `.l` `700 15px/1.3`
  `--ink`; number `.n` `font:var(--t-kpi)` (compact 30px) `--ink`, tabular; sub `.sub`
  `600 13px/1.4` `--ink-tile`.
- Interactive tile: hover lift (1.9), focus `outline:3px solid var(--focus); outline-offset:3px`
  (≥3.25:1 on every tint).

### 4.2 Chart cards

Both are `<section class="card chart-card">` with `<h2>` + segmented control in `.card-head`, and
an SVG with `role="img"` and an `aria-label` that states every value (e.g. "Findings by severity:
Critical 2, High 5, Medium 3, Low 1, Info 0"). Every value is also printed as visible text (bar
value labels; donut legend), so colour is never the only carrier.

#### 4.2.1 `SeverityBarChart`

- `viewBox="0 0 520 240"`, `width:100%; height:240px`, `preserveAspectRatio="none"` is **not** used
  (keep proportions; the card height follows).
- Plot area: x 44→508 (w 464), y 20→196 (h 176). Five categories in fixed order CRITICAL, HIGH,
  MEDIUM, LOW, INFO, labelled "Critical", "High", "Medium", "Low", "Info". Band = 464/5 = 92.8;
  bar width 44; bar x = 44 + band·i + (band − 44)/2.
- Scale: `step = niceStep(max(1, maxCount)/4)` with niceStep picking the smallest of
  1, 2, 5, 10, 20, 50, … ≥ the input; `yMax = step·4`; ticks at 0, step, 2·step, 3·step, 4·step.
  Gridlines: `stroke:var(--slate-200); stroke-width:1; stroke-dasharray:3 5`; tick labels at x=36,
  `text-anchor:end`, `font:var(--t-micro)` weight 600, fill `--ink-2`.
- Bar: height h = 176·count/yMax; path with rounded top only, r = min(10, w/2, h):
  `M x,196 V {196-h+r} Q x,{196-h} {x+r},{196-h} H {x+w-r} Q {x+w},{196-h} {x+w},{196-h+r} V 196 Z`.
  Fill: `linearGradient` per severity (vertical): offset 0 = base colour mixed 22% white, offset .35 and
  1 = base `--sev-*`. Under-shadow: a copy of the path offset +4px y, fill `rgba(20,35,50,.12)`,
  `filter: blur(3px)` via SVG `feGaussianBlur stdDeviation="3"`. Zero count: a 44×4 rounded stub,
  fill `--slate-200`.
- Value label above each bar: y = 196 − h − 8, `text-anchor:middle`, `700 13px var(--font-ui)`,
  fill `--ink`. X labels at y = 218, `--t-micro` 600, fill `--ink-2`.
- Segmented "All" / "Confirmed" recomputes counts.

#### 4.2.2 `DonutCard`

- Layout: row, donut 200×200 left, legend right (column, gap 12px); ≤640 stacked, legend full width.
- SVG `viewBox="0 0 200 200"`: centre (100,100), r = 72, stroke-width 28, circumference
  C = 2π·72 = 452.389. Track circle stroke `--slate-100`. For segment i (value v, total T, cumulative
  before it S): `stroke-dasharray = "${max(C·v/T − gap, 0)} ${C}"`, `stroke-dashoffset = −C·S/T`,
  `transform="rotate(-90 100 100)"`, `stroke-linecap:butt`, gap = 3 when ≥2 non-zero segments else 0.
  Segments with v = 0 are not drawn.
- Clay depth: the segment group gets `filter:drop-shadow(0 6px 10px rgba(31,45,58,.18))`; an inner
  disc r = 58 filled with `radial-gradient`-equivalent SVG `radialGradient` (#ffffff → #eef2f5)
  and a 1px `--border-soft` stroke.
- Centre: total in `font:var(--t-kpi)` `--ink` at y = 104, and "findings" `--t-micro` `--ink-2` at y = 126.
- Legend row: 12px dot (segment colour, 1px white ring), label `600 14px` `--ink`, count
  `700 14px` tabular `--ink` right-aligned, percent `--t-small` `--ink-2` (min-width 44px, right).
- Colours: verdict mode `--v-tp`, `--v-hu`, `--v-fp`; category mode `--cat-dast`, `--cat-sast`,
  `--cat-sca`, `--cat-none`.
- Empty (T = 0): track only, centre "0", legend rows show 0 and "0%".

### 4.3 Chips and pills

All chips: `display:inline-flex; align-items:center; gap:6px; white-space:nowrap`. Text from fixed
enum tables only.

1. **`SeverityChip`** (was `SeverityBadge`): height 24px, padding `0 10px`, radius `--r-xs` (8px:
   square-ish, so it reads differently from verdict pills), `font:var(--t-micro)` weight 800,
   uppercase, tracking `--tracking-caps`; bg/ink per `--sev-*-bg` / `--sev-*-ink`. Text = the
   severity enum (CRITICAL…INFO). INFO gets its own info colours now (it shared LOW before).
2. **`VerdictChip`**: height 28px, padding `0 12px 0 10px`, radius pill, `700 12.5px`, leading 8px dot
   (`--v-*`), bg/ink `--v-*-bg` / `--v-*-ink`. Labels unchanged: True positive / Needs human /
   Likely noise; unknown verdicts fail safe to Needs human.
3. **`VerdictPill`** (policy decision): height 28px, padding `0 14px`, radius pill,
   `800 12px` tracking .08em uppercase. PASS `--p-pass`/white, CONDITIONAL `--p-cond`/`--p-cond-ink`,
   FAIL `--p-fail`/white + `box-shadow:0 8px 18px -10px var(--coral-700)`, INCOMPLETE
   `--p-inc`/`--p-inc-ink`, NOT EVALUATED same as INCOMPLETE with a `1.5px dashed var(--slate-300)` border.
   Text is the decision string exactly ("PASS", "FAIL", …, "NOT EVALUATED").
4. **Tag** (CWE, category): height 24px, padding `0 8px`, radius 8px, `--t-mono-sm` 500,
   `--ink-2` on `--surface-sunken`.
5. **Count pill** (`.count`): height 24px, padding `0 10px`, radius pill, `700 12px`,
   `--ok-ink` on `--ok-bg`.
6. **DETECT-ONLY badge**: height 22px, padding `0 9px`, radius pill, `800 12px` tracking .06em,
   `--ok-ink` on `--ok-bg`, `1px solid var(--ok-border)`.
7. **Scope badges**: In scope = tick icon + "In scope", `700 12.5px`, `--teal-650`; out of scope =
   "Out of scope: approval is blocked", `700 12.5px`, `--coral-750` (6.84:1 on white; the
   `.scope-bad` contrast test keeps passing).
8. **`SeverityStripe`**: 5px wide, `top:10px; bottom:10px; left:0`, radius 5px, fill `--sev-*`.
9. **`ConfidenceBar`**: track 8px, radius pill, `--surface-sunken`, inset `0 1px 2px rgba(31,45,58,.10)`;
   fill radius pill: TP `linear-gradient(90deg,var(--teal-600),var(--teal-500))`, needs-human
   `linear-gradient(90deg,var(--sand-500),#c9a24a)`, noise `linear-gradient(90deg,var(--slate-400),var(--slate-300))`;
   value `--t-mono-sm` 500 `--ink-2`, 2 decimals, min-width 34px.

### 4.4 `PolicyGate` card

- `<section class="card policy policy--{decision}" aria-labelledby="policy-gate-title">`; tint
  `background:var(--p-*-tint)` (opaque; the frosted surface is not used here so contrast is exact);
  FAIL additionally gets a 6px left accent bar (`::before`, `--coral-700`, radius `28px 0 0 28px`).
- **Head row**: clay badge 56px (`--badge-teal|sand|coral|bluegrey` by decision; glyph: tick, "!",
  "×", "…" respectively), then a column: `<h2 id="policy-gate-title" tabIndex={-1}>Policy gate</h2>`
  and the headline (the existing `LABEL` strings: "Policy passed", "Passed with warnings",
  "Policy failed", "Scan incomplete — cannot pass") in `800 20px/1.25 var(--font-display)`
  colour `--p-*-head`. Right side (wraps under on ≤640): `VerdictPill` {decision}, mono chip
  "exit {code}", and `policy {name} · {hash12}` in `--t-mono-sm` `--ink-2`.
- **Counts**: four mini stat blocks in a row (wrap 2×2 ≤640): white 70% surface, radius 16px,
  padding `10px 14px`, number `800 20px Nunito` `--ink` + label `--t-small` `--ink-2`: failing,
  warnings, demoted likely-FP, evaluated. The existing strings remain present as text:
  "{n} failing", "{n} warnings", "{n} demoted likely-FP", "{n} evaluated" (number in `<b>`).
- **INCOMPLETE reason** callout (exact existing sentences): `background:rgba(255,255,255,.65)`,
  radius 14px, info icon, `--ink-2`.
- **Top failing list** (failed, else warned; first 5): each row a white rounded row (radius 14px,
  padding `10px 14px`, `--shadow-card` light): `SeverityChip`, title (`--t-h3`), locus
  (`--t-mono-sm` `--ink-2`), reason pushed right (`--t-small` `--ink-2`). ≤640 rows wrap.
- **Footer note**: "Read-only verdict from out/gate.json[, evaluated {ts}]. It is chained into the
  audit log." `--t-small` `--ink-2`, with a lock icon.
- **Not evaluated**: tint `--p-inc-tint`, `VerdictPill` "NOT EVALUATED", and the existing body text
  with `--policy` code chips.
- Loading: skeleton block 160px + caption "Loading policy gate…" (`role="status"`). Error:
  `role="alert"` `ErrorState` "Could not load the policy gate" + Retry.

### 4.5 `GateCard` and `Gates` variants

`Gates` gets `variant?: "page" | "compact"` (default `"page"`; tests render the default). One gate =
one `<article class="gcard" aria-labelledby>`:

- Box: `background:var(--surface-raised)`, radius 24px, border `1px solid var(--border)`,
  `--shadow-card`, padding 22px (compact 16px), column, gap 14px (compact 10px).
- Head: clay shield badge 40px (`--badge-ice`; compact 32px), `<h3>` title (`--t-h3`, wraps) and the
  DETECT-ONLY badge when `detect_only === true`.
- `why` paragraph (`--t-body` `--ink-2`).
- "Target:" label (`--t-micro` caps `--ink-2`) + target in a mono tag (wraps, `word-break:break-word`).
- Command block: `--t-mono`, `color:var(--code-ink)`, `background:var(--code-bg)`,
  `border:1px solid var(--code-border)`, radius 14px, padding `12px 14px`, `white-space:pre-wrap;
  word-break:break-word`. Always shown in full (consent requires seeing the full command), both
  variants.
- Expected evidence / Why it might fail: page variant shows them inline as two blocks with bold
  labels exactly "Expected evidence:" and "Why it might fail:". Compact variant puts both in
  `<details class="gdetails"><summary>More context</summary>…</details>` (same label text inside).
- Scope badge (4.3.7).
- Actions row, gap 10px: **Approve** primary pill (flex 1, height 44px, compact 40px), disabled when
  out of scope or busy; **Deny** danger-soft pill (height 44/40, padding `0 20px`), disabled when busy.
  Busy: the clicked button shows a 14px spinner before its label; labels stay "Approve"/"Deny".
- Consent note (always, both variants), with an info icon, `--t-small` `--ink-2`, left-aligned:
  "Every decision is written to the audit log. Approving records consent; it does not run the command."

### 4.6 `ListCard`

```ts
interface ListCardProps { title: string; count?: ReactNode; seeAll?: { label: string; onClick(): void };
  headExtra?: ReactNode; children: ReactNode }
```

- `<section class="card list-card">`, head: `<h2>` title, count pill, `headExtra`, and at right the
  "See all" button: secondary pill sm (height 32px, padding `0 14px`, `700 12.5px`); visible text
  "See all" plus `<span class="sr-only"> {label}</span>` so names are unique ("See all findings",
  "See all approval gates", "See all audit entries").
- Rows: min-height 56px, padding `10px 4px`, gap 12px, divided by `1px solid var(--border-soft)`
  (not after the last). Non-interactive rows get no hover style.

### 4.7 Findings table

- Wrapper `.tbl` `overflow:auto`; `<table>` keeps real table semantics; `border-collapse:separate;
  border-spacing:0 8px; min-width:880px`.
- `<th>`: `--t-micro` 700 uppercase tracking `--tracking-caps`, `--ink-2`, padding `4px 14px`.
  Columns and widths: Finding (auto, min 280px), Severity 112px, Confidence 160px, Verdict 148px,
  Location 220px, Mapping 140px.
- `<td>`: padding `14px`, `background:rgba(255,255,255,.80)`, top/bottom border
  `1px solid rgba(255,255,255,.9)`; first cell radius `18px 0 0 18px` and holds the stripe; last
  cell radius `0 18px 18px 0`. Row hover `background:#ffffff` only (no pointer cursor; rows do
  nothing on click, the old `cursor:pointer` is removed).
- Finding cell: title `.fname` `700 14px` `--ink` (wraps), rule `.frule` `--t-mono-sm` `--ink-3`.
  Location `.loc` `--t-mono-sm` `--ink-2`, `overflow-wrap:anywhere`.
- **≤640px stacked cards**: `table, thead, tbody, tr, td {display:block}`; `thead` visually hidden
  (sr-only, not `display:none`); each `tr` becomes a white card (radius 20px, padding `16px 16px 16px 22px`,
  margin-bottom 12px, stripe on its left); each `td` after the first is a 2-column row
  (`grid-template-columns:96px 1fr`) whose label comes from `td::before{content:attr(data-label)}`
  (`--t-micro` caps `--ink-2`). `data-label` values are fixed strings ("Severity", "Confidence",
  "Verdict", "Location", "Mapping"), never data.

### 4.8 Form fields

- `.field` column gap 8px. `<label>` `700 13.5px` `--ink`. Hint `--t-small` `--ink-2`, linked via
  `aria-describedby`.
- Input / select / textarea: height 46px (textarea min 148px, mono 13px/1.6), radius 14px,
  `background:#ffffff`, `border:1.5px solid var(--border-input)` (3.81:1), padding `0 14px`
  (textarea `12px 14px`), `box-shadow:inset 0 2px 4px rgba(31,45,58,.06)`, text `--t-body` `--ink`,
  placeholder `--ink-3` (5.05:1 on white).
- Focus-visible: `outline:3px solid var(--focus); outline-offset:2px; border-color:var(--teal-600)`.
- Invalid: `border-color:var(--coral-700)`, `aria-invalid="true"`.
- **Select**: `appearance:none`, padding-right 44px, chevron as a `data:` SVG background
  (`url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%231f2d3a' stroke-width='2.2' stroke-linecap='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E") right 16px center / 18px no-repeat`;
  allowed by `img-src data:`). Native options keep keyboard and screen-reader behaviour.
- **Fieldset**: `border:1px solid var(--border-soft)`, radius 20px, padding `16px 18px 18px`,
  `background:rgba(255,255,255,.45)`; legend `--t-h3`, padding `0 6px`.

### 4.9 Buttons and segmented control

| Variant | Class | Height / padding | Background | Text | Border / shadow | Hover / active |
|---|---|---|---|---|---|---|
| Primary pill | `.btn .btn-primary` | 44px / `0 22px` (sm 36px / `0 16px`) | `linear-gradient(180deg,var(--teal-550) 0%,#2a6a64 100%)` | `#fff` `700 14px` (4.71:1 at the lightest stop) | `--shadow-clay` | hover: gradient `--teal-600`→`#255e59`, lift; active: `--shadow-pressed`, `translateY(1px)` |
| Secondary | `.btn .btn-secondary` | 44 / `0 20px` (sm 32 / `0 14px`) | `linear-gradient(180deg,#ffffff,#f1f4f6)` | `--ink` `700 14px` | `1px solid var(--border-soft)`, light clay | hover `#ffffff`, lift |
| Danger-soft (Deny) | `.btn .btn-danger` | 44 / `0 20px` | `var(--coral-75)` | `--coral-800` `700 14px` (6.55:1) | `1px solid var(--coral-200)` | hover bg `--coral-100` |
| Ghost on dark | `.btn .btn-ghost-dark` | 40 / `0 18px` | `rgba(255,255,255,.12)` | `--ink-on-dark` `700 14px` | `1px solid rgba(255,255,255,.28)` | hover bg `.20` |
| Text button | `.btn-text` | auto / `0 4px` | none | `--link` `700 13.5px`, underline on hover | none | — |
| Icon button | `.icon-btn` | 44×44 circle | see 2.3 | glyph `--ink` | see 2.3 | lift |

All: `border-radius:var(--r-pill)`, `display:inline-flex; align-items:center; gap:8px`, icon 18px,
`cursor:pointer`, `transition:transform var(--d-1) var(--ease-out), box-shadow var(--d-1), background var(--d-1)`.
Disabled: `background:var(--slate-100); color:var(--ink-3); border-color:var(--slate-200);
box-shadow:none; cursor:not-allowed; transform:none`. Focus-visible: `outline:3px solid var(--focus);
outline-offset:2px` (`--focus-on-dark` for ghost-dark and anything inside the sidebar or hero).

**Segmented control** (`.segs`, `role="group"` with `aria-label`): well `--surface-sunken`, radius
pill, padding 4px; options are `<button aria-pressed>`, height 30px, padding `0 14px`, `700 12.5px`,
`--ink-2`; pressed: `background:#fff; color:var(--ink); box-shadow:0 4px 10px -6px rgba(31,45,58,.35)`.

### 4.10 Toasts

Logic unchanged (5s auto-dismiss, max 4, polite region for ok/info, assertive region for errors,
`.ic` glyph ✓ / i / !). Visual:

- Toast: `background:var(--surface-raised)`, radius 20px, `--shadow-toast`, padding `14px 14px 14px 16px`,
  width 360px (≤640 full width), row gap 12px.
- `.ic`: 36px clay disc, white glyph, `--badge-teal` (ok), `--badge-bluegrey` (info), `--badge-coral` (error).
- Title `700 14px` `--ink`; detail `--t-small` `--ink-2`.
- Add a dismiss button: 28px circle, "×" glyph, `aria-label="Dismiss notification"`, removes the
  toast immediately. Hovering or focusing a toast pauses its timer (WCAG 2.2.1).

### 4.11 `IconBadge` and icons

`src/components/icons.tsx` exports every glyph as a component (24×24 viewBox, stroke-only, round
caps/joins, `aria-hidden`). `IconBadge({tone,size,children})` applies 1.6. Glyph list: grid, target,
search-lines, shield-check, document, chain, radar, crosshair-check, hand, funnel-slash, refresh,
bell, lock, info, alert-triangle, alert-circle, tick, x, play-circle, clipboard, copy, chevron-down.

### 4.12 `Mascot`, `EmptyState`, `ErrorState`, `Skeleton`

- `Mascot({pose:"hero"|"avatar"|"rest"|"puzzled", size, float?})` →
  `<span class="mascot mascot--{pose}" aria-hidden="true" style={{width:size,height:size}}>`;
  CSS maps the pose to `background-image:url(/mascot/watchdog-{pose}.png)` with `contain` sizing and
  a soft radial fallback disc behind it. Never an `<img>`.
- `EmptyState({pose="rest", size, title, children, action})`: centred column, gap 10px, padding
  `28px 16px`; title `--t-h3` `--ink`; body `--t-small` `--ink-2`.
- `ErrorState({title, detail, onRetry})`: `role="alert"` wrapper, puzzled mascot 96px, title
  `--t-h3`, detail `--ink-2`, secondary pill "Retry" when `onRetry`. Titles keep today's strings
  ("Could not load findings", …). `ErrorBoundary` reuses this look with its fixed text "This view
  failed to render." and button "Try again".
- `Skeleton({h, w, r})`: `background:linear-gradient(90deg,var(--surface-sunken) 0%,#f3f6f8 50%,var(--surface-sunken) 100%)`,
  `background-size:200% 100%`, shimmer 1.4s; always paired with a visible caption ("Loading
  findings…", etc.) inside the `role="status"` container.

---

## 5. Accessibility and motion

### 5.1 Rules

- Landmarks: `nav[aria-label=Primary]`, `header` (top bar), `main` wraps `.screen`, `form[role=search]`,
  Report's `nav[aria-label="Report sections"]`. One `h1` per screen; card `h2`s; no skipped levels
  inside cards.
- Skip link: first focusable element `<a class="skip" href="#main">Skip to content</a>`, visible on
  focus (white pill, top-left, 3px focus ring).
- Keyboard: Tab order = skip link → nav (6) → policy mini-card button → search → refresh → bell →
  screen content. "/" focuses search; Esc clears it. Segmented controls are buttons with
  `aria-pressed` (Tab between, Space/Enter toggles). Toggle KPI tiles likewise.
- Focus ring everywhere: `outline:3px solid var(--focus); outline-offset:2px` on light surfaces;
  `--focus-on-dark` (#8fd3c9) on the sidebar, hero and bottom tab bar. Never `outline:none` without
  a replacement.
- Live regions: loading containers `role="status"`; load errors `role="alert"`; chain FAIL is the
  only alert on the Audit screen; toasts keep their polite/assertive split; search hint `role="status"`.
- Charts: `role="img"` + full-value `aria-label`; all values also visible as text.
- Decorative art (mascots, waves, fabric, icon badges, stripes) is `aria-hidden`.
- Touch targets ≥44×44 (nav items 48px tall; bottom tab buttons ≥44px; icon buttons 44px; sm
  buttons are 32–36px tall but ≥44px wide with 8px spacing, the WCAG 2.2 spacing exception).
- Text resize: at 200% zoom a 1280px window lays out as the 641–1023 breakpoint, and the layout
  holds. KPI tiles and the hero use `min-height`, never `height`, so enlarged text grows them instead
  of clipping.
- Reduced motion per 1.9.

### 5.2 Contrast table (WCAG 2.x ratios, measured)

Text (needs 4.5:1; 3:1 for ≥18.66px bold / 24px):

| Foreground | Background | Use | Ratio |
|---|---|---|---|
| `#1f2d3a` ink | `#dbe3e8` page canvas | page title, top bar | 10.81 |
| `#1f2d3a` ink | `#acb7c1` canvas over darkest fabric pixel | worst case of the above | 6.89 |
| `#1f2d3a` ink | `#f4f7f8` card (90% over canvas) | body | 13.05 |
| `#4a5d6b` ink-2 | `#f0f2f4` card over worst fabric | secondary | 6.10 |
| `#566876` ink-3 | `#f0f2f4` card over worst fabric | meta, hashes | 5.14 |
| `#566876` ink-3 | `#f8e6e3` FAIL tint (worst tint) | meta | 4.79 |
| `#4a5d6b` ink-2 | `#f8e6e3` FAIL tint | policy body | 5.68 |
| `#1f5e57` link | `#f8e6e3` FAIL tint (worst) | links | 6.23 |
| `#566876` placeholder | `#ffffff` input | placeholder | 5.77 |
| `#f2f5f7` ink-on-dark | `#3a4f63` sidebar top | wordmark, active text | 7.74 |
| `#c3d0db` ink-on-dark-2 | `#3a4f63` sidebar top | nav labels, status | 5.39 |
| `#d6e0e8` ink-on-dark-3 | `#445b70` sidebar card | policy line | 5.27 |
| `#1f2d3a` ink | `#e6eff0` active nav pill | active label | 12.02 |
| `#f4f7f9` | `#3e5468` hero | greeting | 7.30 |
| `#d6e0e8` ink-on-dark-3 | `#4a6276` hero lightest stop under text | hero sub-lines | 4.75 |
| `#1f2d3a` ink | `#b9dcd5` teal tile (dark stop) | label, number | 9.54 |
| `#3b5058` ink-tile | `#b9dcd5` teal tile | sub-line | 5.76 |
| `#3b5058` ink-tile | `#c5d1dc` blue-grey tile | sub-line | 5.47 |
| `#3b5058` ink-tile | `#d9e8f0` ice tile | sub-line | 6.77 |
| `#3b5058` ink-tile | `#ccc6e7` lavender tile | sub-line | 5.17 |
| `#ffffff` | `#357f78` primary button (lightest stop) | button label | 4.71 |
| `#ffffff` | `#2f766f` | hover / count on teal | 5.33 |
| `#f2f5f7` | `#516476` ghost-on-dark over hero | ghost button | 5.58 |
| `#9a2e28` | `#fbeceb` | Deny button | 6.55 |
| `#1f2d3a` | `#ffffff` | secondary button, toasts | 14.05 |
| `#9a2e28` | `#f6dcd9` | CRITICAL chip, True positive chip | 5.78 |
| `#8a4614` | `#f7e3d2` | HIGH chip | 5.69 |
| `#6e5310` | `#f4ead0` | MEDIUM chip, Needs human chip | 6.03 |
| `#245f57` | `#d6ece8` | LOW chip | 5.97 |
| `#3d5266` | `#e1e7ed` | INFO chip | 6.49 |
| `#46566a` | `#e3e8ec` | Likely noise chip | 6.08 |
| `#ffffff` | `#2f7d74` | PASS pill | 4.88 |
| `#5e460c` | `#f0ddb0` | CONDITIONAL pill | 6.65 |
| `#ffffff` | `#b0433c` | FAIL pill, chain FAIL, count badges | 5.65 |
| `#3d4b57` | `#e1e6ea` | INCOMPLETE / NOT EVALUATED pill | 7.13 |
| `#1d4a52` | `#e3efee` | command / code block | 8.29 |
| `#a3332d` | `#ffffff` | out-of-scope text (`.scope-bad` test) | 6.84 |
| `#276a62` | `#f4f7f8` | in-scope text | 5.87 |
| `#1f5e57` | `#dcefeb` | count pill, DETECT-ONLY, ok card | 6.29 |
| `#8f2a24` | `#f8e1de` | error callout | 6.66 |
| `#1f2d3a` / `#4a5d6b` | `#eadfca` sand banner (dark stop) | banner title / sub | 10.64 / 5.18 |
| `#5e460c` | `#f6efdf` | Active-profile warning callout | 7.78 |

Non-text (needs 3:1):

| Element | Colours | Ratio |
|---|---|---|
| Focus ring on card | `#2f766f` vs `#f4f7f8` | 4.95 |
| Focus ring on lavender tile (worst tint) | `#2f766f` vs `#ccc6e7` | 3.25 |
| Focus ring on dark | `#8fd3c9` vs `#33475b` / `#3e5468` | 5.62 / 4.61 |
| Input boundary | `#748593` vs `#ffffff` | 3.81 |
| Bar / donut fills vs card | crit `#c25750` 4.02, high `#c27234` 3.34, med `#a8832a` 3.23, low `#4b9289` 3.32, info `#71879b` 3.40, SAST `#6a63b0` 4.77 | ≥3.23 |
| Status dot active on sidebar | `#6fd0c1` vs `#3a4f63` | 4.63 |

Rule the implementation must follow: `--ink-2` and `--ink-3` never sit directly on the bare page
canvas (worst case 3.36); only `--ink` does. `--teal-600` is never used for text (use `--link`).

A new `src/styles/tokens.test.ts` parses `tokens.css` `:root` and asserts every text row of this table
≥4.5 and every non-text row ≥3 (reuse the luminance helpers from `glass.test.ts`).

---

## 6. Assets for the controller to generate

Shared style prompt (prepend to each): "Pixar-style 3D clay character render, soft subsurface
scattering, matte materials, fluffy white fur with fine strand detail, soft studio key light from
upper left, gentle cool rim light from the right, muted pastel palette (sea-glass teal #6fb8ae, slate
blue-grey #4a6276, warm sand #d9c3a0, cream #f5efe4, navy #2e4153), fully transparent background,
no ground plane, no cast shadow on the floor, no text, no logos, no watermark, centred, consistent
character across images."

Character sheet (identical in every image): a small, round, fluffy **white dog** (Samoyed-puppy-like
proportions: big head, short muzzle, upright fluffy triangular ears), large dark-brown glossy eyes
with catchlights, small black nose, friendly closed-mouth smile; wears a **navy hoodie** (#2e4153)
with cream drawstrings and a tiny plain teal shield patch on the chest (no text); **over-ear
headphones** with slate-teal cups (#4b9289), cream cushions and a slate headband passing between the
ears.

| # | Path (under `frontend/public/`) | Generate at | Ship at | Format | Pose / framing | Notes |
|---|---|---|---|---|---|---|
| 1 | `mascot/watchdog-hero.png` | 1024×1024 | 768×768 | PNG-24 + alpha, ≤420 KB | Sitting, framed from the hips up, body turned three-quarters to the viewer's **right** (toward the hero text), head tilted 8°, eyes open and attentive, both front paws lifted holding the headphone cups, content smile. Character fills 90% of the height, its bottom edge touches the image bottom (cropped at the hips), 5% padding top. | Displayed 232px; its head breaks the banner's top edge |
| 2 | `mascot/watchdog-avatar.png` | 1024×1024 | 384×384 | PNG-24 + alpha, ≤160 KB | Head and shoulders, facing the camera, slight head tilt left, eyes open, gentle smile, headphones on, hoodie collar and drawstrings visible. Head centred; all of the head and ears inside the central 82% circle; shoulders run to the bottom edge. | Sits on a teal radial disc in a 116px circle |
| 3 | `mascot/watchdog-rest.png` | 1024×1024 | 480×480 | PNG-24 + alpha, ≤200 KB | Lying down curled on a small round cream cushion, eyes closed, peaceful, headphones resting around the neck, chin on front paws, tail curled around. Full body, three-quarter view from slightly above, centred with 8% padding. | All empty states ("all quiet") |
| 4 | `mascot/watchdog-puzzled.png` | 1024×1024 | 480×480 | PNG-24 + alpha, ≤200 KB | Sitting, full body, facing the camera, head tilted strongly to one side (20°), one ear flopped down, one front paw raised to scratch a headphone cup, eyebrows raised, small "huh?" mouth. No question-mark symbols. Centred, 8% padding. | Error states; must read as friendly, not alarming |
| 5 | `textures/fabric-wave.jpg` | 2400×800 | 2400×800 | JPEG q78, ≤240 KB | Not a character. Flowing, softly knitted fabric waves rolling from the left-bottom to the right, like the moodboard: layers of slate blue-grey (#8fa3b5→#4a6276) and sea-glass teal (#9ccfc6) fabric, with warm sand (#d9c3a0) visible in the upper-left troughs; fine horizontal knit texture; matte, soft diffuse light; no hard shadows, no objects, no text. Opaque. Brightest area top, darker folds bottom-right. | Page backdrop at 28% and the report banner |

Delivery: also export a 1-px-margin-trimmed check (no stray semi-transparent halos; alpha edges
clean against both `#3e5468` and `#f4f7f8`). The favicon stays `public/favicon.svg` (out of scope).

---

## 7. Implementation order

Each step ends green (`npm run lint`, `npm test`, `npm run build`). Verify visually per step against
the running dashboard, busting the cached bundle (hard reload / `?v=` query) before judging UI.

1. **Assets and fonts.** Drop the five files into `frontend/public/` (or ship the CSS fallbacks first:
   every mascot spot already shows a gradient disc without its PNG). Update the font `<link>` in
   `index.html`.
2. **Tokens and base.** Add `styles/tokens.css`, `styles/base.css` (reset, canvas 1.4, typography 1.7,
   `.sr-only`, skip link, reduced motion), `styles/components.css` (card, buttons, chips, fields,
   segmented, toasts, skeleton), `styles/shell.css`, `styles/screens.css`. Import them in
   `main.tsx` in that order. Delete `glass.css` once the last screen moves (step 9); until then
   import it last. Replace `glass.test.ts` with `tokens.test.ts` (5.2) plus the kept assertions:
   `.scope-bad` colour ≥4.5 on white; the feed caps move to `.feed--page { max-height: calc(100vh - 280px) }`
   and `.feed--compact { max-height: none }` (update those two assertions to the new selectors).
3. **Data layer.** `src/data/resources.ts` (`useResource`, `__resetResourceCache`), `src/data/search.ts`
   (`matchFinding`), `src/data/greeting.ts` (time-of-day). Reset the cache in `src/test/setup.ts`
   `afterEach`. Move `App`'s `auditVersion`/`engVersion` to `versions` + `bump`.
4. **Primitives.** `icons.tsx`, `IconBadge`, `Mascot`, `Button` classes, `SeverityChip`,
   `VerdictChip`, `VerdictPill`, `Skeleton`, `EmptyState`, `ErrorState`, `ListCard`, `Toast` (extract
   `ToastView` from `Gates.tsx`, add dismiss + pause). Restyle `ErrorBoundary`.
5. **Shell.** Sidebar (identity, nav with badges, policy mini-card), top bar (h1, search, refresh,
   bell), the three responsive modes, skip link. `App` passes `title`, `pendingGates`, `policy`,
   `query`, handlers.
6. **Overview.** `OverviewHero`, KPI row (`KpiTile`), restyled `PolicyGate`, `SeverityBarChart`,
   `DonutCard`, the three list cards (`Gates variant="compact"`, `AuditEntryRow` compact), report
   banner. Remove the `aside` path from `App` and `Shell`.
7. **Findings.** KPI filter toggles, table restyle and mobile cards, query + filter plumbing, empty
   and no-match states.
8. **Approval gates.** Intro strip, `GateCard` page variant, grid, empty state.
9. **New scan, Report, Audit.** New Scan two-column layout and DAST fields styling (coordinate with
   the in-flight DAST change on `feat/dast-coverage`; style whatever field names it lands), Report
   typography + section index, Audit chain card + type filter + timeline. Delete `glass.css`.
10. **Polish.** Responsive pass at 1440, 1280, 1040, 768, 390; keyboard-only pass; reduced-motion
    pass; axe check; regenerate `docs/images/dashboard-*.png` and update README screenshots.

### 7.1 Tests that need updates

| File | What changes | Why |
|---|---|---|
| `components/Shell.test.tsx` | h1 accessible name becomes "Ascent Console: Overview" (the test's `name: "Ascent Console"` exact match fails; use a regex `/Ascent Console/`), and the h1 no longer has `sr-only` (only its prefix span does). `getAllByRole("button")` length 6 → 8 (6 nav + Refresh data + Pending approvals; the policy mini-card is absent when `policy` is undefined). The two "no search" assertions (`queryByLabelText("Search")`, `queryByRole("searchbox")`) invert: the searchbox exists with name "Search findings". `getByLabelText("Findings")`, `.dot`/`.idle` and the status text checks are unchanged. | Real search and icon buttons are added; title becomes visible |
| `App.test.tsx` | Should pass unchanged if copy is kept: "SSRF in fetch" (Top findings card), "Approval required" (Pending approvals card head), "Hash chain OK" (Recent audit), `/engagement: …/` and `/no engagement loaded/` (sidebar chip only; the hero must not contain either phrase), single Approve button on Overview, "gate g1 → approved" in Recent audit after approving, single "This view failed to render." per screen. No new endpoints are fetched. Add tests: hero CTA navigates to New scan; bell navigates to gates; KPI tile click opens Findings with the filter; search Enter navigates to Findings. | Guard the new navigation paths |
| `screens/Findings.test.tsx` | `.kpi .l` / `.n` selectors keep working (tiles are now buttons with the same classes). `getAllByText(/True positive/i)` must stay 2: do not add any other "True positive" text (no sr-only "Filter: …" strings). Add: tile click filters rows; query prop filters rows; no-match state. Loading test still finds `role="status"` with /loading/. | KPI tiles became toggles |
| `screens/Gates.test.tsx` | Should pass unchanged (labels, toasts `.ic` glyphs, regions, Retry all kept; the new toast dismiss button is named "Dismiss notification", which matches neither /approve/ nor /deny/). Add: compact variant hides evidence inside `<details>` but keeps the consent note; dismiss button removes a toast. | New variant and dismiss |
| `components/PolicyGate.test.tsx` | Unchanged strings ("FAIL", /exit 1/, /policy ci/, the INCOMPLETE sentences, /No policy verdict yet/, /--policy/). The "no img" XSS test still holds (no `<img>` anywhere). | — |
| `screens/Audit.test.tsx` | Unchanged if the filter labels are exactly "Verdicts / Decisions / Policy / Runs" (they must not contain "Triage", "Human decision", "Policy gate" or "Verification run", or the `queryByText(/Triage/)` null checks and `findByText(/Policy gate/)` single-match checks break). Chain FAIL remains the only `role="alert"`. | Type filter added |
| `screens/NewScan.test.tsx` | Unchanged labels and copy; extend the DAST cases already planned by the DAST spec (select "DAST profile", "Auth header name", "Env var holding its value"). Add: `aria-invalid` set on the field named by the error's `field`. | — |
| `screens/Report.test.tsx` | Unchanged; the section index uses internal `#r-…` hrefs without `target`, which the existing link tests do not cover (they check `javascript:` and one named external link). Add: index lists h2 texts as text. | Section index |
| `components/ErrorBoundary.test.tsx` | Unchanged copy ("This view failed to render.", "Try again"). | — |
| `styles/glass.test.ts` | Replaced by `styles/tokens.test.ts` (step 2). | Stylesheet split |
