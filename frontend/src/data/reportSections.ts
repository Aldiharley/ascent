/** Id prefix for report headings; keeps them clear of every other id on the page. */
const PREFIX = "r-";

function slug(text: string): string {
  const s = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return s === "" ? "section" : s;
}

/**
 * One anchor id per heading, in order: `r-` + the lower-cased text with every run of characters
 * outside [a-z0-9] turned into one dash, and `-2`, `-3`, ... for a repeat. The id is only ever
 * built from [a-z0-9-], so the heading text (scanned data) cannot inject anything into an
 * attribute or a selector, and no two ids are equal even when a literal heading looks like a suffix.
 */
export function sectionIds(texts: readonly string[]): string[] {
  const used = new Set<string>();
  return texts.map((t) => {
    const base = PREFIX + slug(t);
    let id = base;
    for (let n = 2; used.has(id); n++) id = `${base}-${n}`;
    used.add(id);
    return id;
  });
}

/** What the index shows for a heading: its text, single-spaced; a numbered fallback when empty. */
export function sectionLabel(text: string, index: number): string {
  const t = text.replace(/\s+/g, " ").trim();
  return t === "" ? `Section ${index + 1}` : t;
}
