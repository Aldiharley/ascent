import type { TriageItem } from "../api";

function text(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/** Where a finding lives: its URL, else `file:line`, else `file`, else "". */
export function findingLocus(item: TriageItem): string {
  const f = item?.finding;
  const url = text(f?.url);
  if (url) return url;
  const file = text(f?.file);
  if (file) return typeof f?.line === "number" && f.line ? `${file}:${f.line}` : file;
  return "";
}

/**
 * Client-side findings search. The query is lower-cased and split on whitespace; every term must be
 * a substring of `title | rule_id | locus | cwe | category | tool` (lower-cased, space-joined).
 * Plain substring matching only: the query is never interpreted as a pattern. Fields come from
 * scanned data, so anything that is not a string is ignored.
 */
export function matchFinding(item: TriageItem, query: string): boolean {
  const terms = text(query).toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const f = item?.finding;
  const hay = [f?.title, f?.rule_id, findingLocus(item), f?.cwe, f?.category, f?.tool]
    .map(text)
    .join(" ")
    .toLowerCase();
  return terms.every((t) => hay.includes(t));
}
