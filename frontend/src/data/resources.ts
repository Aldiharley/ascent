import { useCallback, useEffect, useState } from "react";
import {
  getAudit,
  getEngagement,
  getFindings,
  getGate,
  getGates,
  getReport,
} from "../api";
import type { AuditLog, Engagement, Gate, GateReport, TriageItem } from "../api";

/** Data the console reads. One key per `/api/*` GET the screens share. */
export interface ResourceMap {
  findings: TriageItem[];
  gates: Gate[];
  audit: AuditLog;
  report: string;
  engagement: Engagement | null;
  gate: GateReport | null;
}

export type ResourceKey = keyof ResourceMap;

export const RESOURCE_KEYS: readonly ResourceKey[] = [
  "findings",
  "gates",
  "audit",
  "report",
  "engagement",
  "gate",
];

export type Resource<T> =
  | { status: "loading" }
  | { status: "error"; retry(): void }
  | { status: "ready"; data: T };

const FETCHERS: { [K in ResourceKey]: () => Promise<ResourceMap[K]> } = {
  findings: getFindings,
  gates: getGates,
  audit: getAudit,
  report: getReport,
  engagement: getEngagement,
  gate: getGate,
};

type Settled<T> = { ok: true; data: T } | { ok: false };

interface Entry {
  promise: Promise<unknown>;
  /** Set once the request settles. Only successes stay cached (see `ensure`). */
  settled?: Settled<unknown>;
}

// Module-level cache keyed `${key}@${version}`. A request is shared by every consumer of the same
// key and version; bumping the version (App's `versions`) is how a view asks for fresh data.
const cache = new Map<string, Entry>();

const idOf = (key: ResourceKey, version: number) => `${key}@${version}`;

/** Test hook: forget every cached request (called from `src/test/setup.ts` after each test). */
export function __resetResourceCache(): void {
  cache.clear();
}

function ensure(key: ResourceKey, version: number): Entry {
  const id = idOf(key, version);
  const hit = cache.get(id);
  if (hit) return hit;
  // A newer version supersedes older ones of the same key, so a long session does not pile up
  // stale payloads (the report can be large).
  for (const [other] of cache) {
    const [k, v] = other.split("@");
    if (k === key && Number(v) < version) cache.delete(other);
  }
  const entry: Entry = { promise: FETCHERS[key]() };
  entry.promise.then(
    (data) => {
      entry.settled = { ok: true, data };
    },
    () => {
      // Errors are never cached: the next consumer (or Retry) asks again.
      if (cache.get(id) === entry) cache.delete(id);
    },
  );
  cache.set(id, entry);
  return entry;
}

/**
 * Loads one shared resource. Results are cached per `key@version`, so re-mounting a screen is
 * instant and two cards that read the same key make one request. The error state deliberately
 * carries no error text: a failed payload can contain scanned-target data.
 */
export function useResource<K extends ResourceKey>(
  key: K,
  version = 0,
): Resource<ResourceMap[K]> {
  const id = idOf(key, version);
  const [local, setLocal] = useState<{ id: string; result: Settled<ResourceMap[K]> } | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true;
    const entry = ensure(key, version);
    // Already settled and shared: the render below reads it straight from the cache.
    if (entry.settled) return;
    entry.promise.then(
      (data) => live && setLocal({ id, result: { ok: true, data: data as ResourceMap[K] } }),
      () => live && setLocal({ id, result: { ok: false } }),
    );
    return () => {
      live = false;
    };
  }, [key, version, id, attempt]);

  const retry = useCallback(() => {
    cache.delete(id);
    setLocal(null);
    setAttempt((n) => n + 1);
  }, [id]);

  // Prefer the shared cache (ready on the very first render of a remount), else this hook's own
  // settled result (the only place a failure is visible, since failures are evicted).
  const cached = cache.get(id)?.settled as Settled<ResourceMap[K]> | undefined;
  const result = cached ?? (local?.id === id ? local.result : undefined);
  if (!result) return { status: "loading" };
  return result.ok ? { status: "ready", data: result.data } : { status: "error", retry };
}
