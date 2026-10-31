import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
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

// Requests in flight, for the top bar's refresh spinner (any screen's load counts, not only the
// ones App reads itself). `generation` changes on a cache reset so a request that was already
// forgotten cannot decrement the count of the ones that replaced it.
let inFlight = 0;
let generation = 0;
const fetchListeners = new Set<() => void>();
const emitFetching = () => {
  for (const listener of [...fetchListeners]) listener();
};
const subscribeFetching = (listener: () => void) => {
  fetchListeners.add(listener);
  return () => {
    fetchListeners.delete(listener);
  };
};
const isFetching = () => inFlight > 0;

/** True while any resource request is in flight (first loads and refetches alike). */
export function useIsFetching(): boolean {
  return useSyncExternalStore(subscribeFetching, isFetching);
}

// Module-level cache keyed `${key}@${version}`. A request is shared by every consumer of the same
// key and version; bumping the version (App's `versions`) is how a view asks for fresh data.
const cache = new Map<string, Entry>();

const idOf = (key: ResourceKey, version: number) => `${key}@${version}`;

// Mounted consumers listen for a Retry of their `key@version`: a failure evicts the entry, so
// every consumer that was showing it needs to ask again, not only the one whose button was clicked.
const retryListeners = new Set<(id: string) => void>();

/** Test hook: forget every cached request (called from `src/test/setup.ts` after each test). */
export function __resetResourceCache(): void {
  cache.clear();
  generation += 1;
  if (inFlight !== 0) {
    inFlight = 0;
    emitFetching();
  }
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
  const startedIn = generation;
  const done = () => {
    if (startedIn !== generation) return;
    inFlight -= 1;
    emitFetching();
  };
  inFlight += 1;
  emitFetching();
  entry.promise.then(
    (data) => {
      entry.settled = { ok: true, data };
      done();
    },
    () => {
      // Errors are never cached: the next consumer (or Retry) asks again.
      if (cache.get(id) === entry) cache.delete(id);
      done();
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

  useEffect(() => {
    const onRetry = (retried: string) => {
      if (retried !== id) return;
      setLocal(null);
      setAttempt((n) => n + 1);
    };
    retryListeners.add(onRetry);
    return () => {
      retryListeners.delete(onRetry);
    };
  }, [id]);

  const retry = useCallback(() => {
    // Only a failed or still-unsettled entry is dropped: another consumer may have re-requested the
    // key since this one failed, and its healthy entry must not be thrown away (nor refetched).
    if (!cache.get(id)?.settled?.ok) cache.delete(id);
    for (const listener of [...retryListeners]) listener(id);
  }, [id]);

  // Prefer the shared cache (ready on the very first render of a remount), else this hook's own
  // settled result (the only place a failure is visible, since failures are evicted).
  const cached = cache.get(id)?.settled as Settled<ResourceMap[K]> | undefined;
  // Keep what the cache served in local state too: the cache may evict this entry later (a newer
  // version of the key, a reset), and a mounted consumer must not fall back to `loading` then.
  if (cached && (local?.id !== id || local.result !== cached)) setLocal({ id, result: cached });
  const result = cached ?? (local?.id === id ? local.result : undefined);
  if (!result) return { status: "loading" };
  return result.ok ? { status: "ready", data: result.data } : { status: "error", retry };
}

/**
 * `useResource` for views that stay on screen across a refresh: while a newer version loads it keeps
 * returning the previous payload (as `ready`), so Refresh swaps data in place instead of flashing a
 * skeleton and a decision toast or a scroll position survives. A first load is still `loading`, and
 * a failure is reported as an error, after which there is nothing stale left to show.
 */
export function useStaleResource<K extends ResourceKey>(
  key: K,
  version = 0,
): Resource<ResourceMap[K]> {
  const res = useResource(key, version);
  const last = useLastReady(res, true);
  if (res.status === "loading" && last) return { status: "ready", data: last.data };
  return res;
}

/**
 * The most recent payload a resource was `ready` with, as `{ data }` (the box tells a legitimate
 * `null` payload from "nothing yet"), or `null` before the first one. With `clearOnError` a failure
 * forgets it; otherwise it is kept (a chip that must not lose a name it already showed).
 *
 * Kept in state and adjusted during render (React's "derive state from props" pattern) rather than
 * in a ref written during render, which concurrent rendering may discard or replay.
 */
export function useLastReady<T>(res: Resource<T>, clearOnError = false): { data: T } | null {
  const [last, setLast] = useState<{ data: T } | null>(null);
  if (res.status === "ready" && (last === null || last.data !== res.data)) setLast({ data: res.data });
  else if (res.status === "error" && clearOnError && last !== null) setLast(null);
  return last;
}
