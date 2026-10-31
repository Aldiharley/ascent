import { useEffect, useMemo, useSyncExternalStore } from "react";
import type { Gate } from "../api";
import { useStaleResource } from "./resources";
import type { Resource } from "./resources";

/*
 * The pending approval gates, as every view sees them.
 *
 * Several views list the same gates: the Approval gates page, the Overview card, the hero summary,
 * the sidebar badge and the bell. If each kept its own idea of "decided", they would disagree for
 * as long as a refetch takes (or for good, if the server view is stale). So a recorded decision
 * lives here, once, and every reader subtracts it from the payload it holds.
 */

let decided: ReadonlySet<string> = new Set();
const listeners = new Set<() => void>();

function publish(next: ReadonlySet<string>): void {
  decided = next;
  for (const listener of [...listeners]) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

const snapshot = () => decided;

/** A decision was recorded (or found already recorded) for this gate: hide it everywhere, now. */
export function markGateDecided(id: string): void {
  if (decided.has(id)) return;
  publish(new Set(decided).add(id));
}

/**
 * Forget every decided id that `listed` no longer contains. Once the server stops listing a gate
 * the hiding has done its job; keeping it would hide a later, genuinely pending gate that happens
 * to reuse the id.
 */
function forgetUnlisted(listed: ReadonlySet<string>): void {
  const keep = new Set<string>();
  for (const id of decided) if (listed.has(id)) keep.add(id);
  if (keep.size !== decided.size) publish(keep);
}

/**
 * Forget every recorded decision. Called when a new scan is created: the decided ids belong to the
 * previous engagement, and a gate of the new one may reuse an id.
 */
export function forgetAllGateDecisions(): void {
  if (decided.size > 0) publish(new Set());
}

/** Test hook: forget every recorded decision (called from `src/test/setup.ts` after each test). */
export function __resetGateDecisions(): void {
  forgetAllGateDecisions();
}

/**
 * The gates still awaiting a decision: the `gates` resource minus the ones decided in this
 * session. Same loading/error/ready contract (and stale-while-revalidate behaviour, reset by a new
 * `epoch`) as `useStaleResource`; `data.length` is the one pending count to show anywhere.
 */
export function usePendingGates(version = 0, epoch = 0): Resource<Gate[]> {
  const res = useStaleResource("gates", version, epoch);
  const ids = useSyncExternalStore(subscribe, snapshot);
  const list = res.status === "ready" && Array.isArray(res.data) ? res.data : undefined;

  useEffect(() => {
    if (!list) return;
    forgetUnlisted(new Set(list.map((g) => g?.id)));
  }, [list]);

  const pending = useMemo(() => (list ? list.filter((g) => !ids.has(g?.id)) : undefined), [list, ids]);
  return pending ? { status: "ready", data: pending } : res;
}
