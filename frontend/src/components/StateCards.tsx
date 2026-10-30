import { ErrorState } from "./ErrorState";
import { Skeleton } from "./Skeleton";

export const BACKEND_HINT = "check that the Ascent backend is running";

/**
 * Load-failure card: fixed text only (a response body can carry scanned data) and a Retry.
 * `ErrorState` is the one `role="alert"`.
 */
export function ErrorCard({ title, onRetry, detail = BACKEND_HINT }: { title: string; onRetry: () => void; detail?: string }) {
  return (
    <section className="card">
      <ErrorState title={title} detail={detail} onRetry={onRetry} />
    </section>
  );
}

/** Skeleton card: announced as a status, with a visible caption (spec 4.12). */
export function LoadingCard({ caption, rows = 3, h = 56 }: { caption: string; rows?: number; h?: number }) {
  return (
    <section className="card list-card" role="status">
      <div className="skeleton-stack">
        <Skeleton h={22} w="45%" />
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} h={h} r={16} />
        ))}
      </div>
      <p className="loading-caption">{caption}</p>
    </section>
  );
}
