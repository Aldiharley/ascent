import { Button } from "./Button";
import { Mascot } from "./Mascot";

/**
 * Load/render failure: the puzzled watchdog, a fixed title and optional detail, and a Retry
 * button when the caller can retry. Pass fixed strings only; never an error message from a
 * response, which can carry scanned-target data.
 *
 * `announce` (default true) makes it a `role="alert"`. When several cards show the failure of one
 * resource, only the first announces; the others pass `announce={false}` and stay visible but quiet.
 */
export function ErrorState({
  title,
  detail,
  onRetry,
  retryLabel = "Retry",
  announce = true,
}: {
  title: string;
  detail?: string;
  onRetry?: () => void;
  retryLabel?: string;
  announce?: boolean;
}) {
  return (
    <div className="error-state" role={announce ? "alert" : undefined}>
      <Mascot pose="puzzled" size={96} />
      <p className="es-title">{title}</p>
      {detail ? <div className="es-body">{detail}</div> : null}
      {onRetry ? (
        <Button variant="secondary" onClick={onRetry}>
          {retryLabel}
        </Button>
      ) : null}
    </div>
  );
}
