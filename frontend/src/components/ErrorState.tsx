import { Button } from "./Button";
import { Mascot } from "./Mascot";

/**
 * Load/render failure: the puzzled watchdog, a fixed title and optional detail, and a Retry
 * button when the caller can retry. Pass fixed strings only; never an error message from a
 * response, which can carry scanned-target data.
 */
export function ErrorState({
  title,
  detail,
  onRetry,
  retryLabel = "Retry",
}: {
  title: string;
  detail?: string;
  onRetry?: () => void;
  retryLabel?: string;
}) {
  return (
    <div className="error-state" role="alert">
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
