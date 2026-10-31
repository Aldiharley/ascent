import { useCallback, useEffect, useRef, useState } from "react";
import { IconX } from "./icons";

export interface ToastMsg {
  kind: "ok" | "info" | "error";
  title: string;
  detail: string;
}

export interface ToastItem extends ToastMsg {
  key: number;
}

export const TOAST_MS = 5000;
export const MAX_TOASTS = 4;

/**
 * Toast list state: `notify` appends (keeping the newest MAX_TOASTS), `dismiss` removes one.
 * Timers live in each `ToastView`, so unmounting the stack cancels every one of them.
 */
export function useToasts() {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextKey = useRef(0);

  const notify = useCallback((msg: ToastMsg) => {
    const key = nextKey.current++;
    setToasts((prev) => [...prev, { ...msg, key }].slice(-MAX_TOASTS));
  }, []);

  const dismiss = useCallback((key: number) => {
    setToasts((prev) => prev.filter((t) => t.key !== key));
  }, []);

  return { toasts, notify, dismiss };
}

// Glyphs are fixed per kind (not data).
const TOAST_ICON: Record<ToastMsg["kind"], string> = { ok: "✓", info: "i", error: "!" };

/**
 * One toast. Auto-dismisses after TOAST_MS, but hovering it or focusing inside it pauses the timer
 * (WCAG 2.2.1) and leaving resumes with the time that was left. The × button removes it at once.
 * Title and detail are React text.
 */
export function ToastView({
  toast,
  onDismiss,
}: {
  toast: ToastItem;
  onDismiss: (key: number) => void;
}) {
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const paused = hovered || focused;
  const remaining = useRef(TOAST_MS);
  // The timer must call the latest onDismiss without being restarted when it changes. The ref is
  // written in an effect (declared before the timer effect), never during render.
  const dismissRef = useRef(onDismiss);
  useEffect(() => {
    dismissRef.current = onDismiss;
  });
  const { key } = toast;

  useEffect(() => {
    if (paused) return;
    const startedAt = Date.now();
    const timer = setTimeout(() => dismissRef.current(key), remaining.current);
    return () => {
      clearTimeout(timer);
      remaining.current = Math.max(0, remaining.current - (Date.now() - startedAt));
    };
  }, [paused, key]);

  return (
    <div
      className={`toast toast-${toast.kind}`}
      // Pointer events, and not for touch: a tap fires an emulated hover that no leave ever undoes
      // (until the next tap elsewhere), which would pin the toast on screen for good.
      onPointerEnter={(e) => setHovered(e.pointerType !== "touch")}
      onPointerLeave={() => setHovered(false)}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
    >
      <div className="ic" aria-hidden="true">
        {TOAST_ICON[toast.kind]}
      </div>
      <div className="m">
        <b>{toast.title}</b>
        <div>{toast.detail}</div>
      </div>
      <button
        type="button"
        className="toast-x"
        aria-label="Dismiss notification"
        onClick={() => onDismiss(key)}
      >
        <IconX size={14} strokeWidth={2.6} />
      </button>
    </div>
  );
}

/**
 * The fixed toast stack. Two always-mounted live regions: successes and info are polite, errors
 * are assertive, so an error is announced immediately and is not displaced by a later success.
 */
export function ToastStack({
  toasts,
  onDismiss,
}: {
  toasts: ToastItem[];
  onDismiss: (key: number) => void;
}) {
  const views = (isError: boolean) =>
    toasts
      .filter((t) => (t.kind === "error") === isError)
      .map((t) => <ToastView key={t.key} toast={t} onDismiss={onDismiss} />);
  return (
    <div className="toast-stack">
      <div aria-live="polite" role="status" className="toast-region">
        {views(false)}
      </div>
      <div aria-live="assertive" role="alert" className="toast-region">
        {views(true)}
      </div>
    </div>
  );
}
