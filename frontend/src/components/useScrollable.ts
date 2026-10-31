import { useLayoutEffect, useRef, useState } from "react";
import type { RefObject } from "react";

/**
 * Whether an element's content is taller than its box, i.e. whether it really scrolls. A region that
 * scrolls must be reachable by keyboard (WCAG 2.1.1), but one that does not (a phone, where the
 * Audit timeline is not height-capped, or a short list) must not add a pointless tab stop.
 *
 * Re-measured when the box resizes (ResizeObserver; the window's resize event where it is missing)
 * and whenever `deps` change (the content was filtered or refreshed).
 */
export function useScrollable<T extends HTMLElement>(deps: readonly unknown[]): [RefObject<T>, boolean] {
  const ref = useRef<T>(null);
  const [scrollable, setScrollable] = useState(false);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => setScrollable(el.scrollHeight > el.clientHeight + 1);
    measure();
    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measure);
      return () => window.removeEventListener("resize", measure);
    }
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `deps` is the caller's re-measure trigger
  }, deps);

  return [ref, scrollable];
}
