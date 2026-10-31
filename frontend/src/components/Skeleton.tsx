/**
 * Shimmering placeholder block. Decorative: always pair it with a visible caption
 * ("Loading findings…") inside a `role="status"` container so the state is announced.
 */
export function Skeleton({
  h = 16,
  w = "100%",
  r,
}: {
  h?: number | string;
  w?: number | string;
  r?: number | string;
}) {
  return (
    <span
      className="skeleton"
      aria-hidden="true"
      style={{ height: h, width: w, ...(r !== undefined ? { borderRadius: r } : null) }}
    />
  );
}
