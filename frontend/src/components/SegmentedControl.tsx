export interface SegmentOption<T extends string> {
  value: T;
  /** Fixed UI string, never scanned data. */
  label: string;
  disabled?: boolean;
}

/**
 * Pill-shaped switch (spec 4.9): a labelled group of `aria-pressed` buttons, so keyboard and
 * screen-reader users Tab between options and press with Space/Enter.
 */
export function SegmentedControl<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: readonly SegmentOption<T>[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="segs" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={o.value === value}
          disabled={o.disabled}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
