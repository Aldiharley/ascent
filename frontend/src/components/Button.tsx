import type { ButtonHTMLAttributes } from "react";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost-dark" | "text";

const VARIANTS: Record<ButtonVariant, string> = {
  primary: "btn-primary",
  secondary: "btn-secondary",
  danger: "btn-danger",
  "ghost-dark": "btn-ghost-dark",
  text: "btn-text",
};

export interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "className"> {
  variant?: ButtonVariant;
  size?: "md" | "sm";
  /** Full-width. */
  block?: boolean;
  /** A request is in flight: shows a spinner before the label and disables the button. */
  busy?: boolean;
  className?: string;
}

/** Class string for the variants in `components.css` (spec 4.9). Text buttons are `.btn-text` alone. */
export function buttonClass(
  variant: ButtonVariant = "secondary",
  opts: { size?: "md" | "sm"; block?: boolean; className?: string } = {},
): string {
  const v = VARIANTS[variant] ?? VARIANTS.secondary;
  const parts = variant === "text" ? [v] : ["btn", v];
  if (opts.size === "sm") parts.push("btn-sm");
  if (opts.block) parts.push("btn-block");
  if (opts.className) parts.push(opts.className);
  return parts.join(" ");
}

/** A real `<button type="button">` by default; every use must have a stated function. */
export function Button({
  variant = "secondary",
  size,
  block,
  busy,
  className,
  type = "button",
  disabled,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      type={type}
      className={buttonClass(variant, { size, block, className })}
      disabled={disabled || busy}
      aria-busy={busy ? true : undefined}
    >
      {busy && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}
