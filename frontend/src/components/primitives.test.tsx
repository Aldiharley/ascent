import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import * as icons from "./icons";
import { IconBadge } from "./IconBadge";
import { ListCard } from "./ListCard";
import { SeverityChip } from "./SeverityChip";
import { Skeleton } from "./Skeleton";
import { VerdictChip } from "./VerdictChip";
import { VerdictPill } from "./VerdictPill";

test.each([
  ["CRITICAL", "sev-chip--crit"],
  ["HIGH", "sev-chip--high"],
  ["MEDIUM", "sev-chip--med"],
  ["LOW", "sev-chip--low"],
  ["INFO", "sev-chip--info"],
] as const)("SeverityChip %s", (sev, cls) => {
  render(<SeverityChip severity={sev} />);
  expect(screen.getByText(sev)).toHaveClass("sev-chip", cls);
});

test("SeverityChip fails safe for an unknown severity and never uses it as a class", () => {
  const { container } = render(<SeverityChip severity={'x" onload="y' as never} />);
  expect(container.firstElementChild).toHaveClass("sev-chip--info");
  expect(container.firstElementChild?.className).not.toMatch(/onload/);
  expect(container).toHaveTextContent("INFO");
});

test.each([
  ["TRUE_POSITIVE", "True positive", "vchip--tp"],
  ["ABSTAIN", "Needs human", "vchip--hu"],
  ["LIKELY_FALSE_POSITIVE", "Likely noise", "vchip--fp"],
] as const)("VerdictChip %s", (v, label, cls) => {
  render(<VerdictChip verdict={v} />);
  expect(screen.getByText(label)).toHaveClass("vchip", cls);
});

test("VerdictChip fails safe to Needs human", () => {
  render(<VerdictChip verdict={"WAT" as never} />);
  expect(screen.getByText("Needs human")).toHaveClass("vchip--hu");
});

test.each([
  ["PASS", "vpill--pass"],
  ["CONDITIONAL", "vpill--cond"],
  ["FAIL", "vpill--fail"],
  ["INCOMPLETE", "vpill--inc"],
] as const)("VerdictPill %s", (d, cls) => {
  render(<VerdictPill decision={d} />);
  expect(screen.getByText(d)).toHaveClass("vpill", cls);
});

test("VerdictPill with no verdict reads NOT EVALUATED; an unknown decision is INCOMPLETE", () => {
  const a = render(<VerdictPill decision={null} />);
  expect(a.getByText("NOT EVALUATED")).toHaveClass("vpill--none");
  a.unmount();
  const b = render(<VerdictPill decision={"MAYBE" as never} />);
  expect(b.getByText("INCOMPLETE")).toHaveClass("vpill--inc");
});

test("IconBadge is aria-hidden and takes a tone and size from fixed tables", () => {
  const { container } = render(
    <IconBadge tone="sand" size="lg">
      <icons.IconDocument />
    </IconBadge>,
  );
  const el = container.firstElementChild as HTMLElement;
  expect(el).toHaveAttribute("aria-hidden", "true");
  expect(el).toHaveClass("ibadge", "ibadge--sand", "ibadge--lg");
  expect(el.querySelector("svg")).not.toBeNull();
});

test("IconBadge defaults to a medium teal badge and rejects unknown tones", () => {
  const { container } = render(<IconBadge tone={"zzz" as never}>x</IconBadge>);
  expect(container.firstElementChild?.className).toBe("ibadge ibadge--teal");
});

test("every spec glyph is exported and is an aria-hidden 24px-viewBox stroke svg", () => {
  const names = [
    "IconGrid", "IconTarget", "IconSearchLines", "IconShieldCheck", "IconDocument", "IconChain",
    "IconRadar", "IconCrosshairCheck", "IconHand", "IconFunnelSlash", "IconRefresh", "IconBell",
    "IconLock", "IconInfo", "IconAlertTriangle", "IconAlertCircle", "IconTick", "IconX",
    "IconPlayCircle", "IconClipboard", "IconCopy", "IconChevronDown", "IconSearch",
  ] as const;
  for (const n of names) {
    const Glyph = icons[n];
    const { container, unmount } = render(<Glyph />);
    const svg = container.querySelector("svg") as SVGElement;
    expect(svg, n).not.toBeNull();
    expect(svg).toHaveAttribute("aria-hidden", "true");
    expect(svg).toHaveAttribute("viewBox", "0 0 24 24");
    expect(svg).toHaveAttribute("fill", "none");
    unmount();
  }
});

test("Button maps variants to the stylesheet classes and defaults to type=button", () => {
  render(<Button variant="primary">Go</Button>);
  const b = screen.getByRole("button", { name: "Go" });
  expect(b).toHaveAttribute("type", "button");
  expect(b).toHaveClass("btn", "btn-primary");
  expect(b).not.toHaveClass("btn-sm");
});

test("Button size and block modifiers, extra className, and click", () => {
  const onClick = vi.fn();
  render(
    <Button variant="secondary" size="sm" block className="extra" onClick={onClick}>
      Retry
    </Button>,
  );
  const b = screen.getByRole("button", { name: "Retry" });
  expect(b).toHaveClass("btn", "btn-secondary", "btn-sm", "btn-block", "extra");
  fireEvent.click(b);
  expect(onClick).toHaveBeenCalledTimes(1);
});

test("a busy Button shows a spinner, keeps its label, and is disabled", () => {
  const { container } = render(
    <Button variant="primary" busy>
      Approve
    </Button>,
  );
  const b = screen.getByRole("button", { name: "Approve" });
  expect(b).toBeDisabled();
  expect(b).toHaveAttribute("aria-busy", "true");
  expect(container.querySelector(".spinner")).not.toBeNull();
});

test("Skeleton is decorative and takes its size", () => {
  const { container } = render(<Skeleton h={20} w="60%" r={8} />);
  const el = container.firstElementChild as HTMLElement;
  expect(el).toHaveClass("skeleton");
  expect(el).toHaveAttribute("aria-hidden", "true");
  expect(el.style.height).toBe("20px");
  expect(el.style.width).toBe("60%");
  expect(el.style.borderRadius).toBe("8px");
});

test("EmptyState shows the rest mascot (no img), title, body and action", () => {
  const onClick = vi.fn();
  const { container } = render(
    <EmptyState title="No findings yet" action={<Button onClick={onClick}>Clear</Button>}>
      Run a scan first.
    </EmptyState>,
  );
  expect(screen.getByText("No findings yet")).toBeInTheDocument();
  expect(screen.getByText("Run a scan first.")).toBeInTheDocument();
  expect(container.querySelector(".mascot--rest")).toHaveAttribute("aria-hidden", "true");
  expect(container.querySelector("img")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Clear" }));
  expect(onClick).toHaveBeenCalled();
});

test("EmptyState renders hostile text literally", () => {
  const { container } = render(<EmptyState title={"No findings match “<img src=x onerror=1>”"} />);
  expect(container.querySelector("img")).toBeNull();
  expect(container).toHaveTextContent("<img src=x onerror=1>");
});

test("ErrorState is an alert with the puzzled mascot and an optional Retry", () => {
  const onRetry = vi.fn();
  const { container, rerender } = render(
    <ErrorState
      title="Could not load findings"
      detail="check that the Ascent backend is running"
      onRetry={onRetry}
    />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("Could not load findings");
  expect(screen.getByRole("alert")).toHaveTextContent("check that the Ascent backend is running");
  expect(container.querySelector(".mascot--puzzled")).toHaveAttribute("aria-hidden", "true");
  expect(container.querySelector("img")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(onRetry).toHaveBeenCalledTimes(1);
  rerender(<ErrorState title="Could not load findings" />);
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
});

test("ErrorState retry label is overridable", () => {
  render(<ErrorState title="x" onRetry={() => undefined} retryLabel="Try again" />);
  expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
});

test("ListCard: h2 title, count, labelled section, See all with a unique accessible name", () => {
  const onClick = vi.fn();
  render(
    <ListCard title="Top findings" count="3 triaged" seeAll={{ label: "findings", onClick }}>
      <p>row</p>
    </ListCard>,
  );
  const region = screen.getByRole("region", { name: "Top findings" });
  expect(region).toHaveClass("card", "list-card");
  expect(screen.getByRole("heading", { level: 2, name: "Top findings" })).toBeInTheDocument();
  expect(screen.getByText("3 triaged")).toHaveClass("count");
  fireEvent.click(screen.getByRole("button", { name: "See all findings" }));
  expect(onClick).toHaveBeenCalledTimes(1);
  expect(screen.getByText("row")).toBeInTheDocument();
});

test("ListCard without seeAll or count has no button and no count pill", () => {
  const { container } = render(
    <ListCard title="Recent audit" headExtra={<span>chain</span>}>
      <p>row</p>
    </ListCard>,
  );
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
  expect(container.querySelector(".count")).toBeNull();
  expect(screen.getByText("chain")).toBeInTheDocument();
});
