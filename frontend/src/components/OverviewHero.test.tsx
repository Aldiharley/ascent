import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { OverviewHero } from "./OverviewHero";
import type { OverviewHeroProps } from "./OverviewHero";

function hero(over: Partial<OverviewHeroProps> = {}) {
  const props: OverviewHeroProps = {
    engagement: { kind: "named", name: "ascent-local-lab" },
    onNavigate: vi.fn(),
    now: new Date(2026, 9, 31, 9, 0, 0),
    ...over,
  };
  const r = render(<OverviewHero {...props} />);
  return { ...r, props };
}

test("greets by local time of day", () => {
  const cases: [number, string][] = [
    [4, "Good evening!"],
    [5, "Good morning!"],
    [11, "Good morning!"],
    [12, "Good afternoon!"],
    [17, "Good afternoon!"],
    [18, "Good evening!"],
  ];
  for (const [h, text] of cases) {
    const { unmount } = hero({ now: new Date(2026, 9, 31, h, 30) });
    expect(screen.getByText(text)).toHaveClass("hero-greet");
    unmount();
  }
});

test("a named engagement reads 'Watching {name}' with the name in bold", () => {
  const { container } = hero();
  const line = container.querySelector(".hero-eng") as HTMLElement;
  expect(line).toHaveTextContent("Watching ascent-local-lab");
  expect(line.querySelector("b")).toHaveTextContent("ascent-local-lab");
});

test("the hero never uses the sidebar chip's phrases", () => {
  const a = hero();
  expect(a.container.textContent).not.toMatch(/engagement:/);
  expect(a.container.textContent).not.toMatch(/no engagement loaded/);
  a.unmount();
  const b = hero({ engagement: { kind: "none" } });
  expect(b.container.textContent).not.toMatch(/engagement:/);
  expect(b.container.textContent).not.toMatch(/no engagement loaded/);
});

test("no engagement says to define a scope; loading and failure omit the line", () => {
  const a = hero({ engagement: { kind: "none" } });
  expect(screen.getByText("Define a scope to get started.")).toBeInTheDocument();
  a.unmount();
  const b = hero({ engagement: { kind: "error" } });
  expect(b.container.querySelector(".hero-eng")).toBeNull();
  b.unmount();
  const c = hero({ engagement: { kind: "loading" } });
  expect(c.container.querySelector(".hero-eng")).toBeNull();
});

test("an engagement name is text, never HTML", () => {
  const evil = "<img src=x onerror=alert(1)>";
  const { container } = hero({ engagement: { kind: "named", name: evil } });
  expect(screen.getByText(evil)).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
});

test("the summary line joins only what has loaded", () => {
  const a = hero({ summary: { needsReview: 3, pending: 1, decision: "FAIL" } });
  expect(a.container.querySelector(".hero-sum")).toHaveTextContent("3 need your review · 1 approval pending · policy FAIL");
  a.unmount();
  const b = hero({ summary: { needsReview: 0, pending: 2, decision: null } });
  expect(b.container.querySelector(".hero-sum")).toHaveTextContent("2 approvals pending");
  b.unmount();
  const c = hero({ summary: { needsReview: 4 } });
  expect(c.container.querySelector(".hero-sum")).toHaveTextContent("4 need your review");
  c.unmount();
  const d = hero({ summary: { decision: "PASS" } });
  expect(d.container.querySelector(".hero-sum")).toHaveTextContent("policy PASS");
});

test("all quiet only when findings and gates are loaded, both zero, and no verdict exists", () => {
  const a = hero({ summary: { needsReview: 0, pending: 0, decision: null } });
  expect(screen.getByText("All quiet. Nothing needs you right now.")).toBeInTheDocument();
  a.unmount();
  // A verdict exists: it is summarised instead.
  const b = hero({ summary: { needsReview: 0, pending: 0, decision: "PASS" } });
  expect(screen.queryByText(/All quiet/)).toBeNull();
  expect(b.container.querySelector(".hero-sum")).toHaveTextContent("policy PASS");
  b.unmount();
  // Findings still loading: do not claim quiet.
  const c = hero({ summary: { pending: 0, decision: null } });
  expect(screen.queryByText(/All quiet/)).toBeNull();
  expect(c.container.querySelector(".hero-sum")).toBeNull();
});

test("an unknown policy decision from the API is shown as INCOMPLETE, not as its own text", () => {
  const { container } = hero({ summary: { decision: "constructor" as never } });
  expect(container.querySelector(".hero-sum")).toHaveTextContent("policy INCOMPLETE");
});

test("'Define a new scan' goes to New scan; 'Run' and 'Start' wording is never used", () => {
  const { props, container } = hero();
  fireEvent.click(screen.getByRole("button", { name: "Define a new scan" }));
  expect(props.onNavigate).toHaveBeenCalledWith("newscan");
  expect(container.textContent).not.toMatch(/\b(start|run|launch)\b/i);
});

test("'Review approvals' appears only while approvals are pending and goes to Approval gates", () => {
  const a = hero({ summary: { pending: 0 } });
  expect(screen.queryByRole("button", { name: "Review approvals" })).toBeNull();
  a.unmount();
  const { props } = hero({ summary: { pending: 2 } });
  fireEvent.click(screen.getByRole("button", { name: "Review approvals" }));
  expect(props.onNavigate).toHaveBeenCalledWith("gates");
});

test("the mascot and waves are decorative and there is no <img>", () => {
  const { container } = hero();
  const mascot = container.querySelector(".mascot--hero");
  expect(mascot).toHaveClass("mascot", "mascot--float");
  expect(mascot).toHaveAttribute("aria-hidden", "true");
  expect(mascot?.getAttribute("style") ?? "").toBe(""); // size comes from the breakpoint CSS
  expect(container.querySelector(".hero-waves")?.closest("[aria-hidden=true]")).not.toBeNull();
  expect(container.querySelectorAll(".hero-waves path")).toHaveLength(4); // 3 waves + knit lines overlay
  expect(container.querySelector("img")).toBeNull();
});
