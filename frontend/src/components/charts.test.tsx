import { fireEvent, render, screen, within } from "@testing-library/react";
import { expect, test } from "vitest";
import type { Severity, TriageItem, Verdict } from "../api";
import { DonutCard, categoryMix, verdictMix } from "./DonutCard";
import { SegmentedControl } from "./SegmentedControl";
import { SeverityBarChart, niceStep, severityCounts } from "./SeverityBarChart";

function item(
  severity: Severity | string,
  verdict: Verdict | string = "TRUE_POSITIVE",
  category?: string,
): TriageItem {
  return {
    finding: { id: `${severity}-${verdict}-${category}`, rule_id: "r", severity, title: "t", category },
    verdict,
    confidence: 0.5,
    fp_likelihood: 0.5,
  } as unknown as TriageItem;
}

// ---- SegmentedControl ----

test("a segmented control is a labelled group of aria-pressed buttons", () => {
  const picks: string[] = [];
  render(
    <SegmentedControl
      label="Show"
      value="a"
      options={[
        { value: "a", label: "Alpha" },
        { value: "b", label: "Beta" },
        { value: "c", label: "Gamma", disabled: true },
      ]}
      onChange={(v) => picks.push(v)}
    />,
  );
  const group = screen.getByRole("group", { name: "Show" });
  expect(group).toHaveClass("segs");
  expect(within(group).getByRole("button", { name: "Alpha" })).toHaveAttribute("aria-pressed", "true");
  expect(within(group).getByRole("button", { name: "Beta" })).toHaveAttribute("aria-pressed", "false");
  expect(within(group).getByRole("button", { name: "Gamma" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Beta" }));
  expect(picks).toEqual(["b"]);
});

// ---- SeverityBarChart ----

test("niceStep picks the smallest of 1, 2, 5, 10, 20, 50, ... at or above the input", () => {
  expect([0.25, 1, 1.5, 2, 3, 5, 6, 12, 30, 75, 101].map(niceStep)).toEqual([
    1, 1, 2, 2, 5, 5, 10, 20, 50, 100, 200,
  ]);
});

test("severityCounts counts the five tiers, an unknown severity falling into Info", () => {
  const items = [item("CRITICAL"), item("HIGH"), item("HIGH", "ABSTAIN"), item("weird"), item("constructor")];
  expect(severityCounts(items, "all")).toEqual({ CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 2 });
  // Confirmed = TRUE_POSITIVE only.
  expect(severityCounts(items, "confirmed")).toEqual({ CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 2 });
});

const mixed = [
  item("CRITICAL"),
  item("CRITICAL", "ABSTAIN"),
  item("HIGH"),
  item("HIGH"),
  item("HIGH", "LIKELY_FALSE_POSITIVE"),
  item("MEDIUM"),
  item("MEDIUM", "ABSTAIN"),
  item("MEDIUM", "ABSTAIN"),
  item("LOW"),
];

test("the bar chart states every value in its accessible name and prints them as text", () => {
  const { container } = render(<SeverityBarChart items={mixed} />);
  const chart = screen.getByRole("img", {
    name: "Findings by severity: Critical 2, High 3, Medium 3, Low 1, Info 0",
  });
  expect(chart.tagName.toLowerCase()).toBe("svg");
  expect(screen.getByRole("heading", { level: 2, name: "Findings by severity" })).toBeInTheDocument();
  const values = [...container.querySelectorAll(".val-text")].map((n) => n.textContent);
  expect(values).toEqual(["2", "3", "3", "1", "0"]);
  const labels = [...container.querySelectorAll(".x-text")].map((n) => n.textContent);
  expect(labels).toEqual(["Critical", "High", "Medium", "Low", "Info"]);
});

test("the y scale uses a nice step: max 3 gives ticks 0..4, max 30 gives 0, 10, 20, 30, 40", () => {
  const { container, rerender } = render(<SeverityBarChart items={mixed} />);
  const ticks = () => [...container.querySelectorAll(".tick-text")].map((n) => n.textContent);
  expect(ticks()).toEqual(["0", "1", "2", "3", "4"]);
  const many = Array.from({ length: 30 }, (_, i) => item("HIGH", "TRUE_POSITIVE", `c${i}`));
  rerender(<SeverityBarChart items={many} />);
  expect(ticks()).toEqual(["0", "10", "20", "30", "40"]);
});

test("a bar is a path with a rounded top whose height follows the count", () => {
  const four = [item("CRITICAL"), item("CRITICAL"), item("HIGH"), item("HIGH"), item("HIGH"), item("HIGH")];
  const { container } = render(<SeverityBarChart items={four} />);
  const bars = container.querySelectorAll("path.bar-rect");
  expect(bars).toHaveLength(2); // Critical and High; the three empty tiers are stubs
  // yMax = 4, so 2 findings is half of the 176px plot; x = 44 + (92.8 - 44) / 2.
  expect(bars[0].getAttribute("d")).toBe("M68.4,196 V118 Q68.4,108 78.4,108 H102.4 Q112.4,108 112.4,118 V196 Z");
  // A full-height bar reaches y = 20.
  expect(bars[1].getAttribute("d")).toContain("V30 Q");
});

test("a zero count is a flat stub, not a path", () => {
  const { container } = render(<SeverityBarChart items={[item("HIGH")]} />);
  expect(container.querySelectorAll("path.bar-rect")).toHaveLength(1);
  const stubs = container.querySelectorAll("rect.bar-stub");
  expect(stubs).toHaveLength(4);
  expect(stubs[0]).toHaveAttribute("width", "44");
  expect(stubs[0]).toHaveAttribute("height", "4");
});

test("the Confirmed switch recomputes the counts", () => {
  const { container } = render(<SeverityBarChart items={mixed} />);
  const all = screen.getByRole("button", { name: "All" });
  const confirmed = screen.getByRole("button", { name: "Confirmed" });
  expect(all).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(confirmed);
  expect(confirmed).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("img", { name: /^Confirmed findings by severity: Critical 1, High 2, Medium 1, Low 1, Info 0$/ })).toBeInTheDocument();
  expect([...container.querySelectorAll(".val-text")].map((n) => n.textContent)).toEqual(["1", "2", "1", "1", "0"]);
});

test("an empty chart is still drawn, with an empty-state note", () => {
  const { container } = render(<SeverityBarChart items={[]} />);
  expect(screen.getByRole("img", { name: "Findings by severity: Critical 0, High 0, Medium 0, Low 0, Info 0" })).toBeInTheDocument();
  expect(container.querySelectorAll("rect.bar-stub")).toHaveLength(5);
  expect(screen.getByText("No findings yet")).toBeInTheDocument();
});

// ---- DonutCard ----

test("verdictMix and categoryMix bucket by fixed enums; unknown values fail safe", () => {
  const items = [
    item("HIGH", "TRUE_POSITIVE", "DAST"),
    item("HIGH", "ABSTAIN", "SAST"),
    item("HIGH", "LIKELY_FALSE_POSITIVE", "SCA"),
    item("HIGH", "bogus", "weird"),
    item("HIGH", "constructor", undefined),
  ];
  expect(verdictMix(items).map((s) => [s.label, s.value])).toEqual([
    ["True positive", 1],
    ["Needs human", 3],
    ["Likely noise", 1],
  ]);
  expect(categoryMix(items).map((s) => [s.label, s.value])).toEqual([
    ["DAST", 1],
    ["SAST", 1],
    ["SCA", 1],
    ["Uncategorised", 2],
  ]);
});

test("the donut card shows the verdict mix with a legend of counts and percents", () => {
  const items = [item("HIGH"), item("HIGH"), item("HIGH", "ABSTAIN"), item("HIGH", "LIKELY_FALSE_POSITIVE")];
  const { container } = render(<DonutCard items={items} />);
  expect(screen.getByRole("heading", { level: 2, name: "Verdict mix" })).toBeInTheDocument();
  expect(
    screen.getByRole("img", { name: "Verdict mix: True positive 2, Needs human 1, Likely noise 1" }),
  ).toBeInTheDocument();
  const rows = [...container.querySelectorAll(".legend-row")].map((r) => r.textContent);
  expect(rows).toEqual(["True positive250%", "Needs human125%", "Likely noise125%"]);
  expect(container.querySelector(".donut-total")).toHaveTextContent("4");
  expect(screen.getByText("findings")).toBeInTheDocument();
});

test("donut segments use dasharray/dashoffset with a 3px gap when two or more are drawn", () => {
  const C = 2 * Math.PI * 72;
  const items = [item("HIGH"), item("HIGH"), item("HIGH", "ABSTAIN"), item("HIGH", "LIKELY_FALSE_POSITIVE")];
  const { container } = render(<DonutCard items={items} />);
  const segs = container.querySelectorAll("circle.donut-seg");
  expect(segs).toHaveLength(3);
  const dash = (el: Element) => (el.getAttribute("stroke-dasharray") ?? "").split(" ").map(Number);
  expect(dash(segs[0])[0]).toBeCloseTo(C * 0.5 - 3, 2);
  expect(dash(segs[1])[0]).toBeCloseTo(C * 0.25 - 3, 2);
  expect(Number(segs[0].getAttribute("stroke-dashoffset"))).toBeCloseTo(0, 5);
  expect(Number(segs[1].getAttribute("stroke-dashoffset"))).toBeCloseTo(-C * 0.5, 2);
  expect(Number(segs[2].getAttribute("stroke-dashoffset"))).toBeCloseTo(-C * 0.75, 2);
  expect(segs[0]).toHaveAttribute("transform", "rotate(-90 100 100)");
});

test("every segment carries the circumference its draw-in animation starts from", () => {
  const C = 2 * Math.PI * 72;
  const items = [item("HIGH"), item("HIGH", "ABSTAIN")];
  const { container } = render(<DonutCard items={items} />);
  const segs = container.querySelectorAll<SVGCircleElement>("circle.donut-seg");
  expect(segs).toHaveLength(2);
  for (const seg of segs) {
    expect(Number(seg.style.getPropertyValue("--donut-circ"))).toBeCloseTo(C, 2);
  }
  // the radius and the circumference are one fact: the dasharray's gap length is the same number
  expect(Number((segs[0].getAttribute("stroke-dasharray") ?? "").split(" ")[1])).toBeCloseTo(C, 2);
});

test("the donut and hero art take their colours from tokens, never a hex literal", () => {
  const { container } = render(<DonutCard items={[item("HIGH")]} />);
  expect(container.innerHTML).not.toMatch(/#[0-9a-fA-F]{3,6}\b(?!-)/);
});

test("one drawn segment has no gap and zero-value segments are not drawn", () => {
  const C = 2 * Math.PI * 72;
  const { container } = render(<DonutCard items={[item("HIGH"), item("LOW")]} />);
  const segs = container.querySelectorAll("circle.donut-seg");
  expect(segs).toHaveLength(1);
  expect(Number((segs[0].getAttribute("stroke-dasharray") ?? "").split(" ")[0])).toBeCloseTo(C, 2);
});

test("an empty donut draws only the track with 0 in the centre and zero legend rows", () => {
  const { container } = render(<DonutCard items={[]} />);
  expect(container.querySelectorAll("circle.donut-seg")).toHaveLength(0);
  expect(container.querySelector("circle.donut-track")).not.toBeNull();
  expect(container.querySelector(".donut-total")).toHaveTextContent("0");
  expect([...container.querySelectorAll(".legend-row")].map((r) => r.textContent)).toEqual([
    "True positive00%",
    "Needs human00%",
    "Likely noise00%",
  ]);
  expect(screen.getByText("No findings yet")).toBeInTheDocument();
});

test("the Category switch regroups by category and renames the card", () => {
  const items = [
    item("HIGH", "TRUE_POSITIVE", "DAST"),
    item("HIGH", "TRUE_POSITIVE", "DAST"),
    item("HIGH", "ABSTAIN", "SAST"),
    item("HIGH", "ABSTAIN", undefined),
  ];
  render(<DonutCard items={items} />);
  fireEvent.click(screen.getByRole("button", { name: "Category" }));
  expect(screen.getByRole("heading", { level: 2, name: "Category mix" })).toBeInTheDocument();
  expect(
    screen.getByRole("img", { name: "Category mix: DAST 2, SAST 1, SCA 0, Uncategorised 1" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Category" })).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(screen.getByRole("button", { name: "Verdict" }));
  expect(screen.getByRole("heading", { level: 2, name: "Verdict mix" })).toBeInTheDocument();
});

test("scanned strings never reach the charts' markup as anything but fixed labels", () => {
  const evil = "<img src=x onerror=alert(1)>";
  const items = [item(evil, evil, evil)];
  const { container } = render(
    <>
      <SeverityBarChart items={items} />
      <DonutCard items={items} />
    </>,
  );
  expect(container.innerHTML).not.toContain("onerror");
  expect(container.querySelector("img")).toBeNull();
});
