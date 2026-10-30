import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { IconRadar } from "./icons";
import { KpiTile } from "./KpiTile";

const base = { label: "Findings", value: 7, sub: "from 2 scanners", tone: "teal" as const, icon: <IconRadar /> };

test("a tile with onClick is a button that keeps the .kpi/.l/.n/.sub class names", () => {
  const onClick = vi.fn();
  const { container } = render(<KpiTile {...base} onClick={onClick} />);
  const tile = screen.getByRole("button");
  expect(tile).toHaveClass("kpi", "kpi--teal");
  expect(tile).toHaveAttribute("type", "button");
  expect(container.querySelector(".l")).toHaveTextContent("Findings");
  expect(container.querySelector(".n")).toHaveTextContent("7");
  expect(container.querySelector(".sub")).toHaveTextContent("from 2 scanners");
  fireEvent.click(tile);
  expect(onClick).toHaveBeenCalledTimes(1);
});

test("a tile without onClick is a plain div, not a control", () => {
  const { container } = render(<KpiTile {...base} />);
  expect(screen.queryByRole("button")).toBeNull();
  expect(container.firstElementChild?.tagName).toBe("DIV");
  expect(container.firstElementChild).toHaveClass("kpi");
});

test("pressed is exposed as aria-pressed only on interactive tiles", () => {
  const { rerender } = render(<KpiTile {...base} onClick={() => {}} pressed />);
  expect(screen.getByRole("button")).toHaveAttribute("aria-pressed", "true");
  rerender(<KpiTile {...base} onClick={() => {}} />);
  expect(screen.getByRole("button")).not.toHaveAttribute("aria-pressed");
  rerender(<KpiTile {...base} pressed />);
  expect(document.querySelector(".kpi")).not.toHaveAttribute("aria-pressed");
});

test("the tone class and compact class come from fixed tables", () => {
  const { container, rerender } = render(<KpiTile {...base} tone="lav" compact />);
  expect(container.firstElementChild).toHaveClass("kpi--lav", "kpi--compact");
  rerender(<KpiTile {...base} tone={"zzz" as never} />);
  expect(container.firstElementChild).toHaveClass("kpi--teal");
  expect(container.firstElementChild?.className).not.toMatch(/zzz/);
});

test("the icon sits in a decorative clay badge", () => {
  const { container } = render(<KpiTile {...base} tone="ice" />);
  const badge = container.querySelector(".ibadge");
  expect(badge).toHaveClass("ibadge--ice");
  expect(badge).toHaveAttribute("aria-hidden", "true");
});

test("label and sub-line render as text", () => {
  const evil = "<img src=x onerror=alert(1)>";
  const { container } = render(<KpiTile {...base} sub={evil} />);
  expect(screen.getByText(evil)).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
});
