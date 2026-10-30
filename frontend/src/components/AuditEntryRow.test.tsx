import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import type { AuditEntry } from "../api";
import { AuditEntryRow } from "./AuditEntryRow";

const HASH = "abcdef0123456789".repeat(4);

function row(entry: Record<string, unknown>, density?: "page" | "compact") {
  return render(<AuditEntryRow entry={entry as unknown as AuditEntry} density={density} />);
}

test("a triage entry reads 'Triage · finding {id} → {verdict} ({conf})'", () => {
  const { container } = row({ ts: "2026-10-04T10:00:00Z", finding_id: "n1", verdict: "TRUE_POSITIVE", confidence: 0.9, entry_hash: HASH });
  expect(screen.getByText("Triage")).toBeInTheDocument();
  expect(screen.getByText(/finding n1 → TRUE_POSITIVE \(0\.90\)/)).toBeInTheDocument();
  expect(screen.getByText("2026-10-04T10:00:00Z")).toBeInTheDocument();
  expect(container.querySelector(".audit-hash")).toHaveTextContent("abcdef012345");
  expect(screen.queryByText(HASH)).toBeNull();
});

test("a human decision, a policy gate and a verification run keep their exact strings", () => {
  const a = row({ type: "gate_decision", gate_id: "g1", decision: "approved", entry_hash: "1" });
  expect(screen.getByText("Human decision")).toBeInTheDocument();
  expect(screen.getByText(/gate g1 → approved/)).toBeInTheDocument();
  a.unmount();
  const b = row({ type: "gate_evaluation", decision: "FAIL", exit_code: 1 });
  expect(screen.getByText("Policy gate")).toBeInTheDocument();
  expect(screen.getByText(/FAIL \(exit 1\)/)).toBeInTheDocument();
  b.unmount();
  row({ type: "gate_execution", gate_id: "g9", outcome: "ran" });
  expect(screen.getByText("Verification run")).toBeInTheDocument();
  expect(screen.getByText(/gate g9 → ran/)).toBeInTheDocument();
});

test("missing fields fall back to '?', and no hash chip is drawn without a hash", () => {
  const { container } = row({ type: "gate_decision" });
  expect(screen.getByText(/gate \? → \?/)).toBeInTheDocument();
  expect(container.querySelector(".audit-hash")).toBeNull();
});

test("the node glyph and tint are fixed per entry type and decorative", () => {
  const kinds: [Record<string, unknown>, string][] = [
    [{ finding_id: "x" }, "audit-node--triage"],
    [{ type: "gate_decision" }, "audit-node--decision"],
    [{ type: "gate_evaluation" }, "audit-node--policy"],
    [{ type: "gate_execution" }, "audit-node--run"],
  ];
  for (const [entry, cls] of kinds) {
    const { container, unmount } = row(entry);
    const node = container.querySelector(".audit-node");
    expect(node).toHaveClass(cls);
    expect(node).toHaveAttribute("aria-hidden", "true");
    expect(node?.querySelector("svg")).not.toBeNull();
    unmount();
  }
});

test("an unrecognised entry type is shown as a triage entry, never as its own class name", () => {
  const { container } = row({ type: "constructor", finding_id: "f" });
  expect(container.querySelector(".audit-node")).toHaveClass("audit-node--triage");
  expect(container.innerHTML).not.toContain("constructor");
});

test("density only adds a modifier class", () => {
  expect(row({}).container.firstElementChild).toHaveClass("audit-row", "audit-row--page");
  expect(row({}, "compact").container.firstElementChild).toHaveClass("audit-row--compact");
});

test("values render as text, not HTML", () => {
  const evil = "<img src=x onerror=alert(1)>";
  const { container } = row({ type: "gate_decision", gate_id: evil, decision: evil, ts: evil, entry_hash: evil });
  expect(container.querySelector("img")).toBeNull();
  expect(container.textContent).toContain(evil);
});
