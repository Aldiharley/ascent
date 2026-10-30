import { render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { PolicyGate } from "./PolicyGate";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}
function report(over: Record<string, unknown> = {}) {
  return {
    policy: { name: "ci", hash: "abcdef0123456789" },
    decision: "FAIL", exit_code: 1, complete: true, failed_tools: [],
    counts: { evaluated: 3, failed: 1, warned: 1, demoted_fp: 0 },
    failed: [{ fingerprint: "ascent/v1:aa", rule_id: "py.sqli", severity: "HIGH", category: "SAST",
               title: "SQL injection", locus: "app.py:3", reason: "severity HIGH in fail_on" }],
    warned: [], evaluated_at: "2026-10-30T00:00:00Z",
    ...over,
  };
}
afterEach(() => vi.restoreAllMocks());

test("shows a FAIL verdict with the failing finding and exit code", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report()));
  render(<PolicyGate />);
  expect(await screen.findByText("FAIL")).toBeInTheDocument();
  expect(screen.getByText("SQL injection")).toBeInTheDocument();
  expect(screen.getByText("app.py:3")).toBeInTheDocument();
  expect(screen.getByText(/exit 1/)).toBeInTheDocument();
  expect(screen.getByText(/policy ci/)).toBeInTheDocument();
});

test("PASS and CONDITIONAL render their own labels", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report({ decision: "PASS", exit_code: 0, failed: [] })));
  const { unmount } = render(<PolicyGate />);
  expect(await screen.findByText("PASS")).toBeInTheDocument();
  unmount();
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report({ decision: "CONDITIONAL", exit_code: 0, failed: [] })));
  render(<PolicyGate />);
  expect(await screen.findByText("CONDITIONAL")).toBeInTheDocument();
});

test("INCOMPLETE explains why it cannot pass", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(report({ decision: "INCOMPLETE", exit_code: 3, complete: false, failed: [], failed_tools: ["opengrep"] })),
  );
  render(<PolicyGate />);
  expect(await screen.findByText("INCOMPLETE")).toBeInTheDocument();
  expect(screen.getByText(/opengrep/)).toBeInTheDocument();
});

test("no gate yet shows how to enable one", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(null));
  render(<PolicyGate />);
  expect(await screen.findByText(/No policy verdict yet/)).toBeInTheDocument();
  // The copy names --policy twice (ascent run, ascent gate).
  expect(screen.getAllByText(/--policy/).length).toBeGreaterThan(0);
});

test("attacker-controlled strings render as text, not HTML", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(report({ failed: [{ fingerprint: "f", rule_id: "r", severity: "HIGH", category: "DAST",
      title: "<img src=x onerror=alert(1)>", locus: "https://x/", reason: "r" }] })),
  );
  const { container } = render(<PolicyGate />);
  expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
});
