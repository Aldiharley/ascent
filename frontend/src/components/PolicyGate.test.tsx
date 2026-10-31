import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { __resetResourceCache } from "../data/resources";
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
  __resetResourceCache(); // a second mount in one test would otherwise be served from the cache
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

test("INCOMPLETE names analysers that were not installed", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(report({ decision: "INCOMPLETE", exit_code: 3, complete: false, failed: [],
                  skipped_tools: ["gitleaks", "trivy"] })),
  );
  render(<PolicyGate />);
  expect(await screen.findByText("INCOMPLETE")).toBeInTheDocument();
  expect(screen.getByText(/Analysers not installed: gitleaks, trivy\./)).toBeInTheDocument();
});

test("INCOMPLETE without skipped_tools says nothing about analysers", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(report({ decision: "INCOMPLETE", exit_code: 3, complete: false, failed: [], skipped_tools: "bogus" })),
  );
  render(<PolicyGate />);
  expect(await screen.findByText("INCOMPLETE")).toBeInTheDocument();
  expect(screen.queryByText(/Analysers not installed/)).toBeNull();
});

test("no gate yet shows how to enable one", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(null));
  render(<PolicyGate />);
  expect(await screen.findByText(/No policy verdict yet/)).toBeInTheDocument();
  // The copy names --policy twice (ascent run, ascent gate).
  expect(screen.getAllByText(/--policy/).length).toBeGreaterThan(0);
});

test("the card heading is the focus target for the sidebar's View verdict", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report()));
  render(<PolicyGate />);
  const h = await screen.findByRole("heading", { level: 2, name: "Policy gate" });
  expect(h).toHaveAttribute("id", "policy-gate-title");
  expect(h).toHaveAttribute("tabindex", "-1");
  expect(screen.getByRole("region", { name: "Policy gate" })).toBeInTheDocument(); // section aria-labelledby
});

test("the not-evaluated card keeps the same heading id", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(null));
  render(<PolicyGate />);
  const h = await screen.findByRole("heading", { level: 2, name: "Policy gate" });
  expect(h).toHaveAttribute("id", "policy-gate-title");
  expect(h).toHaveAttribute("tabindex", "-1");
  expect(screen.getByText("NOT EVALUATED")).toHaveClass("vpill", "vpill--none");
});

test("a verdict shows a tinted card, the pill, the headline, exit code and a 12-char policy hash", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report()));
  const { container } = render(<PolicyGate />);
  expect(await screen.findByText("FAIL")).toHaveClass("vpill", "vpill--fail");
  expect(container.querySelector("section.card.policy")).toHaveClass("policy--fail");
  expect(screen.getByText("Policy failed")).toHaveClass("policy-headline");
  expect(screen.getByText("exit 1")).toBeInTheDocument();
  expect(screen.getByText("policy ci · abcdef012345")).toBeInTheDocument();
});

test.each([
  ["PASS", "Policy passed", "policy--pass"],
  ["CONDITIONAL", "Passed with warnings", "policy--conditional"],
  ["INCOMPLETE", "Scan incomplete — cannot pass", "policy--incomplete"],
])("%s has its own headline and tint", async (decision, headline, cls) => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report({ decision, exit_code: 0, failed: [] })));
  const { container } = render(<PolicyGate />);
  expect(await screen.findByText(headline)).toBeInTheDocument();
  expect(container.querySelector("section.policy")).toHaveClass(cls);
});

test("the four counts stay readable as '<n> failing', '<n> warnings', ...", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(report({ counts: { evaluated: 9, failed: 4, warned: 3, demoted_fp: 2 } })),
  );
  render(<PolicyGate />);
  await screen.findByText("FAIL");
  const stat = (re: RegExp) => screen.getByText(re, { selector: ".stat" });
  expect(stat(/failing/)).toHaveTextContent("4 failing");
  expect(stat(/warnings/)).toHaveTextContent("3 warnings");
  expect(stat(/demoted likely-FP/)).toHaveTextContent("2 demoted likely-FP");
  expect(stat(/evaluated/)).toHaveTextContent("9 evaluated");
});

test("failing entries show a severity chip, title, locus and reason; warnings stand in when none failed", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(
      report({
        decision: "CONDITIONAL",
        exit_code: 0,
        failed: [],
        warned: [
          { fingerprint: "w1", rule_id: "r", severity: "MEDIUM", category: "SAST", title: "Weak hash", locus: "a.py:9", reason: "severity MEDIUM in warn_on" },
        ],
      }),
    ),
  );
  const { container } = render(<PolicyGate />);
  expect(await screen.findByText("Weak hash")).toBeInTheDocument();
  expect(container.querySelector(".sev-chip")).toHaveTextContent("MEDIUM");
  expect(screen.getByText("a.py:9")).toBeInTheDocument();
  expect(screen.getByText("severity MEDIUM in warn_on")).toBeInTheDocument();
});

test("only the first five entries are listed", async () => {
  const many = Array.from({ length: 8 }, (_, i) => ({
    fingerprint: `f${i}`, rule_id: "r", severity: "HIGH", category: "SAST", title: `Entry ${i}`, locus: "l", reason: "x",
  }));
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report({ failed: many })));
  render(<PolicyGate />);
  await screen.findByText("Entry 0");
  expect(screen.getByText("Entry 4")).toBeInTheDocument();
  expect(screen.queryByText("Entry 5")).toBeNull();
});

test("the footer says the verdict is read-only and chained into the audit log", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report()));
  render(<PolicyGate />);
  await screen.findByText("FAIL");
  expect(
    screen.getByText("Read-only verdict from out/gate.json, evaluated 2026-10-30T00:00:00Z. It is chained into the audit log."),
  ).toBeInTheDocument();
});

test("it offers no control that evaluates a policy or starts a run", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(report()));
  render(<PolicyGate />);
  await screen.findByText("FAIL");
  expect(screen.queryByRole("button")).toBeNull();
});

test("loading is a status with a visible caption; a failure is an alert with Retry", async () => {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({}, 500)).mockResolvedValueOnce(json(report()));
  render(<PolicyGate />);
  expect(screen.getByRole("status")).toHaveTextContent("Loading policy gate…");
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not load the policy gate");
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("FAIL")).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(2);
});

test("a new version swaps the verdict in place, without a loading flash", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(report()))
    .mockResolvedValueOnce(json(report({ decision: "PASS", exit_code: 0, failed: [] })));
  const { rerender } = render(<PolicyGate version={0} />);
  await screen.findByText("FAIL");
  rerender(<PolicyGate version={1} />);
  expect(screen.getByText("FAIL")).toBeInTheDocument();
  expect(screen.queryByText("Loading policy gate…")).toBeNull();
  expect(await screen.findByText("PASS")).toBeInTheDocument();
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
