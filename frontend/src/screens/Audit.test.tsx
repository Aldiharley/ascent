import { render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { Audit } from "./Audit";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("audit shows chain status", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(
      JSON.stringify({ entries: [{ ts: "t", verdict: "TRUE_POSITIVE", finding_id: "n1" }], chain_ok: true }),
    ),
  );
  render(<Audit />);
  expect(await screen.findByText(/chain .*OK/i)).toBeInTheDocument();
});

test("renders a triage entry with verdict, confidence and short hash", async () => {
  const hash = "abcdef0123456789".repeat(4);
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    json({
      entries: [
        {
          ts: "2026-10-04T10:00:00Z",
          finding_id: "n1",
          finding_hash: "f".repeat(64),
          triager: "crux",
          verdict: "TRUE_POSITIVE",
          confidence: 0.9,
          fp_likelihood: 0.1,
          prev_hash: "0".repeat(64),
          entry_hash: hash,
        },
      ],
      chain_ok: true,
    }),
  );
  render(<Audit />);
  expect(await screen.findByText(/Triage/)).toBeInTheDocument();
  expect(screen.getByText(/n1/)).toBeInTheDocument();
  expect(screen.getByText(/TRUE_POSITIVE/)).toBeInTheDocument();
  expect(screen.getByText(/0\.90/)).toBeInTheDocument();
  expect(screen.getByText(/2026-10-04T10:00:00Z/)).toBeInTheDocument();
  expect(screen.getByText(/abcdef012345/)).toBeInTheDocument();
  expect(screen.queryByText(hash)).toBeNull();
});

test("renders a gate_decision entry as a human decision", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    json({
      entries: [
        {
          ts: "2026-10-04T11:00:00Z",
          type: "gate_decision",
          gate_id: "g1",
          decision: "approved",
          prev_hash: "0".repeat(64),
          entry_hash: "123456789abcdef0".repeat(4),
        },
      ],
      chain_ok: true,
    }),
  );
  render(<Audit />);
  expect(await screen.findByText(/Human decision/)).toBeInTheDocument();
  expect(screen.getByText(/g1/)).toBeInTheDocument();
  expect(screen.getByText(/approved/)).toBeInTheDocument();
  expect(screen.queryByText(/Triage/)).toBeNull();
});

test("shows an alarming FAIL badge when the chain is broken", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    json({ entries: [{ ts: "t", verdict: "TRUE_POSITIVE", finding_id: "n1" }], chain_ok: false }),
  );
  render(<Audit />);
  const badge = await screen.findByText(/Hash chain FAIL: log may have been tampered with/i);
  expect(badge).toBeInTheDocument();
  expect(screen.queryByText(/chain .*OK/i)).toBeNull();
  expect(screen.getByRole("alert")).toContainElement(badge);
});

test("empty state when there are no entries", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ entries: [], chain_ok: true }));
  render(<Audit />);
  expect(await screen.findByText(/No audit entries yet/i)).toBeInTheDocument();
});

test("error state when the request fails", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(json({}, 500));
  render(<Audit />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not load/i);
});
