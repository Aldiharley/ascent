import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { __resetResourceCache } from "../data/resources";
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

test("renders a gate_evaluation entry as the policy gate verdict", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    json({
      entries: [
        { type: "gate_evaluation", decision: "FAIL", exit_code: 1, ts: "t", prev_hash: "a", entry_hash: "b" },
      ],
      chain_ok: true,
    }),
  );
  render(<Audit />);
  expect(await screen.findByText(/Policy gate/)).toBeInTheDocument();
  expect(screen.getByText(/FAIL \(exit 1\)/)).toBeInTheDocument();
  expect(screen.queryByText(/Triage/)).toBeNull();
});

test("renders a gate_execution entry with its outcome", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    json({
      entries: [{ type: "gate_execution", gate_id: "g9", outcome: "ran", ts: "t", entry_hash: "b" }],
      chain_ok: true,
    }),
  );
  render(<Audit />);
  expect(await screen.findByText(/Verification run/)).toBeInTheDocument();
  expect(screen.getByText(/gate g9 → ran/)).toBeInTheDocument();
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

test("a new version refetches and swaps the entries in place, without a loading flash", async () => {
  const log = (id: string) => json({ entries: [{ type: "gate_decision", gate_id: id, decision: "approved", entry_hash: id }], chain_ok: true });
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(log("g1")).mockResolvedValueOnce(log("g2"));
  const { rerender } = render(<Audit version={0} />);
  expect(await screen.findByText(/gate g1 → approved/)).toBeInTheDocument();
  rerender(<Audit version={1} />);
  expect(screen.getByText(/gate g1 → approved/)).toBeInTheDocument();
  expect(screen.queryByText(/Loading audit log/)).toBeNull();
  expect(await screen.findByText(/gate g2 → approved/)).toBeInTheDocument();
});

test("the timeline uses the shared audit rows in log order", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    json({
      entries: [
        { type: "gate_decision", gate_id: "g1", decision: "approved", entry_hash: "a" },
        { type: "gate_execution", gate_id: "g1", outcome: "ran", entry_hash: "b" },
      ],
      chain_ok: true,
    }),
  );
  const { container } = render(<Audit />);
  await screen.findByText(/Human decision/);
  const rows = [...container.querySelectorAll(".feed--page .audit-row")];
  expect(rows).toHaveLength(2);
  expect(rows[0]).toHaveTextContent("Human decision");
  expect(rows[1]).toHaveTextContent("Verification run");
});

test("error state when the request fails", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(json({}, 500));
  render(<Audit />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not load/i);
});

// ---------------------------------------------------------------------------------------------
// Task 6: chain card, type filter, timeline.
// ---------------------------------------------------------------------------------------------

const MIXED = {
  entries: [
    { type: "triage", finding_id: "n1", verdict: "TRUE_POSITIVE", confidence: 0.9, ts: "t1", entry_hash: "a".repeat(64) },
    { type: "gate_decision", gate_id: "g1", decision: "approved", ts: "t2", entry_hash: "b".repeat(64) },
    { type: "gate_execution", gate_id: "g1", outcome: "ran", ts: "t3", entry_hash: "c".repeat(64) },
    { type: "gate_evaluation", decision: "FAIL", exit_code: 1, ts: "t4", entry_hash: "d".repeat(64) },
    { type: "gate_decision", gate_id: "g2", decision: "denied", ts: "t5", entry_hash: "e".repeat(64) },
    { finding_id: "n2", verdict: "ABSTAIN", ts: "t6", entry_hash: "f".repeat(64) },
  ],
  chain_ok: true,
};

function mockAudit(body: unknown) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(json(body));
}

function rowTitles(container: HTMLElement) {
  return Array.from(container.querySelectorAll(".feed--page .audit-row b")).map((b) => b.textContent);
}

test("the chain card: OK is a status pill with the entry count, no legacy glass or panel", async () => {
  mockAudit(MIXED);
  const { container } = render(<Audit />);
  const ok = await screen.findByText("Hash chain OK");
  expect(ok).toHaveAttribute("role", "status");
  expect(ok).toHaveClass("chain", "chain-ok");
  const card = ok.closest(".card") as HTMLElement;
  expect(card).toHaveTextContent("6 entries");
  expect(card.querySelector(".ibadge--teal")).not.toBeNull();
  expect(container.querySelector(".glass, .panel, .phead, .ptitle, .audit.glass, .note")).toBeNull();
  expect(screen.queryByRole("alert")).toBeNull();
});

test("a broken chain is the one alert, in a coral badge card, and the timeline is still shown", async () => {
  mockAudit({ ...MIXED, chain_ok: false });
  const { container } = render(<Audit />);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Hash chain FAIL: log may have been tampered with");
  expect(alert).toHaveClass("chain", "chain-fail");
  expect(screen.getAllByRole("alert")).toHaveLength(1);
  expect(alert.closest(".card")?.querySelector(".ibadge--coral")).not.toBeNull();
  expect(container.querySelectorAll(".feed--page .audit-row")).toHaveLength(6);
});

test("a single entry reads '1 entry'", async () => {
  mockAudit({ entries: [MIXED.entries[0]], chain_ok: true });
  render(<Audit />);
  expect(await screen.findByText("1 entry")).toBeInTheDocument();
});

test("the type filter labels counts and avoids the row titles", async () => {
  mockAudit(MIXED);
  render(<Audit />);
  const group = await screen.findByRole("group", { name: "Show" });
  const labels = within(group).getAllByRole("button").map((b) => b.textContent);
  expect(labels).toEqual(["All 6", "Verdicts 2", "Decisions 2", "Policy 1", "Runs 1"]);
  for (const l of labels) expect(l).not.toMatch(/Triage|Human decision|Policy gate|Verification run/);
  expect(within(group).getByRole("button", { name: "All 6" })).toHaveAttribute("aria-pressed", "true");
});

test("each filter narrows the timeline to its entry type and All restores it, in log order", async () => {
  mockAudit(MIXED);
  const { container } = render(<Audit />);
  const group = await screen.findByRole("group", { name: "Show" });
  const press = (name: string) => fireEvent.click(within(group).getByRole("button", { name }));

  press("Decisions 2");
  expect(rowTitles(container)).toEqual(["Human decision", "Human decision"]);
  expect(container.querySelectorAll(".feed--page .audit-row")[0]).toHaveTextContent("gate g1 → approved");
  expect(container.querySelectorAll(".feed--page .audit-row")[1]).toHaveTextContent("gate g2 → denied");
  expect(within(group).getByRole("button", { name: "Decisions 2" })).toHaveAttribute("aria-pressed", "true");
  expect(within(group).getByRole("button", { name: "All 6" })).toHaveAttribute("aria-pressed", "false");

  press("Verdicts 2");
  expect(rowTitles(container)).toEqual(["Triage", "Triage"]); // an entry with no type is a verdict
  press("Policy 1");
  expect(rowTitles(container)).toEqual(["Policy gate"]);
  press("Runs 1");
  expect(rowTitles(container)).toEqual(["Verification run"]);
  press("All 6");
  expect(rowTitles(container)).toEqual([
    "Triage", "Human decision", "Verification run", "Policy gate", "Human decision", "Triage",
  ]);
});

test("a filter with no entries is disabled; the chain FAIL stays the only alert while filtering", async () => {
  mockAudit({ entries: [MIXED.entries[0], MIXED.entries[1]], chain_ok: false });
  render(<Audit />);
  const group = await screen.findByRole("group", { name: "Show" });
  expect(within(group).getByRole("button", { name: "Policy 0" })).toBeDisabled();
  expect(within(group).getByRole("button", { name: "Runs 0" })).toBeDisabled();
  expect(within(group).getByRole("button", { name: "Verdicts 1" })).toBeEnabled();
  fireEvent.click(within(group).getByRole("button", { name: "Verdicts 1" }));
  expect(screen.getAllByRole("alert")).toHaveLength(1);
});

test("a selected filter that a refresh empties falls back to All instead of an empty list", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(MIXED))
    .mockResolvedValueOnce(json({ entries: [MIXED.entries[0]], chain_ok: true }));
  const { rerender, container } = render(<Audit version={0} />);
  const group = await screen.findByRole("group", { name: "Show" });
  fireEvent.click(within(group).getByRole("button", { name: "Policy 1" }));
  expect(rowTitles(container)).toEqual(["Policy gate"]);
  rerender(<Audit version={1} />);
  await waitFor(() => expect(rowTitles(container)).toEqual(["Triage"]));
  expect(screen.getByRole("button", { name: "All 1" })).toHaveAttribute("aria-pressed", "true");
});

/** jsdom does no layout: make every element report these heights for the duration of a test. */
function stubLayout(scrollHeight: number, clientHeight: number) {
  const sh = vi.spyOn(HTMLElement.prototype, "scrollHeight", "get").mockReturnValue(scrollHeight);
  const ch = vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(clientHeight);
  return () => {
    sh.mockRestore();
    ch.mockRestore();
  };
}

test("the timeline is a labelled, keyboard-scrollable region of rows with hash chips", async () => {
  mockAudit(MIXED);
  const restore = stubLayout(900, 400); // taller than its box: it scrolls
  try {
    const { container } = render(<Audit />);
    await screen.findByRole("group", { name: "Show" });
    const feed = container.querySelector(".feed--page") as HTMLElement;
    expect(feed).toHaveAttribute("tabindex", "0");
    expectFeed(feed);
  } finally {
    restore();
  }
});

test("a timeline that fits its box is not a tab stop: there is nothing to scroll", async () => {
  mockAudit(MIXED);
  const restore = stubLayout(400, 400); // e.g. a phone, where the feed is not height-capped
  try {
    const { container } = render(<Audit />);
    await screen.findByRole("group", { name: "Show" });
    const feed = container.querySelector(".feed--page") as HTMLElement;
    expect(feed).not.toHaveAttribute("tabindex");
    expectFeed(feed); // still a labelled region with its rows
  } finally {
    restore();
  }
});

test("the tab stop follows the content: filtering a long timeline down to a few rows drops it", async () => {
  mockAudit(MIXED);
  let overflow = true;
  const sh = vi.spyOn(HTMLElement.prototype, "scrollHeight", "get").mockImplementation(() => (overflow ? 900 : 100));
  const ch = vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(400);
  try {
    const { container } = render(<Audit />);
    const group = await screen.findByRole("group", { name: "Show" });
    const feed = () => container.querySelector(".feed--page") as HTMLElement;
    expect(feed()).toHaveAttribute("tabindex", "0");
    overflow = false;
    fireEvent.click(within(group).getByRole("button", { name: "Policy 1" }));
    expect(feed()).not.toHaveAttribute("tabindex");
  } finally {
    sh.mockRestore();
    ch.mockRestore();
  }
});

function expectFeed(feed: HTMLElement) {
  expect(feed).toHaveAttribute("role", "region");
  expect(feed).toHaveAccessibleName("Audit timeline");
  expect(feed.querySelectorAll(".audit-hash")).toHaveLength(6);
  expect(feed.querySelectorAll(".audit-hash")[0]).toHaveTextContent("a".repeat(12));
  expect(feed.querySelectorAll("img")).toHaveLength(0);
}

test("empty log: chain card, 0 entries, the resting watchdog at 120px and no filter", async () => {
  mockAudit({ entries: [], chain_ok: true });
  const { container } = render(<Audit />);
  expect(await screen.findByText("No audit entries yet")).toBeInTheDocument();
  expect(screen.getByText("0 entries")).toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("Hash chain OK");
  expect(container.querySelector(".mascot--rest")).toHaveStyle({ width: "120px", height: "120px" });
  expect(screen.queryByRole("group", { name: "Show" })).toBeNull();
  expect(container.querySelector("img")).toBeNull();
});

test("loading is a status with a caption; a failure has Retry and refetches", async () => {
  let release!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch").mockReturnValueOnce(new Promise<Response>((res) => (release = res)));
  const { unmount } = render(<Audit />);
  expect(screen.getByRole("status")).toHaveTextContent("Loading audit log…");
  release(json(MIXED));
  await screen.findByRole("group", { name: "Show" });
  unmount();

  __resetResourceCache();
  vi.restoreAllMocks();
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({}, 500)).mockResolvedValueOnce(json(MIXED));
  render(<Audit />);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Could not load the audit log");
  fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));
  expect(await screen.findByRole("group", { name: "Show" })).toBeInTheDocument();
});

test("log strings are text, never markup", async () => {
  mockAudit({
    entries: [{ type: "gate_decision", gate_id: "<img src=x onerror=alert(1)>", decision: "<b>x</b>", ts: "<i>t</i>", entry_hash: "<u>hash</u>" }],
    chain_ok: true,
  });
  const { container } = render(<Audit />);
  await screen.findByRole("group", { name: "Show" });
  expect(container.querySelector("img, i, u, [onerror]")).toBeNull();
  expect(screen.getByText("<i>t</i>")).toBeInTheDocument();
});
