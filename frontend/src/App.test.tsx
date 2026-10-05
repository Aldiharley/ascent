import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import App from "./App";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

const finding = {
  finding: { id: "f1", rule_id: "ssrf-1", severity: "HIGH", title: "SSRF in fetch", url: "http://lab/x" },
  verdict: "TRUE_POSITIVE",
  confidence: 0.9,
  fp_likelihood: 0.1,
};

const gate = {
  id: "g1",
  title: "Confirm SSRF",
  why: "w",
  command: "nuclei ...",
  target: "/x",
  in_scope: true,
};

/** Routes fetch by URL path; `overrides` replaces a route (a function result is used as the Response). */
function mockApi(overrides: Record<string, () => Response | Promise<Response>> = {}) {
  const routes: Record<string, () => Response | Promise<Response>> = {
    "/api/findings": () => json([finding]),
    "/api/gates": () => json([gate]),
    "/api/audit": () => json({ entries: [], chain_ok: true }),
    "/api/report": () => json({ markdown: "## Report body" }),
    "/api/engagement": () => json({ name: "ascent-local-lab" }),
    ...overrides,
  };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const path = String(input);
    const route = routes[path];
    if (!route) throw new Error(`unmocked fetch: ${path}`);
    return route();
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("overview shows the findings table and the gate panel", async () => {
  mockApi();
  render(<App />);
  expect(await screen.findByText("SSRF in fetch")).toBeInTheDocument();
  expect(await screen.findByText("Approval required")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Overview" })).toHaveAttribute("aria-current", "page");
});

test("overview also shows the audit feed in the aside", async () => {
  mockApi();
  render(<App />);
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
});

test("rail switches to gates", async () => {
  mockApi();
  render(<App />);
  await screen.findByText("SSRF in fetch");
  fireEvent.click(screen.getByRole("button", { name: "Approval gates" }));
  expect(await screen.findByText("Approval required")).toBeInTheDocument();
  expect(screen.queryByText("SSRF in fetch")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Approval gates" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("button", { name: "Overview" })).not.toHaveAttribute("aria-current");
});

test("rail switches to the audit screen and shows the chain badge", async () => {
  mockApi();
  render(<App />);
  await screen.findByText("SSRF in fetch");
  fireEvent.click(screen.getByRole("button", { name: "Audit" }));
  expect(await screen.findByText("Hash chain OK")).toBeInTheDocument();
  expect(screen.queryByText("SSRF in fetch")).not.toBeInTheDocument();
});

test("rail switches to findings and report screens", async () => {
  mockApi();
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Report" }));
  expect(await screen.findByText("Report body")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Findings" }));
  expect(await screen.findByText("SSRF in fetch")).toBeInTheDocument();
  expect(screen.queryByText("Approval required")).not.toBeInTheDocument();
});

test("topbar shows the engagement name", async () => {
  mockApi();
  render(<App />);
  expect(await screen.findByText(/engagement: ascent-local-lab/)).toBeInTheDocument();
});

test("topbar falls back to a neutral status when the engagement is null", async () => {
  mockApi({ "/api/engagement": () => json(null) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  expect(screen.getByText(/no engagement loaded/)).toBeInTheDocument();
});

test("topbar falls back to a neutral status when the engagement fetch fails", async () => {
  mockApi({ "/api/engagement": () => json({ error: "x" }, 500) });
  render(<App />);
  await screen.findByText("SSRF in fetch");
  await waitFor(() => expect(screen.getByText(/no engagement loaded/)).toBeInTheDocument());
});

test("deciding a gate refreshes the audit feed", async () => {
  let decided = false;
  mockApi({
    "/api/gates/g1/approve": () => {
      decided = true;
      return json({ ok: true });
    },
    "/api/audit": () =>
      json({
        entries: decided ? [{ type: "gate_decision", gate_id: "g1", decision: "approved", entry_hash: "abc" }] : [],
        chain_ok: true,
      }),
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  expect(await screen.findByText(/gate g1 → approved/)).toBeInTheDocument();
});
