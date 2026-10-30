import { act, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { __resetGateDecisions, markGateDecided, usePendingGates } from "./gates";

function json(body: unknown) {
  return new Response(JSON.stringify(body));
}

const gate = (id: string) => ({ id, title: `Gate ${id}`, why: "w", command: "c", target: "/x", in_scope: true });

function Probe({ version = 0, label = "p" }: { version?: number; label?: string }) {
  const res = usePendingGates(version);
  return (
    <p data-testid={label}>
      {res.status === "ready" ? res.data.map((g) => g.id).join(",") || "none" : res.status}
    </p>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  __resetGateDecisions();
});

test("lists the pending gates", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([gate("a"), gate("b")]));
  render(<Probe />);
  expect(await screen.findByText("a,b")).toBeInTheDocument();
});

test("a decided gate disappears from every consumer at once, whatever the server still says", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([gate("a"), gate("b")]));
  render(
    <>
      <Probe label="one" />
      <Probe label="two" />
    </>,
  );
  await screen.findAllByText("a,b");
  act(() => markGateDecided("a"));
  expect(screen.getByTestId("one")).toHaveTextContent("b");
  expect(screen.getByTestId("one")).not.toHaveTextContent("a");
  expect(screen.getByTestId("two")).toHaveTextContent("b");
  expect(screen.getByTestId("two")).not.toHaveTextContent("a");
});

test("a gate decided before a view mounted is hidden from it", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([gate("a"), gate("b")]));
  markGateDecided("a");
  render(<Probe />);
  expect(await screen.findByText("b")).toBeInTheDocument();
});

test("an id a newer payload no longer lists is forgotten, so a later real pending gate is shown", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate("a")]))
    .mockResolvedValueOnce(json([])) // the server recorded the decision
    .mockResolvedValueOnce(json([gate("a")])); // ...and later proposes a new gate with the same id
  const { rerender } = render(<Probe version={0} />);
  await screen.findByText("a");
  act(() => markGateDecided("a"));
  expect(await screen.findByText("none")).toBeInTheDocument();
  rerender(<Probe version={1} />);
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20)); // payload 2 lands (empty): the id is pruned here
  });
  expect(screen.getByTestId("p")).toHaveTextContent("none");
  rerender(<Probe version={2} />);
  expect(await screen.findByText("a")).toBeInTheDocument();
});

test("an id a payload still lists stays hidden (a slow or stale refetch must not resurrect it)", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([gate("a")]));
  const { rerender } = render(<Probe version={0} />);
  await screen.findByText("a");
  act(() => markGateDecided("a"));
  rerender(<Probe version={1} />);
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
  expect(screen.getByTestId("p")).toHaveTextContent("none");
});

test("a failed load is still an error", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 500 }));
  render(<Probe />);
  expect(await screen.findByText("error")).toBeInTheDocument();
});
