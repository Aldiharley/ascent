import { act, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { __resetGateDecisions, forgetAllGateDecisions, markGateDecided, usePendingGates } from "./gates";

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

// The decided set is reset by src/test/setup.ts after RTL's cleanup has unmounted every Probe;
// resetting it here, before the cleanup, would update mounted Probes outside act().
afterEach(() => {
  vi.restoreAllMocks();
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
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate("a")]))
    .mockResolvedValueOnce(json([gate("b")])) // the server recorded the decision on "a"
    .mockResolvedValueOnce(json([gate("a"), gate("b")])); // ...and later proposes a new gate reusing the id
  const { rerender } = render(<Probe version={0} />);
  await screen.findByText("a");
  act(() => markGateDecided("a"));
  expect(await screen.findByText("none")).toBeInTheDocument();
  rerender(<Probe version={1} />);
  // Payload 2 has landed once "b" shows; it no longer lists "a", so the hiding of "a" is pruned there.
  expect(await screen.findByText("b")).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(2);
  rerender(<Probe version={2} />);
  expect(await screen.findByText("a,b")).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(3);
});

test("an id a payload still lists stays hidden (a slow or stale refetch must not resurrect it)", async () => {
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate("a")]))
    .mockResolvedValueOnce(json([gate("a"), gate("c")])); // still lists the decided "a"
  const { rerender } = render(<Probe version={0} />);
  await screen.findByText("a");
  act(() => markGateDecided("a"));
  rerender(<Probe version={1} />);
  // "c" proves the second payload landed; "a" must still be hidden alongside it.
  expect(await screen.findByText("c")).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(2);
  expect(screen.getByTestId("p")).not.toHaveTextContent("a");
});

test("__resetGateDecisions publishes: a mounted consumer shows the gate again", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([gate("a"), gate("b")]));
  render(<Probe />);
  await screen.findByText("a,b");
  act(() => markGateDecided("a"));
  expect(screen.getByTestId("p")).toHaveTextContent("b");
  act(() => __resetGateDecisions());
  expect(screen.getByTestId("p")).toHaveTextContent("a,b");
});

test("forgetAllGateDecisions (a new engagement) shows every listed gate again", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => json([gate("a"), gate("b")]));
  render(<Probe />);
  await screen.findByText("a,b");
  act(() => {
    markGateDecided("a");
    markGateDecided("b");
  });
  expect(screen.getByTestId("p")).toHaveTextContent("none");
  act(() => forgetAllGateDecisions());
  expect(screen.getByTestId("p")).toHaveTextContent("a,b");
});

test("a failed load is still an error", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 500 }));
  render(<Probe />);
  expect(await screen.findByText("error")).toBeInTheDocument();
});
