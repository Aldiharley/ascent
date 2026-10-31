import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { Gates } from "./Gates";

function gate(over: Record<string, unknown> = {}) {
  return {
    id: "g1",
    title: "Confirm SSRF",
    why: "w",
    command: "nuclei ...",
    target: "/x",
    in_scope: true,
    ...over,
  };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("approving a gate calls the api and removes it", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ ok: true }));
  render(<Gates />);
  const btn = await screen.findByRole("button", { name: /approve/i });
  fireEvent.click(btn);
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
  expect(screen.getByText(/recorded in the audit log/i)).toBeInTheDocument();
});

test("approve posts to /api/gates/g1/approve with the CSRF header", async () => {
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ ok: true }));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  await screen.findByText(/No actions awaiting approval/i);
  const [url, init] = spy.mock.calls[1] as [string, RequestInit];
  expect(url).toBe("/api/gates/g1/approve");
  expect(init.method).toBe("POST");
  expect(init.headers).toEqual({ "X-Ascent": "1" });
});

test("deny posts to /deny and removes the card", async () => {
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ ok: true }));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /deny/i }));
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
  expect((spy.mock.calls[1] as [string])[0]).toBe("/api/gates/g1/deny");
  expect(screen.getByText(/Denied/)).toBeInTheDocument();
});

test("an id containing a slash is URL-encoded", async () => {
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate({ id: "a/b c" })]))
    .mockResolvedValueOnce(json({ ok: true }));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  await screen.findByText(/No actions awaiting approval/i);
  expect((spy.mock.calls[1] as [string])[0]).toBe("/api/gates/a%2Fb%20c/approve");
});

test("409 removes the card with an already-decided toast", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ error: "decided" }, 409));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
  expect(screen.getByText(/already decided/i)).toBeInTheDocument();
});

test("500 keeps the card, shows an error toast and re-enables the buttons", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ error: "audit chain broken" }, 500));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/not recorded/i));
  expect(screen.getByText("Confirm SSRF")).toBeInTheDocument();
  expect(screen.queryByText(/No actions awaiting approval/i)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /approve/i })).toBeEnabled();
  expect(screen.getByRole("button", { name: /deny/i })).toBeEnabled();
});

test("a network failure keeps the card and re-enables the buttons", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockRejectedValueOnce(new TypeError("network down"));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /deny/i }));
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/not recorded/i));
  expect(screen.getByText("Confirm SSRF")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /deny/i })).toBeEnabled();
});

test("both buttons are disabled while a decision is in flight", async () => {
  let resolve!: (r: Response) => void;
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
  render(<Gates />);
  const approve = await screen.findByRole("button", { name: /approve/i });
  fireEvent.click(approve);
  await waitFor(() => expect(approve).toBeDisabled());
  expect(screen.getByRole("button", { name: /deny/i })).toBeDisabled();
  fireEvent.click(approve); // no double submit
  expect(spy).toHaveBeenCalledTimes(2);
  expect(screen.getByText("Confirm SSRF")).toBeInTheDocument(); // not removed before the response
  resolve(json({ ok: true }));
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
});

test("an out-of-scope gate has Approve disabled and Deny enabled", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate({ in_scope: false })]));
  render(<Gates />);
  expect(await screen.findByText(/Out of scope/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /approve/i })).toBeDisabled();
  expect(screen.getByRole("button", { name: /deny/i })).toBeEnabled();
});

test("an in-scope gate shows the In scope badge", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()]));
  render(<Gates />);
  expect(await screen.findByText(/In scope/i)).toBeInTheDocument();
  expect(screen.getByText("/x")).toBeInTheDocument();
  expect(screen.getByText("w")).toBeInTheDocument();
});

test("empty state for no gates", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([]));
  render(<Gates />);
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
});

test("shows an error state when the gates cannot be loaded", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({}, 500));
  render(<Gates />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not load/i);
});

test("command text containing HTML renders literally", async () => {
  const cmd = "<script>alert(1)</script>";
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate({ command: cmd })]));
  const { container } = render(<Gates />);
  expect(await screen.findByText(cmd)).toBeInTheDocument();
  expect(container.querySelector("script")).toBeNull();
});

function polite(c: HTMLElement) {
  return c.querySelector('[aria-live="polite"]') as HTMLElement;
}
function assertive(c: HTMLElement) {
  return c.querySelector('[aria-live="assertive"]') as HTMLElement;
}

test("approving g1 leaves g2 present with its buttons enabled", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Confirm XSS" })]))
    .mockResolvedValueOnce(json({ ok: true }));
  render(<Gates />);
  await screen.findByText("Confirm SSRF");
  fireEvent.click(screen.getAllByRole("button", { name: /approve/i })[0]);
  await waitFor(() => expect(screen.queryByText("Confirm SSRF")).not.toBeInTheDocument());
  expect(screen.getByText("Confirm XSS")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /approve/i })).toBeEnabled();
  expect(screen.getByRole("button", { name: /deny/i })).toBeEnabled();
});

test("a toast is visible after a decision and auto-dismisses after 5 seconds", async () => {
  vi.useFakeTimers();
  try {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json([gate()]))
      .mockResolvedValueOnce(json({ ok: true }));
    render(<Gates />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    fireEvent.click(screen.getByRole("button", { name: /approve/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByText(/recorded in the audit log/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(4900);
    });
    expect(screen.getByText(/recorded in the audit log/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(200);
    });
    expect(screen.queryByText(/recorded in the audit log/i)).not.toBeInTheDocument();
  } finally {
    vi.useRealTimers();
  }
});

test("an error toast stays visible after a later success toast", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Confirm XSS" })]))
    .mockResolvedValueOnce(json({ error: "boom" }, 500))
    .mockResolvedValueOnce(json({ ok: true }));
  const { container } = render(<Gates />);
  await screen.findByText("Confirm SSRF");
  fireEvent.click(screen.getAllByRole("button", { name: /approve/i })[0]);
  await waitFor(() => expect(assertive(container)).toHaveTextContent(/not recorded/i));
  fireEvent.click(screen.getAllByRole("button", { name: /approve/i })[1]);
  await waitFor(() => expect(polite(container)).toHaveTextContent(/recorded in the audit log/i));
  expect(assertive(container)).toHaveTextContent(/not recorded/i);
});

test("errors render in an always-mounted assertive alert region, successes in a polite one", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()]));
  const { container } = render(<Gates />);
  await screen.findByText("Confirm SSRF");
  expect(assertive(container)).toHaveAttribute("role", "alert");
  expect(assertive(container)).toBeEmptyDOMElement();
  expect(polite(container)).toBeEmptyDOMElement();
});

test("the toast stack is capped at 4, dropping the oldest", async () => {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()]));
  for (let i = 1; i <= 5; i++) spy.mockResolvedValueOnce(json({ error: `e${i}` }, 500));
  const { container } = render(<Gates />);
  await screen.findByText("Confirm SSRF");
  for (let i = 1; i <= 5; i++) {
    fireEvent.click(screen.getByRole("button", { name: /deny/i }));
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1 + i));
    await waitFor(() => expect(screen.getByRole("button", { name: /deny/i })).toBeEnabled());
  }
  await waitFor(() =>
    expect(within(assertive(container)).getAllByText(/not recorded/i)).toHaveLength(4),
  );
});

test("an onDecided that throws neither rejects unhandled nor hides the confirmation", async () => {
  const unhandled = vi.fn();
  process.on("unhandledRejection", unhandled);
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json([gate()]))
      .mockResolvedValueOnce(json({ ok: true }));
    const onDecided = vi.fn(() => {
      throw new Error("refresh failed for g1 http://lab/secret");
    });
    render(<Gates onDecided={onDecided} />);
    fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
    // The decision was recorded: the user is told so, and the view settles back.
    expect(await screen.findByText(/recorded in the audit log/i)).toBeInTheDocument();
    expect(onDecided).toHaveBeenCalledTimes(1);
    await new Promise((r) => setTimeout(r, 0)); // give a stray rejection time to surface
    expect(unhandled).not.toHaveBeenCalled();
    // Nothing is logged: the error text could carry gate or target data.
    expect(errors).not.toHaveBeenCalled();
  } finally {
    process.off("unhandledRejection", unhandled);
  }
});

test("unmounting mid-request and then resolving does not warn or throw", async () => {
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  let resolve!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
  const onDecided = vi.fn();
  const { unmount } = render(<Gates onDecided={onDecided} />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  unmount();
  resolve(json({ ok: true }));
  await new Promise((r) => setTimeout(r, 0));
  expect(errors).not.toHaveBeenCalled();
  // The decision was recorded even though the view is gone, so the app must still refresh
  // (bell, hero, audit log). Only the toast, which needs a mounted view, is skipped.
  expect(onDecided).toHaveBeenCalledTimes(1);
});

test("unmounting mid-request and then getting a 409 still tells the app, without warnings", async () => {
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  let resolve!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
  const onDecided = vi.fn();
  const { unmount } = render(<Gates onDecided={onDecided} />);
  fireEvent.click(await screen.findByRole("button", { name: /deny/i }));
  unmount();
  resolve(json({ error: "decided" }, 409));
  await new Promise((r) => setTimeout(r, 0));
  expect(errors).not.toHaveBeenCalled();
  expect(onDecided).toHaveBeenCalledTimes(1);
});

test("unmounting mid-request and then failing neither refreshes the app nor warns", async () => {
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  let resolve!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
  const onDecided = vi.fn();
  const { unmount } = render(<Gates onDecided={onDecided} />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  unmount();
  resolve(json({ error: "boom" }, 500));
  await new Promise((r) => setTimeout(r, 0));
  expect(errors).not.toHaveBeenCalled();
  expect(onDecided).not.toHaveBeenCalled(); // nothing was recorded
});

test("a gate decided in a view that was then unmounted stays hidden when the list comes back", async () => {
  let resolve!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)))
    .mockResolvedValue(json([gate()])); // a stale server view
  const first = render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  first.unmount();
  resolve(json({ ok: true }));
  await new Promise((r) => setTimeout(r, 0));
  render(<Gates version={1} />);
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
  expect(screen.queryByText("Confirm SSRF")).not.toBeInTheDocument();
});

test("toast timers are cleared on unmount", async () => {
  vi.useFakeTimers();
  try {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json([gate()]))
      .mockResolvedValueOnce(json({ ok: true }));
    const { unmount } = render(<Gates />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    fireEvent.click(screen.getByRole("button", { name: /approve/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(vi.getTimerCount()).toBeGreaterThan(0);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

test("Retry re-fetches the gates after a load failure", async () => {
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json({}, 500))
    .mockResolvedValueOnce(json([gate()]));
  render(<Gates />);
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not load/i);
  fireEvent.click(screen.getByRole("button", { name: /retry/i }));
  expect(await screen.findByText("Confirm SSRF")).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(2);
});

test("409 shows a neutral info icon, not the success check", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ error: "decided" }, 409));
  const { container } = render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  await waitFor(() => expect(polite(container)).toHaveTextContent(/already decided/i));
  const ic = polite(container).querySelector(".ic") as HTMLElement;
  expect(ic).toHaveTextContent("i");
  expect(ic).not.toHaveTextContent("✓");
});

test("a success decision still shows the check icon", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ ok: true }));
  const { container } = render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  await waitFor(() => expect(polite(container)).toHaveTextContent(/recorded in the audit log/i));
  expect(polite(container).querySelector(".ic")).toHaveTextContent("✓");
});

test("two synchronous Approve clicks send exactly one POST", async () => {
  let resolve!: (r: Response) => void;
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
  render(<Gates />);
  const approve = await screen.findByRole("button", { name: /approve/i });
  act(() => {
    approve.click();
    approve.click(); // before React re-renders the disabled state
  });
  expect(spy).toHaveBeenCalledTimes(2); // 1 GET + 1 POST
  resolve(json({ ok: true }));
  expect(await screen.findByText(/No actions awaiting approval/i)).toBeInTheDocument();
});

test("onDecided is still called after approve and after a 409", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Confirm XSS" })]))
    .mockResolvedValueOnce(json({ ok: true }))
    .mockResolvedValueOnce(json({ error: "decided" }, 409));
  const onDecided = vi.fn();
  render(<Gates onDecided={onDecided} />);
  await screen.findByText("Confirm SSRF");
  fireEvent.click(screen.getAllByRole("button", { name: /approve/i })[0]);
  await waitFor(() => expect(onDecided).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole("button", { name: /approve/i }));
  await waitFor(() => expect(onDecided).toHaveBeenCalledTimes(2));
});

test("a detect-only gate shows the badge, expected evidence and failure note alongside Approve/Deny", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json([gate({ detect_only: true, expected_evidence: "ev", why_it_might_fail: "wf" })]),
  );
  render(<Gates />);
  expect(await screen.findByText("DETECT-ONLY")).toBeInTheDocument();
  expect(screen.getByText("Expected evidence:")).toBeInTheDocument();
  expect(screen.getByText("ev")).toBeInTheDocument();
  expect(screen.getByText("Why it might fail:")).toBeInTheDocument();
  expect(screen.getByText("wf")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /approve/i })).toBeEnabled();
  expect(screen.getByRole("button", { name: /deny/i })).toBeEnabled();
});

test("the consent sentence stays under every Approve button", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Two" })]));
  render(<Gates />);
  await screen.findByText("Confirm SSRF");
  expect(
    screen.getAllByText("Every decision is written to the audit log. Approving records consent; it does not run the command."),
  ).toHaveLength(2);
});

test("the busy button shows a spinner and keeps its label", async () => {
  let resolve!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockReturnValueOnce(new Promise<Response>((r) => (resolve = r)));
  render(<Gates />);
  const approve = await screen.findByRole("button", { name: "Approve" });
  fireEvent.click(approve);
  await waitFor(() => expect(approve).toBeDisabled());
  expect(approve.querySelector(".spinner")).not.toBeNull();
  expect(screen.getByRole("button", { name: "Deny" }).querySelector(".spinner")).toBeNull();
  resolve(json({ ok: true }));
  await screen.findByText(/No actions awaiting approval/i);
});

test("the toast dismiss button removes the toast at once", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ ok: true }));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  expect(await screen.findByText(/recorded in the audit log/i)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
  expect(screen.queryByText(/recorded in the audit log/i)).not.toBeInTheDocument();
});

test("a new version refetches the list and keeps the cards and toasts on screen meanwhile", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Confirm XSS" })]))
    .mockResolvedValueOnce(json({ ok: true }))
    .mockResolvedValueOnce(json([gate({ id: "g2", title: "Confirm XSS" }), gate({ id: "g3", title: "Confirm CSRF" })]));
  const { rerender } = render(<Gates version={0} />);
  await screen.findByText("Confirm SSRF");
  fireEvent.click(screen.getAllByRole("button", { name: /approve/i })[0]);
  await screen.findByText(/recorded in the audit log/i);
  rerender(<Gates version={1} />);
  // No loading flash: the toast and the remaining card are still there.
  expect(screen.getByText(/recorded in the audit log/i)).toBeInTheDocument();
  expect(screen.getByText("Confirm XSS")).toBeInTheDocument();
  expect(await screen.findByText("Confirm CSRF")).toBeInTheDocument();
  expect(screen.queryByText("Confirm SSRF")).not.toBeInTheDocument();
  expect(screen.getByText(/recorded in the audit log/i)).toBeInTheDocument();
});

test("a decided gate stays hidden even if a slow refetch still lists it", async () => {
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ ok: true }))
    // stale server view: still lists the decided gate, plus a new one that proves the payload landed
    .mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Confirm XSS" })]));
  const { rerender } = render(<Gates version={0} />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  await screen.findByText(/No actions awaiting approval/i);
  rerender(<Gates version={1} />);
  expect(await screen.findByText("Confirm XSS")).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(3);
  expect(screen.queryByText("Confirm SSRF")).not.toBeInTheDocument();
});

test("a gate without detect-only metadata renders no badge and neither line", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()]));
  render(<Gates />);
  await screen.findByText("Confirm SSRF");
  expect(screen.queryByText("DETECT-ONLY")).not.toBeInTheDocument();
  expect(screen.queryByText(/Expected evidence/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/Why it might fail/i)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /approve/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /deny/i })).toBeInTheDocument();
});

// ---- compact variant (Overview "Approval required" card) ----

test("compact: a list card titled 'Approval required' with a pending count and See all", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Two" })]));
  const onSeeAll = vi.fn();
  render(<Gates variant="compact" onSeeAll={onSeeAll} />);
  expect(await screen.findByRole("heading", { level: 2, name: "Approval required" })).toBeInTheDocument();
  expect(screen.getByText("2 pending")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "See all approval gates" }));
  expect(onSeeAll).toHaveBeenCalledTimes(1);
});

test("compact: no See all control when nothing can navigate", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()]));
  render(<Gates variant="compact" />);
  await screen.findByText("Confirm SSRF");
  expect(screen.queryByRole("button", { name: /see all/i })).toBeNull();
});

test("compact: evidence and failure notes sit in a <details>, the command and consent note stay visible", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json([gate({ detect_only: true, expected_evidence: "ev", why_it_might_fail: "wf", command: "nuclei -u x" })]),
  );
  render(<Gates variant="compact" />);
  await screen.findByText("Confirm SSRF");
  const details = screen.getByText("More context").closest("details") as HTMLElement;
  expect(details).not.toBeNull();
  expect(details).toContainElement(screen.getByText("Expected evidence:"));
  expect(details).toContainElement(screen.getByText("Why it might fail:"));
  expect(details).toHaveClass("gdetails");
  // Consent needs the full command and the sentence, outside the fold.
  expect(details).not.toContainElement(screen.getByText("nuclei -u x"));
  const note = screen.getByText(
    "Every decision is written to the audit log. Approving records consent; it does not run the command.",
  );
  expect(details).not.toContainElement(note);
  expect(screen.getByText("DETECT-ONLY")).toBeInTheDocument();
});

test("compact: a gate with no evidence metadata has no 'More context' fold", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()]));
  render(<Gates variant="compact" />);
  await screen.findByText("Confirm SSRF");
  expect(screen.queryByText("More context")).toBeNull();
});

test("the page variant shows the evidence inline, not in a <details>", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate({ expected_evidence: "ev" })]));
  const { container } = render(<Gates />);
  await screen.findByText("ev");
  expect(container.querySelector("details")).toBeNull();
});

test("compact: shows the first 3 gates and links to the rest", async () => {
  const gates = ["a", "b", "c", "d", "e"].map((id) => gate({ id, title: `Gate ${id}` }));
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(gates));
  const onSeeAll = vi.fn();
  render(<Gates variant="compact" onSeeAll={onSeeAll} />);
  await screen.findByText("Gate a");
  expect(screen.getByText("5 pending")).toBeInTheDocument();
  expect(screen.getByText("Gate c")).toBeInTheDocument();
  expect(screen.queryByText("Gate d")).toBeNull();
  expect(screen.getAllByRole("button", { name: "Approve" })).toHaveLength(3);
  fireEvent.click(screen.getByRole("button", { name: "2 more in Approval gates" }));
  expect(onSeeAll).toHaveBeenCalledTimes(1);
});

test("compact: approving a visible gate pulls the next one into view and calls onDecided", async () => {
  const gates = ["a", "b", "c", "d"].map((id) => gate({ id, title: `Gate ${id}` }));
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(gates)).mockResolvedValueOnce(json({ ok: true }));
  const onDecided = vi.fn();
  render(<Gates variant="compact" onDecided={onDecided} />);
  await screen.findByText("Gate a");
  expect(screen.queryByText("Gate d")).toBeNull();
  fireEvent.click(screen.getAllByRole("button", { name: "Approve" })[0]);
  expect(await screen.findByText("Gate d")).toBeInTheDocument();
  expect(onDecided).toHaveBeenCalledTimes(1);
  expect(screen.queryByText("Gate a")).toBeNull();
});

test("compact: empty state and a Retry on failure", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({}, 500)).mockResolvedValueOnce(json([]));
  render(<Gates variant="compact" />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not load approval gates");
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("No actions awaiting approval")).toBeInTheDocument();
  expect(screen.getByText("0 pending")).toBeInTheDocument();
});

test("compact: loading is announced as a status", () => {
  vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise<Response>(() => {}));
  render(<Gates variant="compact" />);
  expect(screen.getByRole("status")).toHaveTextContent("Loading approval gates…");
});

test("empty or non-true detect-only metadata renders nothing; HTML in it stays literal", async () => {
  const html = "<img src=x onerror=alert(1)>";
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json([gate({ detect_only: false, expected_evidence: "", why_it_might_fail: html })]),
  );
  const { container } = render(<Gates />);
  expect(await screen.findByText(html)).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.queryByText("DETECT-ONLY")).not.toBeInTheDocument();
  expect(screen.queryByText(/Expected evidence/i)).not.toBeInTheDocument();
});

// ---- page variant: intro strip, grid, empty / loading / error (spec 3.4) ----

const CONSENT =
  "Every decision is written to the audit log. Approving records consent; it does not run the command.";

test("page: an intro strip with the Approval required heading, the pending count and the detect-only line", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Two" })]));
  const { container } = render(<Gates />);
  const heading = await screen.findByRole("heading", { level: 2, name: "Approval required" });
  const strip = heading.closest("section") as HTMLElement;
  expect(strip).toHaveClass("intro-strip");
  expect(within(strip).getByText("2 pending")).toHaveClass("count");
  expect(
    within(strip).getByText(
      "Detect-only verification gates. Approving records your consent in the hash-chained audit log. It never runs anything from this console.",
    ),
  ).toBeInTheDocument();
  expect(strip.querySelector(".ibadge")).not.toBeNull();
  // The strip is the only "Approval required" heading, and it carries no legacy glass wrapper.
  expect(screen.getAllByRole("heading", { name: "Approval required" })).toHaveLength(1);
  expect(container.querySelector(".glass")).toBeNull();
});

test("page: the gates sit in a grid, one full card each, with the consent sentence under every Approve", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json([gate(), gate({ id: "g2", title: "Two" }), gate({ id: "g3", title: "Three" })]),
  );
  const { container } = render(<Gates />);
  await screen.findByText("Confirm SSRF");
  const grid = container.querySelector(".gate-grid") as HTMLElement;
  expect(grid).not.toBeNull();
  expect(grid.querySelectorAll("article.gcard")).toHaveLength(3);
  expect(within(grid).getAllByRole("button", { name: "Approve" })).toHaveLength(3);
  expect(within(grid).getAllByText(CONSENT)).toHaveLength(3);
  for (const card of grid.querySelectorAll("article.gcard")) {
    expect(card.querySelector("details")).toBeNull();
  }
});

test("page: the pending count follows the decisions", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate(), gate({ id: "g2", title: "Two" })]))
    .mockResolvedValueOnce(json({ ok: true }));
  render(<Gates />);
  await screen.findByText("2 pending");
  fireEvent.click(screen.getAllByRole("button", { name: "Approve" })[0]);
  expect(await screen.findByText("1 pending")).toBeInTheDocument();
});

test("page: the empty state is a resting watchdog (180px), the title and a hint, no grid", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([]));
  const { container } = render(<Gates />);
  expect(await screen.findByText("No actions awaiting approval")).toBeInTheDocument();
  expect(screen.getByText("When triage proposes a verification step, it waits here for you.")).toBeInTheDocument();
  expect((container.querySelector(".empty-state .mascot") as HTMLElement).style.width).toBe("180px");
  expect(container.querySelector(".gate-grid")).toBeNull();
  expect(screen.getByText("0 pending")).toBeInTheDocument();
});

test("page: loading shows two skeleton gate cards and a status caption", () => {
  vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise<Response>(() => {}));
  const { container } = render(<Gates />);
  expect(screen.getByRole("status")).toHaveTextContent("Loading approval gates…");
  expect(container.querySelectorAll(".gate-grid > .card")).toHaveLength(2);
  expect(container.querySelector(".panel, .glass")).toBeNull();
});

test("page: a load failure is one alert with the fixed copy and a Retry", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({ error: "<b>detail</b>" }, 500));
  render(<Gates />);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Could not load approval gates");
  expect(alert).toHaveTextContent("check that the Ascent backend is running");
  expect(alert).not.toHaveTextContent("detail");
  expect(within(alert).getByRole("button", { name: "Retry" })).toBeInTheDocument();
});

test("page: a toast can be dismissed", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()])).mockResolvedValueOnce(json({ error: "decided" }, 409));
  render(<Gates />);
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  expect(await screen.findByText("Already decided")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
  expect(screen.queryByText("Already decided")).not.toBeInTheDocument();
});

// ---- compact: consent note, toasts, shared load/error cards ----

test("compact: the consent sentence stays under every Approve button", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json([gate(), gate({ id: "g2", title: "Two" }), gate({ id: "g3", title: "Three" })]),
  );
  render(<Gates variant="compact" />);
  await screen.findByText("Confirm SSRF");
  expect(screen.getAllByRole("button", { name: "Approve" })).toHaveLength(3);
  expect(screen.getAllByText(CONSENT)).toHaveLength(3);
});

test("compact: a decision toast can be dismissed", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json([gate()])).mockResolvedValueOnce(json({ ok: true }));
  render(<Gates variant="compact" />);
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  expect(await screen.findByText(/recorded in the audit log/i)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
  expect(screen.queryByText(/recorded in the audit log/i)).not.toBeInTheDocument();
});

test("compact: loading and failure are the shared skeleton and error cards", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({}, 500));
  const { container } = render(<Gates variant="compact" />);
  expect(screen.getByRole("status")).toHaveTextContent("Loading approval gates…");
  expect(container.querySelectorAll(".skeleton").length).toBeGreaterThanOrEqual(3);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Could not load approval gates");
  expect(alert).toHaveTextContent("check that the Ascent backend is running");
  expect(screen.getAllByRole("alert")).toHaveLength(1);
});

// ---- decided ids: pruned when the server stops listing them ----

test("a decided id is forgotten once a newer payload no longer lists it, so a real pending gate with that id shows", async () => {
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json([gate()]))
    .mockResolvedValueOnce(json({ ok: true }))
    // the server has recorded the decision (g1 is gone); g2 proves this payload landed
    .mockResolvedValueOnce(json([gate({ id: "g2", title: "Confirm XSS" })]))
    // later: a new gate that reuses the id g1
    .mockResolvedValueOnce(json([gate({ title: "Confirm SSRF again" }), gate({ id: "g2", title: "Confirm XSS" })]));
  const { rerender } = render(<Gates version={0} />);
  fireEvent.click(await screen.findByRole("button", { name: /approve/i }));
  await screen.findByText(/No actions awaiting approval/i);
  rerender(<Gates version={1} />);
  expect(await screen.findByText("Confirm XSS")).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(3);
  expect(screen.queryByText("Confirm SSRF")).not.toBeInTheDocument();
  rerender(<Gates version={2} />);
  expect(await screen.findByText("Confirm SSRF again")).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Approve" })).toHaveLength(2);
  for (const b of screen.getAllByRole("button", { name: "Approve" })) expect(b).toBeEnabled();
});
