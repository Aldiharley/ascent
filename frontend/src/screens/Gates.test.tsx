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
  expect(onDecided).not.toHaveBeenCalled();
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
