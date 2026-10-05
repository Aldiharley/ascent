import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  expect(await screen.findByRole("alert")).toHaveTextContent(/not recorded/i);
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
  expect(await screen.findByRole("alert")).toBeInTheDocument();
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
