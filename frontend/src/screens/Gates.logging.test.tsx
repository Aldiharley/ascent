import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { Gates } from "./Gates";

// A notifier that throws stands in for "a bug inside the decision handler": it is the one step after
// the POST that is neither the API call (reported as an outcome) nor onDecided (guarded on its own).
vi.mock("../components/Toast", () => ({
  useToasts: () => ({
    toasts: [],
    notify: () => {
      throw new Error("toast failed for g1 http://lab/secret");
    },
    dismiss: () => {},
  }),
  ToastStack: () => null,
}));

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

afterEach(() => {
  vi.restoreAllMocks();
});

test("a bug in the decision handler is logged as one constant line, with no gate or target data", async () => {
  const errors = vi.spyOn(console, "error").mockImplementation(() => {});
  const unhandled = vi.fn();
  process.on("unhandledRejection", unhandled);
  try {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json([{ id: "g1", title: "Confirm SSRF", why: "w", command: "c", target: "/x", in_scope: true }]))
      .mockResolvedValueOnce(json({ ok: true }));
    render(<Gates />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(errors).toHaveBeenCalledTimes(1));
    expect(errors).toHaveBeenCalledWith("gate decision handler failed");
    // The decision itself was recorded before the bug hit: the gate is hidden as usual.
    await waitFor(() => expect(screen.queryByRole("button", { name: "Approve" })).toBeNull());
    await new Promise((r) => setTimeout(r, 0));
    expect(unhandled).not.toHaveBeenCalled();
    expect(JSON.stringify(errors.mock.calls)).not.toMatch(/secret|g1|Confirm/);
  } finally {
    process.off("unhandledRejection", unhandled);
  }
});
