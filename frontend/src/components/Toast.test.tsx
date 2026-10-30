import { act, fireEvent, render, renderHook, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { TOAST_MS, ToastStack, useToasts } from "./Toast";

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

function Harness() {
  const { toasts, notify, dismiss } = useToasts();
  return (
    <>
      <button type="button" onClick={() => notify({ kind: "ok", title: "Saved", detail: "d1" })}>
        ok
      </button>
      <button type="button" onClick={() => notify({ kind: "error", title: "Broke", detail: "d2" })}>
        err
      </button>
      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </>
  );
}

function fire(name: string) {
  fireEvent.click(screen.getByRole("button", { name }));
}

test("a toast shows its glyph, title and detail, with ok in the polite and errors in the assertive region", () => {
  const { container } = render(<Harness />);
  fire("ok");
  fire("err");
  const polite = container.querySelector('[aria-live="polite"]') as HTMLElement;
  const assertive = container.querySelector('[aria-live="assertive"]') as HTMLElement;
  expect(polite).toHaveTextContent("Saved");
  expect(polite.querySelector(".ic")).toHaveTextContent("✓");
  expect(assertive).toHaveTextContent("Broke");
  expect(assertive.querySelector(".ic")).toHaveTextContent("!");
  expect(polite).not.toHaveTextContent("Broke");
});

test("the dismiss button removes that toast immediately", () => {
  render(<Harness />);
  fire("ok");
  expect(screen.getByText("Saved")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
  expect(screen.queryByText("Saved")).not.toBeInTheDocument();
  expect(vi.getTimerCount()).toBe(0);
});

test("dismissing one toast leaves the others", () => {
  render(<Harness />);
  fire("ok");
  fire("err");
  const [first] = screen.getAllByRole("button", { name: "Dismiss notification" });
  fireEvent.click(first);
  expect(screen.getAllByRole("button", { name: "Dismiss notification" })).toHaveLength(1);
});

test("auto-dismisses after TOAST_MS", () => {
  render(<Harness />);
  fire("ok");
  act(() => {
    vi.advanceTimersByTime(TOAST_MS - 100);
  });
  expect(screen.getByText("Saved")).toBeInTheDocument();
  act(() => {
    vi.advanceTimersByTime(200);
  });
  expect(screen.queryByText("Saved")).not.toBeInTheDocument();
});

test("hovering pauses the timer, leaving resumes with the time that was left", () => {
  render(<Harness />);
  fire("ok");
  const toast = screen.getByText("Saved").closest(".toast") as HTMLElement;
  act(() => {
    vi.advanceTimersByTime(3000);
  });
  fireEvent.mouseEnter(toast);
  act(() => {
    vi.advanceTimersByTime(60_000);
  });
  expect(screen.getByText("Saved")).toBeInTheDocument();
  expect(vi.getTimerCount()).toBe(0);
  fireEvent.mouseLeave(toast);
  act(() => {
    vi.advanceTimersByTime(1900);
  });
  expect(screen.getByText("Saved")).toBeInTheDocument();
  act(() => {
    vi.advanceTimersByTime(200);
  });
  expect(screen.queryByText("Saved")).not.toBeInTheDocument();
});

test("keyboard focus inside a toast pauses it too", () => {
  render(<Harness />);
  fire("ok");
  const x = screen.getByRole("button", { name: "Dismiss notification" });
  fireEvent.focus(x);
  act(() => {
    vi.advanceTimersByTime(30_000);
  });
  expect(screen.getByText("Saved")).toBeInTheDocument();
  fireEvent.blur(x);
  act(() => {
    vi.advanceTimersByTime(TOAST_MS + 10);
  });
  expect(screen.queryByText("Saved")).not.toBeInTheDocument();
});

test("the stack is capped at 4, dropping the oldest", () => {
  const { result } = renderHook(() => useToasts());
  act(() => {
    for (let i = 0; i < 6; i++) result.current.notify({ kind: "info", title: `t${i}`, detail: "" });
  });
  expect(result.current.toasts.map((t) => t.title)).toEqual(["t2", "t3", "t4", "t5"]);
});

test("unmounting clears every toast timer", () => {
  const { unmount } = render(<Harness />);
  fire("ok");
  fire("err");
  expect(vi.getTimerCount()).toBeGreaterThan(0);
  unmount();
  expect(vi.getTimerCount()).toBe(0);
});

test("toast text is rendered as text, not markup", () => {
  const { result } = renderHook(() => useToasts());
  act(() => result.current.notify({ kind: "ok", title: "<b>x</b>", detail: "<img src=x>" }));
  const { container } = render(<ToastStack toasts={result.current.toasts} onDismiss={() => undefined} />);
  expect(container.querySelector(".m b")?.textContent).toBe("<b>x</b>");
  expect(container.querySelector("img")).toBeNull();
});
