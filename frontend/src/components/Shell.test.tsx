import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, test, vi } from "vitest";
import { Shell } from "./Shell";
import type { NavId } from "./Shell";

// navigator.clipboard is replaced per test and put back afterwards, so no test sees another's stub.
const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
function stubClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  if (originalClipboard) Object.defineProperty(navigator, "clipboard", originalClipboard);
  else delete (navigator as { clipboard?: unknown }).clipboard;
});

test("renders brand and nav", () => {
  render(
    <Shell>
      <div>content</div>
    </Shell>,
  );
  expect(screen.getByText("content")).toBeInTheDocument();
  expect(screen.getByLabelText("Findings")).toBeInTheDocument();
});

test("has a real search and icon buttons, and no inert placeholders", () => {
  render(<Shell />);
  expect(screen.getByRole("searchbox", { name: "Search findings" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Refresh data" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Pending approvals/ })).toBeInTheDocument();
  expect(screen.queryByLabelText("Settings")).not.toBeInTheDocument();
  expect(screen.queryByText("DL")).not.toBeInTheDocument();
});

test("keeps the six working nav buttons plus refresh and the bell", () => {
  render(<Shell />);
  for (const name of ["Overview", "New scan", "Findings", "Approval gates", "Report", "Audit"]) {
    expect(screen.getByRole("button", { name })).toBeInTheDocument();
  }
  // 6 nav + Refresh data + Pending approvals; the policy mini-card is absent without a policy prop.
  expect(screen.getAllByRole("button")).toHaveLength(8);
});

test("status dot is neutral when no engagement is loaded", () => {
  const { container } = render(<Shell />);
  expect(screen.getByText(/no engagement loaded/)).toBeInTheDocument();
  expect(container.querySelector(".dot")).toHaveClass("idle");
});

test("status dot is not idle once an engagement is loaded", () => {
  const { container } = render(<Shell status="engagement: x" />);
  expect(screen.getByText(/engagement: x/)).toBeInTheDocument();
  expect(container.querySelector(".dot")).not.toHaveClass("idle");
});

test("the status chip carries the full string in a plain-text title", () => {
  const { container } = render(<Shell status="engagement: <b>x</b>" />);
  expect(container.querySelector(".sb-chip")).toHaveAttribute("title", "engagement: <b>x</b>");
  expect(container.querySelector("b")).toBeNull();
});

test("shows a visible Ascent Console h1 whose prefix alone is visually hidden", () => {
  render(<Shell />);
  const h1 = screen.getByRole("heading", { level: 1, name: /Ascent Console/ });
  expect(h1).toHaveAccessibleName("Ascent Console: Overview");
  expect(h1).not.toHaveClass("sr-only");
  expect(within(h1).getByText("Ascent Console:")).toHaveClass("sr-only");
  expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
});

test("the page title follows the active screen unless a title is given", () => {
  const { rerender } = render(<Shell active="audit" />);
  expect(screen.getByRole("heading", { level: 1 })).toHaveAccessibleName("Ascent Console: Audit log");
  rerender(<Shell active="gates" />);
  expect(screen.getByRole("heading", { level: 1 })).toHaveAccessibleName("Ascent Console: Approval gates");
  rerender(<Shell active="gates" title="Custom" />);
  expect(screen.getByRole("heading", { level: 1 })).toHaveAccessibleName("Ascent Console: Custom");
});

test("landmarks: skip link first, labelled nav, header, main, search form", () => {
  const { container } = render(
    <Shell>
      <p>body</p>
    </Shell>,
  );
  const skip = screen.getByRole("link", { name: "Skip to content" });
  expect(skip).toHaveAttribute("href", "#main");
  // First focusable element in the document.
  expect(container.querySelector("a, button, input")).toBe(skip);
  const main = screen.getByRole("main");
  expect(main).toHaveAttribute("id", "main");
  expect(main).toHaveAttribute("tabindex", "-1");
  expect(within(main).getByText("body")).toBeInTheDocument();
  expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
  expect(screen.getByRole("banner")).toBeInTheDocument();
  expect(screen.getByRole("search")).toBeInTheDocument();
});

test("the avatar is decorative CSS art, never an img", () => {
  const { container } = render(<Shell />);
  expect(container.querySelector("img")).toBeNull();
  const avatar = container.querySelector(".avatar");
  expect(avatar).not.toBeNull();
  expect(avatar).toHaveAttribute("aria-hidden", "true");
  expect(avatar).toHaveClass("mascot", "mascot--avatar");
});

test("nav buttons mark the active screen and call onNavigate", () => {
  const onNavigate = vi.fn();
  render(<Shell active="findings" onNavigate={onNavigate} />);
  expect(screen.getByRole("button", { name: "Findings" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("button", { name: "Overview" })).not.toHaveAttribute("aria-current");
  fireEvent.click(screen.getByRole("button", { name: "Report" }));
  expect(onNavigate).toHaveBeenCalledWith("report");
});

test("nav buttons keep their full accessible name beside the short mobile label", () => {
  render(<Shell />);
  const gates = screen.getByRole("button", { name: "Approval gates" });
  expect(gates.querySelector(".nav-label")).toHaveTextContent("Approval gates");
  expect(gates.querySelector(".nav-short")).toHaveTextContent("Gates");
  expect(gates.querySelector(".nav-short")).toHaveAttribute("aria-hidden", "true");
});

test("pending approvals: a nav badge and a bell badge, with the count on the bell's name", () => {
  const { container } = render(<Shell pendingGates={3} />);
  const gates = screen.getByRole("button", { name: "Approval gates" });
  expect(gates.querySelector(".nav-badge")).toHaveTextContent("3");
  expect(gates.querySelector(".nav-badge")).toHaveAttribute("aria-hidden", "true");
  const bell = screen.getByRole("button", { name: "Pending approvals: 3" });
  expect(bell.querySelector(".icon-btn-badge")).toHaveTextContent("3");
  expect(bell.querySelector(".icon-btn-badge")).toHaveAttribute("aria-hidden", "true");
  expect(container.querySelectorAll(".nav-badge")).toHaveLength(1);
});

test("the nav badge is capped at 99+ like the bell's, while the bell name keeps the true count", () => {
  const { container } = render(<Shell pendingGates={150} />);
  expect(container.querySelector(".nav-badge")).toHaveTextContent("99+");
  expect(container.querySelector(".icon-btn-badge")).toHaveTextContent("99+");
  expect(screen.getByRole("button", { name: "Pending approvals: 150" })).toBeInTheDocument();
  const { container: c2 } = render(<Shell pendingGates={99} />);
  expect(c2.querySelector(".nav-badge")).toHaveTextContent("99");
  expect(c2.querySelector(".nav-badge")).not.toHaveTextContent("99+");
});

test("zero pending approvals shows no badge but still names the count", () => {
  const { container } = render(<Shell pendingGates={0} />);
  expect(screen.getByRole("button", { name: "Pending approvals: 0" })).toBeInTheDocument();
  expect(container.querySelector(".nav-badge")).toBeNull();
  expect(container.querySelector(".icon-btn-badge")).toBeNull();
});

test("an unknown pending count shows no badge and a count-free name", () => {
  const { container } = render(<Shell />);
  expect(screen.getByRole("button", { name: "Pending approvals" })).toBeInTheDocument();
  expect(container.querySelector(".nav-badge")).toBeNull();
  expect(container.querySelector(".icon-btn-badge")).toBeNull();
});

test("the bell navigates to Approval gates", () => {
  const onNavigate = vi.fn();
  render(<Shell pendingGates={2} onNavigate={onNavigate} />);
  fireEvent.click(screen.getByRole("button", { name: "Pending approvals: 2" }));
  expect(onNavigate).toHaveBeenCalledWith("gates");
});

test("refresh calls onRefresh and shows busy while data is refetching", () => {
  const onRefresh = vi.fn();
  const { rerender } = render(<Shell onRefresh={onRefresh} />);
  const btn = screen.getByRole("button", { name: "Refresh data" });
  expect(btn).not.toHaveAttribute("aria-busy");
  fireEvent.click(btn);
  expect(onRefresh).toHaveBeenCalledTimes(1);
  rerender(<Shell onRefresh={onRefresh} refreshing />);
  expect(screen.getByRole("button", { name: "Refresh data" })).toHaveAttribute("aria-busy", "true");
});

test("typing reports the query; Enter submits; Escape clears and keeps focus", () => {
  const onQueryChange = vi.fn();
  const onSearchSubmit = vi.fn();
  render(<Shell query="ssrf" onQueryChange={onQueryChange} onSearchSubmit={onSearchSubmit} />);
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  expect(box).toHaveValue("ssrf");
  fireEvent.change(box, { target: { value: "ssrf x" } });
  expect(onQueryChange).toHaveBeenLastCalledWith("ssrf x");
  fireEvent.submit(screen.getByRole("search"));
  expect(onSearchSubmit).toHaveBeenCalledTimes(1);
  act(() => box.focus());
  fireEvent.keyDown(box, { key: "Escape" });
  expect(onQueryChange).toHaveBeenLastCalledWith("");
  expect(box).toHaveFocus();
});

test("a bare Shell still lets you type in the search box", () => {
  render(<Shell />);
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  fireEvent.change(box, { target: { value: "abc" } });
  expect(box).toHaveValue("abc");
  fireEvent.keyDown(box, { key: "Escape" });
  expect(box).toHaveValue("");
});

test("the / key focuses search unless focus is already in a field", () => {
  render(
    <Shell>
      <input aria-label="other" />
    </Shell>,
  );
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  fireEvent.keyDown(document.body, { key: "/" });
  expect(box).toHaveFocus();
  act(() => box.blur());
  const other = screen.getByLabelText("other");
  act(() => other.focus());
  fireEvent.keyDown(other, { key: "/" });
  expect(other).toHaveFocus();
  // Modified keys are not a search shortcut.
  act(() => other.blur());
  fireEvent.keyDown(document.body, { key: "/", ctrlKey: true });
  expect(box).not.toHaveFocus();
});

test("the / key leaves a keystroke another handler already took", () => {
  render(<Shell />);
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  const claim = (e: Event) => e.preventDefault();
  document.addEventListener("keydown", claim, true); // runs first (capture), like a widget's own shortcut
  try {
    fireEvent.keyDown(document.body, { key: "/", cancelable: true });
    expect(box).not.toHaveFocus();
  } finally {
    document.removeEventListener("keydown", claim, true);
  }
  fireEvent.keyDown(document.body, { key: "/", cancelable: true });
  expect(box).toHaveFocus();
});

test("on screens that cannot filter live, focusing search explains Enter", () => {
  const { rerender } = render(<Shell active="audit" />);
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  expect(screen.queryByText("Press Enter to search findings")).not.toBeInTheDocument();
  fireEvent.focus(box);
  expect(screen.getByText("Press Enter to search findings")).toBeInTheDocument();
  expect(screen.getByText("Press Enter to search findings").closest('[role="status"]')).not.toBeNull();
  fireEvent.blur(box);
  expect(screen.queryByText("Press Enter to search findings")).not.toBeInTheDocument();
  // Findings and Overview filter live, so no hint there.
  for (const active of ["findings", "overview"] as const) {
    rerender(<Shell active={active} />);
    fireEvent.focus(screen.getByRole("searchbox", { name: "Search findings" }));
    expect(screen.queryByText("Press Enter to search findings")).not.toBeInTheDocument();
  }
});

test("the policy mini-card is absent until a verdict state is known", () => {
  render(<Shell />);
  expect(screen.queryByText("Policy gate")).not.toBeInTheDocument();
});

test("a policy verdict shows its pill, exit code and policy name", () => {
  render(<Shell policy={{ decision: "FAIL", exit_code: 1, policy: "ci" }} />);
  expect(screen.getByRole("heading", { level: 2, name: "Policy gate" })).toBeInTheDocument();
  expect(screen.getByText("FAIL")).toHaveClass("vpill");
  expect(screen.getByText("exit 1 · ci")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "View verdict" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Policy gate: FAIL" })).toBeInTheDocument();
});

test("View verdict goes to Overview and focuses the policy card heading", () => {
  vi.useFakeTimers();
  const onNavigate = vi.fn();
  render(
    <Shell policy={{ decision: "PASS", exit_code: 0, policy: "ci" }} onNavigate={onNavigate} active="audit">
      <h2 id="policy-gate-title" tabIndex={-1}>
        Policy gate
      </h2>
    </Shell>,
  );
  const target = document.getElementById("policy-gate-title")!;
  target.scrollIntoView = vi.fn();
  fireEvent.click(screen.getByRole("button", { name: "View verdict" }));
  expect(onNavigate).toHaveBeenCalledWith("overview");
  expect(target).toHaveFocus();
  expect(target.scrollIntoView).toHaveBeenCalledTimes(1);
});

test("a screen change moves focus to the page title; the first render does not", () => {
  const { rerender } = render(<Shell active="overview" />);
  const h1 = screen.getByRole("heading", { level: 1 });
  expect(h1).toHaveAttribute("tabindex", "-1");
  expect(h1).not.toHaveFocus();
  rerender(<Shell active="findings" />);
  expect(screen.getByRole("heading", { level: 1 })).toHaveFocus();
  // A re-render on the same screen leaves focus wherever the user put it.
  const box = screen.getByRole("searchbox", { name: "Search findings" });
  act(() => box.focus());
  rerender(<Shell active="findings" status="engagement: lab" />);
  expect(box).toHaveFocus();
});

test("View verdict from another screen lands on the policy card heading, not the page title", () => {
  // The screen change and the verdict request commit together; the verdict focus must win.
  function Harness() {
    const [active, setActive] = useState<NavId>("audit");
    return (
      <Shell policy={{ decision: "PASS", exit_code: 0, policy: "ci" }} active={active} onNavigate={setActive}>
        {active === "overview" ? (
          <h2 id="policy-gate-title" tabIndex={-1}>
            Policy gate
          </h2>
        ) : null}
      </Shell>
    );
  }
  render(<Harness />);
  fireEvent.click(screen.getByRole("button", { name: "View verdict" }));
  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Overview");
  expect(document.getElementById("policy-gate-title")).toHaveFocus();
});

test("View verdict waits for the card to render before focusing it", () => {
  vi.useFakeTimers();
  const { rerender } = render(<Shell policy={{ decision: "PASS", exit_code: 0, policy: "ci" }} active="audit" />);
  fireEvent.click(screen.getByRole("button", { name: "View verdict" }));
  rerender(
    <Shell policy={{ decision: "PASS", exit_code: 0, policy: "ci" }} active="overview">
      <h2 id="policy-gate-title" tabIndex={-1}>
        Policy gate
      </h2>
    </Shell>,
  );
  act(() => {
    vi.advanceTimersByTime(100);
  });
  expect(document.getElementById("policy-gate-title")).toHaveFocus();
});

test("no verdict yet: explains --policy and copies the flag", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  stubClipboard(writeText);
  vi.useFakeTimers();
  render(<Shell policy={null} />);
  expect(screen.getByText("No verdict yet")).toBeInTheDocument();
  expect(screen.getByText(/Add --policy to/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Policy gate: not evaluated" })).toBeInTheDocument();
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Copy --policy flag" }));
  });
  expect(writeText).toHaveBeenCalledWith("--policy ascent-policy.yaml");
  expect(screen.getByRole("button", { name: "Copied" })).toBeInTheDocument();
  act(() => {
    vi.advanceTimersByTime(1500);
  });
  expect(screen.getByRole("button", { name: "Copy --policy flag" })).toBeInTheDocument();
});

test("copying announces 'Copied' in one polite status region, from the card or the rail button", async () => {
  stubClipboard(vi.fn().mockResolvedValue(undefined));
  vi.useFakeTimers();
  render(<Shell policy={null} />);
  const live = document.querySelector(".sb-card-live") as HTMLElement;
  expect(live).toHaveAttribute("role", "status");
  expect(live).toHaveClass("sr-only");
  expect(live).toBeEmptyDOMElement(); // always mounted, so the later text is announced
  // The desktop card button...
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Copy --policy flag" }));
  });
  expect(live).toHaveTextContent("Copied --policy flag to the clipboard");
  act(() => {
    vi.advanceTimersByTime(1500);
  });
  expect(live).toBeEmptyDOMElement();
  // ...and the icon-rail button (whose accessible name never changes) announce the same thing.
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Policy gate: not evaluated" }));
  });
  expect(live).toHaveTextContent("Copied --policy flag to the clipboard");
  expect(document.querySelectorAll(".sb-card-live")).toHaveLength(1);
});

test("a clipboard failure announces nothing and leaves the label alone", async () => {
  stubClipboard(vi.fn().mockRejectedValue(new Error("denied")));
  const { container } = render(<Shell policy={null} />);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Policy gate: not evaluated" }));
  });
  expect(container.querySelector(".sb-card-live")).toBeEmptyDOMElement();
});

test("the live region is not drawn without a policy card", () => {
  const { container } = render(<Shell />);
  expect(container.querySelector(".sb-card-live")).toBeNull();
});

test("a clipboard failure leaves the copy label alone", async () => {
  const writeText = vi.fn().mockRejectedValue(new Error("denied"));
  stubClipboard(writeText);
  render(<Shell policy={null} />);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Copy --policy flag" }));
  });
  expect(screen.getByRole("button", { name: "Copy --policy flag" })).toBeInTheDocument();
});

test("policy text from the API renders as text and unknown decisions fail safe", () => {
  const { container } = render(
    <Shell policy={{ decision: "constructor" as never, exit_code: 2, policy: "<img src=x onerror=alert(1)>" }} />,
  );
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getByText("INCOMPLETE")).toHaveClass("vpill--inc");
  expect(screen.getByText("exit 2 · <img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(container.querySelector(".sb-card .ibadge")).toHaveClass("ibadge--bluegrey");
});

test("the policy badge tone follows the decision", () => {
  const tones: Array<["PASS" | "CONDITIONAL" | "FAIL" | "INCOMPLETE", string]> = [
    ["PASS", "ibadge--teal"],
    ["CONDITIONAL", "ibadge--sand"],
    ["FAIL", "ibadge--coral"],
    ["INCOMPLETE", "ibadge--bluegrey"],
  ];
  for (const [decision, cls] of tones) {
    const { container, unmount } = render(<Shell policy={{ decision, exit_code: 0, policy: "p" }} />);
    expect(container.querySelector(".sb-card .ibadge")).toHaveClass(cls);
    unmount();
  }
});
