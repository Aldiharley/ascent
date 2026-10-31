import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { NewScan } from "./NewScan";

// navigator.clipboard is replaced per test and put back afterwards, so no test sees another's stub.
const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
function stubClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
}

// The hint under the select for the Active profile: backend's standard profile excludes the
// `intrusive` templates, active keeps them (and adds parameter fuzzing), so the warning says so.
// A live active run took a Juice Shop lab container down, so it also warns about that.
const ACTIVE_HINT =
  "Adds intrusive templates and parameter fuzzing — may change application state or take the target down. Use only on a lab or staging target.";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function created(over: Record<string, unknown> = {}) {
  return {
    ok: true,
    name: "Acme",
    path: "engagements/acme.yaml",
    scope: { hosts: ["example.com"], cidrs: ["10.0.0.0/24"], urls: ["http://localhost:3000/"] },
    source: "",
    dast: { profile: "standard", auth_header: "" },
    run_command: "ascent run --engagement engagements/acme.yaml --out out",
    ...over,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  if (originalClipboard) Object.defineProperty(navigator, "clipboard", originalClipboard);
  else delete (navigator as { clipboard?: unknown }).clipboard;
});

test("creating a scan posts parsed targets with the CSRF header and shows the run command", async () => {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  const onCreated = vi.fn();
  render(<NewScan onCreated={onCreated} />);

  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), {
    target: { value: "example.com\n\n  10.0.0.0/24  \nhttp://localhost:3000/\n" },
  });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  expect(await screen.findByText(/Scan defined: Acme/)).toBeInTheDocument();
  expect(
    screen.getByText("ascent run --engagement engagements/acme.yaml --out out"),
  ).toBeInTheDocument();
  expect(onCreated).toHaveBeenCalledTimes(1);

  // Posted with the right method/header and blank lines dropped + trimmed.
  const [url, init] = spy.mock.calls[0];
  expect(url).toBe("/api/engagements");
  expect(init?.method).toBe("POST");
  expect((init?.headers as Record<string, string>)["X-Ascent"]).toBe("1");
  const sent = JSON.parse(init?.body as string);
  expect(sent.name).toBe("Acme");
  expect(sent.targets).toEqual(["example.com", "10.0.0.0/24", "http://localhost:3000/"]);
});

test("rejected targets are listed and no success card is shown", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(
      {
        ok: false,
        error: "these targets are not valid, unambiguous in-scope entries",
        rejected: ["evil.com/path", "exa mple.com"],
      },
      422,
    ),
  );
  render(<NewScan />);
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), {
    target: { value: "evil.com/path\nexa mple.com" },
  });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/not valid, unambiguous/);
  expect(screen.getByText("evil.com/path")).toBeInTheDocument();
  expect(screen.getByText("exa mple.com")).toBeInTheDocument();
  expect(screen.queryByText(/Scan defined/)).not.toBeInTheDocument();
});

test("a source-not-found error is surfaced to the user", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json({ ok: false, error: "source path not found: ./nope", field: "source" }, 422),
  );
  render(<NewScan />);
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "example.com" } });
  fireEvent.change(screen.getByLabelText(/Source directory/), { target: { value: "./nope" } });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(/source path not found: \.\/nope/),
  );
});

test("the DAST profile select defaults to Standard and offers all three profiles", () => {
  render(<NewScan />);
  const select = screen.getByLabelText("DAST profile") as HTMLSelectElement;
  expect(select.value).toBe("standard");
  expect(Array.from(select.options).map((o) => o.value)).toEqual(["passive", "standard", "active"]);
  expect(screen.getByRole("option", { name: /^Passive — non-intrusive checks only$/ })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: /^Standard — .*\(default\)$/ })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: /^Active — adds intrusive templates and parameter fuzzing/})).toBeInTheDocument();
  expect(screen.getByText(/Ascent never stores the value/)).toBeInTheDocument();
});

test("profile and auth names are posted; the card shows them", async () => {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(created({ dast: { profile: "active", auth_header: "Authorization" } })),
  );
  render(<NewScan />);
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "example.com" } });
  fireEvent.change(screen.getByLabelText("DAST profile"), { target: { value: "active" } });
  fireEvent.change(screen.getByLabelText("Auth header name"), { target: { value: "Authorization" } });
  fireEvent.change(screen.getByLabelText("Env var holding its value"), {
    target: { value: "ASCENT_DAST_AUTH" },
  });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  expect(await screen.findByText(/Scan defined: Acme/)).toBeInTheDocument();
  expect(screen.getByText("Profile: active")).toBeInTheDocument();
  expect(screen.getByText("Auth header: Authorization")).toBeInTheDocument();

  const sent = JSON.parse(spy.mock.calls[0][1]?.body as string);
  expect(sent.dast_profile).toBe("active");
  expect(sent.auth_header).toBe("Authorization");
  expect(sent.auth_env).toBe("ASCENT_DAST_AUTH");
  expect(Object.keys(sent).sort()).toEqual(
    ["auth_env", "auth_header", "dast_profile", "name", "source", "targets"],
  );
});

test("default submit shows the standard profile and no auth line", async () => {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  render(<NewScan />);
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "example.com" } });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));

  expect(await screen.findByText("Profile: standard")).toBeInTheDocument();
  expect(screen.queryByText(/Auth header:/)).not.toBeInTheDocument();
  const sent = JSON.parse(spy.mock.calls[0][1]?.body as string);
  expect(sent.dast_profile).toBe("standard");
  expect(sent.auth_header).toBe("");
  expect(sent.auth_env).toBe("");
});

test("there is no input that accepts the auth header value itself", () => {
  render(<NewScan />);
  const labels = screen
    .getAllByRole("textbox")
    .map((el) => el.getAttribute("id"))
    .map((id) => document.querySelector(`label[for="${id}"]`)?.textContent);
  expect(labels).toEqual([
    "Engagement name",
    "Targets",
    "Source directory for SAST (optional)",
    "Auth header name",
    "Env var holding its value",
  ]);
  expect(document.querySelector('input[type="password"]')).toBeNull();
});

test("a dast validation error from the backend is surfaced", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(
      {
        ok: false,
        error: "dast.auth.value_env must be an environment variable name like ASCENT_DAST_AUTH ([A-Z_][A-Z0-9_]*)",
        field: "dast",
      },
      422,
    ),
  );
  render(<NewScan />);
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "example.com" } });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/value_env/));
});

test("the targets placeholder suggests 127.0.0.1, not localhost", () => {
  render(<NewScan />);
  const ta = screen.getByLabelText("Targets") as HTMLTextAreaElement;
  expect(ta.placeholder).toContain("http://127.0.0.1:3000/");
  expect(ta.placeholder).not.toMatch(/localhost/);
});

test("a localhost target shows a non-blocking resolver hint", async () => {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  render(<NewScan />);
  const hint = /ProjectDiscovery tools may not resolve localhost; prefer 127\.0\.0\.1/;
  const targets = screen.getByLabelText("Targets");
  expect(screen.queryByText(hint)).toBeNull();
  for (const value of ["example.com\nhttp://LOCALHOST:3000/", "localhost", "localhost:8080/x"]) {
    fireEvent.change(targets, { target: { value } });
    expect(screen.getByText(hint)).toBeInTheDocument();
  }
  fireEvent.change(targets, { target: { value: "http://127.0.0.1:3000/\nlocalhost.example.com" } });
  expect(screen.queryByText(hint)).toBeNull();

  // non-blocking: the scan is still created
  fireEvent.change(targets, { target: { value: "http://localhost:3000/" } });
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: "Acme" } });
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  expect(await screen.findByText(/Scan defined: Acme/)).toBeInTheDocument();
  expect(spy).toHaveBeenCalledTimes(1);
});

// ---------------------------------------------------------------------------------------------
// Task 6: the watchdog layout, the DAST fields' accessibility, and the non-negotiables.
// ---------------------------------------------------------------------------------------------

function fill(name = "Acme", targets = "example.com") {
  fireEvent.change(screen.getByLabelText("Engagement name"), { target: { value: name } });
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: targets } });
}

test("two cards side by side: the form, then the guidance; no legacy glass or panel", () => {
  const { container } = render(<NewScan />);
  const grid = container.querySelector(".newscan-grid") as HTMLElement;
  expect(grid).not.toBeNull();
  const cards = Array.from(grid.children) as HTMLElement[];
  expect(cards).toHaveLength(2);
  expect(cards[0]).toHaveClass("card");
  expect(cards[0].querySelector("form")).not.toBeNull();
  expect(cards[1]).toHaveClass("card");
  expect(container.querySelector(".glass, .panel, .phead, .ptitle, .fld")).toBeNull();
  expect(screen.getByRole("heading", { level: 2, name: "Define a new scan" })).toBeInTheDocument();
});

test("non-negotiables: scope-only pill, the scope-file note, and no control that launches a scan", () => {
  render(<NewScan />);
  expect(screen.getByText("defines scope — does not launch")).toHaveClass("count");
  expect(
    screen.getByText(
      "Creating a scan writes a scope file. Running it is a separate, explicit step, and every exploit action still requires your approval in the gates.",
    ),
  ).toBeInTheDocument();
  const names = screen.getAllByRole("button").map((b) => b.textContent);
  expect(names).toEqual(["Create scan"]);
  expect(screen.queryByRole("button", { name: /\b(run|start|launch)\b/i })).toBeNull();
});

test("the guidance card explains the three steps with the watchdog, and is replaced after success", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  const { container } = render(<NewScan />);
  expect(screen.getByRole("heading", { level: 2, name: "What happens next" })).toBeInTheDocument();
  const steps = container.querySelectorAll(".step");
  expect(steps).toHaveLength(3);
  expect(steps[0]).toHaveTextContent("Define the scope here.");
  expect(steps[1]).toHaveTextContent("Run it from your terminal.");
  expect(steps[2]).toHaveTextContent("Approve or deny each gate.");
  expect(screen.getByText("Scope first, always.")).toBeInTheDocument();
  const mascot = container.querySelector(".mascot--avatar") as HTMLElement;
  expect(mascot).toHaveAttribute("aria-hidden", "true");
  expect(mascot).toHaveStyle({ width: "96px", height: "96px" });
  expect(container.querySelector("img")).toBeNull();

  fill();
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  expect(await screen.findByText(/Scan defined: Acme/)).toBeInTheDocument();
  expect(screen.queryByText("What happens next")).toBeNull();
  expect(screen.queryByText("Scope first, always.")).toBeNull();
  // A labelled region, not a live region: focus moves to its heading, which is the announcement
  // (a role="status" on top of that is read twice).
  const success = screen.getByRole("region", { name: "Scan defined: Acme" });
  expect(success).toHaveClass("ok-card");
  expect(success).not.toHaveAttribute("role");
  // The only live region in it is the (still empty) copy confirmation, so nothing is read twice.
  for (const s of screen.queryAllByRole("status")) expect(s).toBeEmptyDOMElement();
  // A sibling of the form card's h2, not an h3 hanging under it with a level skipped.
  expect(within(success).getByRole("heading", { level: 2 })).toHaveTextContent("Scan defined: Acme");
  expect(within(success).queryByRole("heading", { level: 3 })).toBeNull();
  // still two cards in the grid
  expect(container.querySelector(".newscan-grid")?.children).toHaveLength(2);
});

test("the success card shows the copyable run command and Copy turns into Copied", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  stubClipboard(writeText);
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  const { container } = render(<NewScan />);
  fill();
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  const cmd = await screen.findByText("ascent run --engagement engagements/acme.yaml --out out");
  expect(cmd).toHaveClass("cmd");
  expect(screen.getByText("Run it from your terminal:")).toBeInTheDocument();
  expect(screen.getByText(/--policy samples\/ascent-policy.example.yaml/)).toBeInTheDocument();
  expect(screen.getByText(/The console now reflects this engagement/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Copy" }));
  expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  expect(writeText).toHaveBeenCalledWith("ascent run --engagement engagements/acme.yaml --out out");
  // hosts, cidrs and urls are listed as text chips
  expect(container.querySelector(".ok-card")).toHaveTextContent("example.com");
  expect(container.querySelector(".ok-card")).toHaveTextContent("10.0.0.0/24");
});

test("a copy is announced in a polite status region, which empties again with the label", async () => {
  stubClipboard(vi.fn().mockResolvedValue(undefined));
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  render(<NewScan />);
  fill();
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  const success = await screen.findByRole("region", { name: "Scan defined: Acme" });
  // Mounted (empty) with the card, so the text appearing in it is what gets announced.
  const live = within(success).getByRole("status");
  expect(live).toBeEmptyDOMElement();
  vi.useFakeTimers();
  try {
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    });
    expect(live).toHaveTextContent("Copied the run command to the clipboard");
    act(() => {
      vi.advanceTimersByTime(1500);
    });
    expect(live).toBeEmptyDOMElement();
    expect(screen.getByRole("button", { name: "Copy" })).toBeInTheDocument();
  } finally {
    vi.useRealTimers();
  }
});

test("a blocked copy says so and selects the command so it can be copied by hand", async () => {
  stubClipboard(vi.fn().mockRejectedValue(new Error("denied")));
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  render(<NewScan />);
  fill();
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  const success = await screen.findByRole("region", { name: "Scan defined: Acme" });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
  });
  // never claims success
  expect(screen.queryByRole("button", { name: "Copied" })).not.toBeInTheDocument();
  expect(within(success).getByRole("status")).toHaveTextContent(
    "Couldn't copy. The command is selected: press Ctrl+C to copy it.",
  );
  expect(window.getSelection()?.toString()).toBe("ascent run --engagement engagements/acme.yaml --out out");
});

test("the clipboard stub does not leak: navigator.clipboard is back to its original after each test", () => {
  expect(Object.getOwnPropertyDescriptor(navigator, "clipboard")).toEqual(originalClipboard);
});

test("on success, focus moves to the success heading and the card is scrolled into view", async () => {
  const scroll = vi.fn();
  Object.defineProperty(Element.prototype, "scrollIntoView", { value: scroll, configurable: true, writable: true });
  try {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
    render(<NewScan />);
    fill();
    fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
    const heading = await screen.findByRole("heading", { level: 2, name: /Scan defined: Acme/ });
    await waitFor(() => expect(heading).toHaveFocus());
    expect(scroll).toHaveBeenCalledWith({ block: "start" });
  } finally {
    delete (Element.prototype as { scrollIntoView?: unknown }).scrollIntoView;
  }
});

test("scanned strings in the success card are text, never markup", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    json(
      created({
        name: "<img src=x onerror=alert(1)>",
        source: "<script>alert(1)</script>",
        run_command: "ascent run <b>x</b>",
        scope: { hosts: ["<i>h</i>"], cidrs: [], urls: [] },
      }),
    ),
  );
  const { container } = render(<NewScan />);
  fill();
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  await screen.findByText(/Scan defined:/);
  expect(container.querySelector("img, script, i")).toBeNull();
  expect(screen.getByText("<i>h</i>")).toBeInTheDocument();
  expect(screen.getByText("ascent run <b>x</b>")).toBeInTheDocument();
});

test("the submit button is busy and disabled while the request is in flight", async () => {
  let release!: (r: Response) => void;
  vi.spyOn(globalThis, "fetch").mockReturnValueOnce(new Promise<Response>((res) => (release = res)));
  render(<NewScan />);
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Create scan" }));
  const busy = await screen.findByRole("button", { name: "Creating…" });
  expect(busy).toBeDisabled();
  expect(busy).toHaveAttribute("aria-busy", "true");
  release(json(created()));
  expect(await screen.findByText(/Scan defined: Acme/)).toBeInTheDocument();
});

test("the DAST profile hint follows the selection; Active is a warning in a polite live region", () => {
  const { container } = render(<NewScan />);
  const select = screen.getByLabelText("DAST profile");
  const live = container.querySelector('[aria-live="polite"]') as HTMLElement;
  expect(live).not.toBeNull();
  expect(select).toHaveAccessibleDescription(/The default/);
  expect(live.querySelector(".callout--warn")).toBeNull();

  fireEvent.change(select, { target: { value: "passive" } });
  expect(select).toHaveAccessibleDescription("Fingerprinting and passive checks only. Sends no attack payloads.");

  fireEvent.change(select, { target: { value: "active" } });
  expect(live).toHaveTextContent(ACTIVE_HINT);
  expect(live.querySelector(".callout--warn")).not.toBeNull();
  expect(live.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  expect(select).toHaveAccessibleDescription(ACTIVE_HINT);

  fireEvent.change(select, { target: { value: "standard" } });
  expect(live.querySelector(".callout--warn")).toBeNull();
  // the live region stays mounted throughout, so the change is announced
  expect(container.contains(live)).toBe(true);
});

test("the auth inputs sit in one fieldset whose hint describes both", () => {
  render(<NewScan />);
  const group = screen.getByRole("group", { name: "Authenticated scanning (optional)" });
  const header = screen.getByLabelText("Auth header name");
  const env = screen.getByLabelText("Env var holding its value");
  expect(group).toContainElement(header);
  expect(group).toContainElement(env);
  expect(group).toHaveClass("fieldset");
  for (const el of [header, env]) {
    expect(el).toHaveAccessibleDescription(/Ascent never stores the value/);
  }
  // the profile select and the other fields are outside the fieldset
  expect(group).not.toContainElement(screen.getByLabelText("DAST profile"));
  expect(group).not.toContainElement(screen.getByLabelText("Targets"));
});

test("the targets, source and localhost hints are linked to their inputs", () => {
  render(<NewScan />);
  expect(screen.getByLabelText("Targets")).toHaveAccessibleDescription(/Authorised scope only/);
  expect(screen.getByLabelText(/Source directory/)).toHaveAccessibleDescription(/white-box SAST/);
  fireEvent.change(screen.getByLabelText("Targets"), { target: { value: "localhost" } });
  expect(screen.getByLabelText("Targets")).toHaveAccessibleDescription(/prefer 127\.0\.0\.1/);
});

function invalidLabels() {
  return [...screen.getAllByRole("textbox"), ...screen.getAllByRole("combobox")]
    .filter((el) => el.getAttribute("aria-invalid") === "true")
    .map((el) => document.querySelector(`label[for="${el.id}"]`)?.textContent);
}

async function submitWith(body: unknown, status = 422) {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(body, status));
  fill();
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  return screen.findByRole("alert");
}

test("a 'source' error marks only the source input invalid and points it at the alert", async () => {
  render(<NewScan />);
  expect(invalidLabels()).toEqual([]);
  const alert = await submitWith({ ok: false, error: "source path not found: ./nope", field: "source" });
  expect(invalidLabels()).toEqual(["Source directory for SAST (optional)"]);
  const source = screen.getByLabelText(/Source directory/);
  expect(source.getAttribute("aria-describedby")).toContain(alert.id);
  expect(source).toHaveAccessibleDescription(/source path not found/);
  // an input that is not invalid does not point at the alert
  expect(screen.getByLabelText("Engagement name").getAttribute("aria-describedby") ?? "").not.toContain(alert.id);
});

test("a 'dast' error marks the two auth inputs invalid", async () => {
  render(<NewScan />);
  const alert = await submitWith({ ok: false, error: "dast.auth.value_env must be an environment variable name", field: "dast" });
  expect(invalidLabels()).toEqual(["Auth header name", "Env var holding its value"]);
  expect(screen.getByLabelText("Env var holding its value").getAttribute("aria-describedby")).toContain(alert.id);
});

test("rejected targets mark the targets textarea invalid and are listed as code chips", async () => {
  render(<NewScan />);
  const alert = await submitWith({ ok: false, error: "these targets are not valid, unambiguous in-scope entries", rejected: ["evil.com/path", "exa mple.com"] });
  expect(invalidLabels()).toEqual(["Targets"]);
  expect(within(alert).getByText("evil.com/path").tagName).toBe("CODE");
  expect(alert).toHaveClass("callout--err");
});

test("an error without a known field marks nothing invalid; hostile field names are ignored", async () => {
  render(<NewScan />);
  await submitWith({ ok: false, error: "name must contain letters or digits" });
  expect(invalidLabels()).toEqual([]);
  for (const field of ["constructor", "__proto__", "toString"]) {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({ ok: false, error: `nope ${field}`, field }, 422));
    fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(`nope ${field}`));
    expect(invalidLabels()).toEqual([]);
  }
});

test("invalid marks clear on the next submit", async () => {
  render(<NewScan />);
  await submitWith({ ok: false, error: "source path not found: ./nope", field: "source" });
  expect(invalidLabels()).toHaveLength(1);
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(created()));
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  await screen.findByText(/Scan defined: Acme/);
  expect(invalidLabels()).toEqual([]);
});

test("a network failure shows the fixed unreachable message, not an error body", async () => {
  vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new TypeError("boom <img src=x>"));
  render(<NewScan />);
  fill();
  fireEvent.click(screen.getByRole("button", { name: /create scan/i }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach the Ascent backend. Try again.");
});
