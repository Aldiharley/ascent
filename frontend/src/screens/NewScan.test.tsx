import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { NewScan } from "./NewScan";

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
  expect(screen.getByRole("option", { name: /^Active — adds parameter fuzzing/ })).toBeInTheDocument();
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
