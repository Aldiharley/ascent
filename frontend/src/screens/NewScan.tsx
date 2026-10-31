import { useEffect, useRef, useState } from "react";
import { CreateEngagementError, createEngagement } from "../api";
import type { CreatedEngagement, NewScanInput } from "../api";
import { Button } from "../components/Button";
import { IconBadge } from "../components/IconBadge";
import { IconAlertCircle, IconAlertTriangle, IconCopy, IconInfo, IconTick } from "../components/icons";
import { Mascot } from "../components/Mascot";

type DastProfile = NonNullable<NewScanInput["dast_profile"]>;

const PROFILE_OPTIONS: { value: DastProfile; label: string }[] = [
  { value: "passive", label: "Passive — non-intrusive checks only" },
  {
    value: "standard",
    label: "Standard — known-vulnerability and injection templates (default)",
  },
  {
    value: "active",
    label: "Active — adds parameter fuzzing; only for targets you may actively test",
  },
];

// One line under the select, following its value (fixed UI copy, never data). Active's is a warning.
const PROFILE_HINTS: Record<DastProfile, string> = {
  passive: "Fingerprinting and passive checks only. Sends no attack payloads.",
  standard: "Passive checks plus known-vulnerability and injection templates. The default.",
  // The standard profile excludes the `intrusive` templates; active keeps them and adds fuzzing.
  active:
    "Adds intrusive templates and parameter fuzzing — may change application state. Use only on a lab or staging target.",
};

export interface NewScanProps {
  /** Called after an engagement is created, so the shell can refresh the topbar. */
  onCreated?: () => void;
}

type Submit =
  | { status: "idle" }
  | { status: "submitting" }
  | { status: "created"; result: CreatedEngagement }
  | { status: "error"; message: string; rejected?: string[]; field?: string };

type Control = "targets" | "source" | "authHeader" | "authEnv";

// Which controls the backend's 422 `field` names. `field` is external text, so it is looked up
// with hasOwn: "constructor" or "__proto__" must never resolve to something.
const FIELD_CONTROLS: Record<string, Control[]> = {
  source: ["source"],
  dast: ["authHeader", "authEnv"],
};

/** The controls an error is about: its named field, plus the targets when some were rejected. */
function invalidControls(err: Extract<Submit, { status: "error" }>): ReadonlySet<Control> {
  const out = new Set<Control>();
  if (err.field !== undefined && Object.hasOwn(FIELD_CONTROLS, err.field)) {
    for (const c of FIELD_CONTROLS[err.field]) out.add(c);
  }
  if (err.rejected && err.rejected.length > 0) out.add("targets");
  return out;
}

/** Space-joined ids for `aria-describedby`, skipping the absent ones. */
function describedBy(...ids: (string | false | undefined)[]): string | undefined {
  const list = ids.filter((i): i is string => typeof i === "string" && i !== "");
  return list.length > 0 ? list.join(" ") : undefined;
}

/** Split the textarea into one raw target per line (blank lines dropped). */
function parseTargets(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

/** The lower-cased host of a raw target line (URL, host[:port][/path], or IP). */
function hostOf(target: string): string {
  if (target.includes("://")) {
    try {
      return new URL(target).hostname.toLowerCase();
    } catch {
      return "";
    }
  }
  const authority = target.split(/[/?#]/)[0];
  return (authority.startsWith("[") ? authority : authority.split(":")[0]).toLowerCase();
}

/** True when any target names `localhost`, which ProjectDiscovery tools may not resolve. */
function mentionsLocalhost(text: string): boolean {
  return parseTargets(text).some((t) => hostOf(t) === "localhost");
}

const ERR_ID = "ns-error";

export function NewScan({ onCreated }: NewScanProps = {}) {
  const [name, setName] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [source, setSource] = useState("");
  const [profile, setProfile] = useState<DastProfile>("standard");
  const [authHeader, setAuthHeader] = useState("");
  const [authEnv, setAuthEnv] = useState("");
  const [submit, setSubmit] = useState<Submit>({ status: "idle" });
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const successCard = useRef<HTMLElement>(null);
  const successTitle = useRef<HTMLHeadingElement>(null);

  useEffect(() => () => clearTimeout(copyTimer.current), []);

  // The success card appears beside (or, on a phone, below) the form: move focus to its heading so
  // keyboard and screen-reader users land on it, and the browser scrolls it into view.
  const created = submit.status === "created";
  useEffect(() => {
    if (!created) return;
    successTitle.current?.focus({ preventScroll: true });
    // Not every environment (jsdom) has scrollIntoView; the card's scroll-margin clears the top bar.
    successCard.current?.scrollIntoView?.({ block: "start" });
  }, [created]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submit.status === "submitting") return;
    setSubmit({ status: "submitting" });
    try {
      const result = await createEngagement({
        name,
        targets: parseTargets(targetsText),
        source: source.trim(),
        dast_profile: profile,
        auth_header: authHeader.trim(),
        auth_env: authEnv.trim(),
      });
      setSubmit({ status: "created", result });
      onCreated?.();
    } catch (err) {
      if (err instanceof CreateEngagementError) {
        setSubmit({
          status: "error",
          message: err.message,
          rejected: err.rejected,
          field: err.field,
        });
      } else {
        setSubmit({ status: "error", message: "Could not reach the Ascent backend. Try again." });
      }
    }
  }

  async function copyCommand(cmd: string) {
    clearTimeout(copyTimer.current);
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
      copyTimer.current = setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  const busy = submit.status === "submitting";
  const invalid = submit.status === "error" ? invalidControls(submit) : new Set<Control>();
  const errRef = (c: Control) => invalid.has(c) && ERR_ID;
  const profileHint = Object.hasOwn(PROFILE_HINTS, profile) ? PROFILE_HINTS[profile] : "";

  return (
    <div className="newscan-grid">
      <section className="card" aria-labelledby="ns-title">
        <div className="card-head">
          <h2 className="card-title" id="ns-title">
            Define a new scan
          </h2>
          <span className="count">defines scope — does not launch</span>
        </div>

        <form className="newscan-form" onSubmit={onSubmit} noValidate>
          <div className="field">
            <label htmlFor="ns-name">Engagement name</label>
            <input
              id="ns-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Acme staging — Q4"
              autoComplete="off"
            />
          </div>

          <div className="field">
            <label htmlFor="ns-targets">Targets</label>
            <span className="hint" id="ns-targets-hint">
              One per line: a hostname, IP, CIDR, or URL. Authorised scope only — Ascent will refuse
              to test anything outside this list. Subdomains of a listed host are included.
            </span>
            <textarea
              id="ns-targets"
              value={targetsText}
              onChange={(e) => setTargetsText(e.target.value)}
              placeholder={"127.0.0.1\n127.0.0.0/8\nhttp://127.0.0.1:3000/"}
              spellCheck={false}
              aria-invalid={invalid.has("targets") ? true : undefined}
              aria-describedby={describedBy(
                "ns-targets-hint",
                mentionsLocalhost(targetsText) && "ns-localhost-hint",
                errRef("targets"),
              )}
            />
            {mentionsLocalhost(targetsText) && (
              <span className="hint" role="note" id="ns-localhost-hint">
                ProjectDiscovery tools may not resolve localhost; prefer 127.0.0.1
              </span>
            )}
          </div>

          <div className="field">
            <label htmlFor="ns-source">Source directory for SAST (optional)</label>
            <span className="hint" id="ns-source-hint">
              A path to source code enables the white-box SAST track. Leave blank for network
              scanning only.
            </span>
            <input
              id="ns-source"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder="e.g. ./src"
              autoComplete="off"
              aria-invalid={invalid.has("source") ? true : undefined}
              aria-describedby={describedBy("ns-source-hint", errRef("source"))}
            />
          </div>

          <div className="field">
            <label htmlFor="ns-profile">DAST profile</label>
            <select
              id="ns-profile"
              value={profile}
              onChange={(e) => setProfile(e.target.value as DastProfile)}
              aria-describedby="ns-profile-hint"
            >
              {PROFILE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
            {/* Always mounted, so the swap between the plain hint and Active's warning is announced. */}
            <div id="ns-profile-hint" aria-live="polite">
              {profile === "active" ? (
                <p className="callout callout--warn">
                  <IconAlertTriangle />
                  <span>{profileHint}</span>
                </p>
              ) : (
                <p className="hint">{profileHint}</p>
              )}
            </div>
          </div>

          <fieldset className="fieldset">
            <legend>Authenticated scanning (optional)</legend>
            <p className="hint" id="ns-auth-hint">
              For authenticated scanning, name the header and the environment variable that holds
              its value (for example Authorization and ASCENT_DAST_AUTH). Ascent never stores the
              value; set the variable in the terminal that runs the scan.
            </p>
            <div className="fieldset-grid">
              <div className="field">
                <label htmlFor="ns-auth-header">Auth header name</label>
                <input
                  id="ns-auth-header"
                  value={authHeader}
                  onChange={(e) => setAuthHeader(e.target.value)}
                  placeholder="e.g. Authorization"
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={invalid.has("authHeader") ? true : undefined}
                  aria-describedby={describedBy("ns-auth-hint", errRef("authHeader"))}
                />
              </div>
              <div className="field">
                <label htmlFor="ns-auth-env">Env var holding its value</label>
                <input
                  id="ns-auth-env"
                  value={authEnv}
                  onChange={(e) => setAuthEnv(e.target.value)}
                  placeholder="e.g. ASCENT_DAST_AUTH"
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={invalid.has("authEnv") ? true : undefined}
                  aria-describedby={describedBy("ns-auth-hint", errRef("authEnv"))}
                />
              </div>
            </div>
          </fieldset>

          <p className="callout callout--info">
            <IconInfo />
            <span>
              Creating a scan writes a scope file. Running it is a separate, explicit step, and every
              exploit action still requires your approval in the gates.
            </span>
          </p>

          {submit.status === "error" && (
            <div className="callout callout--err" role="alert" id={ERR_ID}>
              <IconAlertCircle />
              <div className="callout-body">
                <p>{submit.message}</p>
                {submit.rejected && submit.rejected.length > 0 && (
                  <ul className="chip-list">
                    {submit.rejected.map((t) => (
                      <li key={t}>
                        <code className="tag tag--wrap">{t}</code>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}

          <Button type="submit" variant="primary" className="newscan-submit" busy={busy}>
            {busy ? "Creating…" : "Create scan"}
          </Button>
        </form>
      </section>

      {submit.status === "created" ? (
        // A labelled region rather than a live region: focus moves to the heading, which is what gets
        // announced (a role="status" on top of that is read twice).
        <section className="card ok-card" aria-labelledby="ns-success-title" ref={successCard}>
          <div className="ok-head">
            <IconBadge tone="teal" size="sm">
              <IconTick />
            </IconBadge>
            <h2 className="card-title" id="ns-success-title" ref={successTitle} tabIndex={-1}>
              Scan defined: {submit.result.name}
            </h2>
          </div>
          <ScopeList label="Hosts" items={submit.result.scope.hosts} />
          <ScopeList label="CIDRs" items={submit.result.scope.cidrs} />
          <ScopeList label="URLs" items={submit.result.scope.urls} />
          {submit.result.source !== "" && (
            <div className="scope-list">
              <b>SAST source:</b>
              <code className="tag tag--wrap">{submit.result.source}</code>
            </div>
          )}
          <div className="scope-list">
            <span>{`Profile: ${submit.result.dast.profile}`}</span>
            {submit.result.dast.auth_header !== "" && (
              <span>{`Auth header: ${submit.result.dast.auth_header}`}</span>
            )}
          </div>
          <div className="ok-run">
            <p className="hint">Run it from your terminal:</p>
            <div className="cmd-row">
              <div className="cmd">{submit.result.run_command}</div>
              <Button variant="secondary" size="sm" onClick={() => copyCommand(submit.result.run_command)}>
                {copied ? <IconTick /> : <IconCopy />}
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <p className="hint">
              Add <code>--policy samples/ascent-policy.example.yaml</code> to gate the run: the
              command then exits 1 when the policy fails, ready for CI.
            </p>
          </div>
          <p className="callout callout--info">
            <IconInfo />
            <span>
              The console now reflects this engagement. Findings, gates and the report fill in once
              the run completes.
            </span>
          </p>
        </section>
      ) : (
        <section className="card guidance" aria-labelledby="ns-guidance-title">
          <div className="card-head">
            <h2 className="card-title" id="ns-guidance-title">
              What happens next
            </h2>
          </div>
          <ol className="steps">
            <li className="step">
              <span className="step-num" aria-hidden="true">
                1
              </span>
              <p>
                <b>Define the scope here.</b> Ascent writes a validated engagement file and refuses
                anything outside it.
              </p>
            </li>
            <li className="step">
              <span className="step-num" aria-hidden="true">
                2
              </span>
              <p>
                <b>Run it from your terminal.</b> You get the exact <code>ascent run</code> command
                to copy.
              </p>
            </li>
            <li className="step">
              <span className="step-num" aria-hidden="true">
                3
              </span>
              <p>
                <b>Approve or deny each gate.</b> Approving records consent; nothing runs from this
                console.
              </p>
            </li>
          </ol>
          <div className="guidance-foot">
            <Mascot pose="avatar" size={96} />
            <p>Scope first, always.</p>
          </div>
        </section>
      )}
    </div>
  );
}

function ScopeList({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="scope-list">
      <b>{label}:</b>
      {items.map((it) => (
        <code className="tag tag--wrap" key={it}>
          {it}
        </code>
      ))}
    </div>
  );
}
