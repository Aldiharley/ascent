import { useState } from "react";
import { CreateEngagementError, createEngagement } from "../api";
import type { CreatedEngagement, NewScanInput } from "../api";

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

export interface NewScanProps {
  /** Called after an engagement is created, so the shell can refresh the topbar. */
  onCreated?: () => void;
}

type Submit =
  | { status: "idle" }
  | { status: "submitting" }
  | { status: "created"; result: CreatedEngagement }
  | { status: "error"; message: string; rejected?: string[]; field?: string };

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

export function NewScan({ onCreated }: NewScanProps = {}) {
  const [name, setName] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [source, setSource] = useState("");
  const [profile, setProfile] = useState<DastProfile>("standard");
  const [authHeader, setAuthHeader] = useState("");
  const [authEnv, setAuthEnv] = useState("");
  const [submit, setSubmit] = useState<Submit>({ status: "idle" });
  const [copied, setCopied] = useState(false);

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
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  const busy = submit.status === "submitting";

  return (
    <section className="panel glass">
      <div className="phead">
        <span className="ptitle">New scan</span>
        <span className="count">defines scope — does not launch</span>
      </div>

      <form className="newscan" onSubmit={onSubmit} noValidate>
        <div className="fld">
          <label htmlFor="ns-name">Engagement name</label>
          <input
            id="ns-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Acme staging — Q4"
            autoComplete="off"
          />
        </div>

        <div className="fld">
          <label htmlFor="ns-targets">Targets</label>
          <span className="hint">
            One per line: a hostname, IP, CIDR, or URL. Authorised scope only — Ascent will refuse
            to test anything outside this list. Subdomains of a listed host are included.
          </span>
          <textarea
            id="ns-targets"
            value={targetsText}
            onChange={(e) => setTargetsText(e.target.value)}
            placeholder={"127.0.0.1\n127.0.0.0/8\nhttp://127.0.0.1:3000/"}
            spellCheck={false}
          />
          {mentionsLocalhost(targetsText) && (
            <span className="hint" role="note">
              ProjectDiscovery tools may not resolve localhost; prefer 127.0.0.1
            </span>
          )}
        </div>

        <div className="fld">
          <label htmlFor="ns-source">Source directory for SAST (optional)</label>
          <span className="hint">
            A path to source code enables the white-box SAST track. Leave blank for network scanning
            only.
          </span>
          <input
            id="ns-source"
            value={source}
            onChange={(e) => setSource(e.target.value)}
            placeholder="e.g. ./src"
            autoComplete="off"
          />
        </div>

        <div className="fld">
          <label htmlFor="ns-profile">DAST profile</label>
          <select
            id="ns-profile"
            value={profile}
            onChange={(e) => setProfile(e.target.value as DastProfile)}
          >
            {PROFILE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        <div className="fld">
          <label htmlFor="ns-auth-header">Auth header name</label>
          <input
            id="ns-auth-header"
            value={authHeader}
            onChange={(e) => setAuthHeader(e.target.value)}
            placeholder="e.g. Authorization"
            autoComplete="off"
            spellCheck={false}
          />
        </div>

        <div className="fld">
          <label htmlFor="ns-auth-env">Env var holding its value</label>
          <input
            id="ns-auth-env"
            value={authEnv}
            onChange={(e) => setAuthEnv(e.target.value)}
            placeholder="e.g. ASCENT_DAST_AUTH"
            autoComplete="off"
            spellCheck={false}
          />
          <span className="hint">
            For authenticated scanning, name the header and the environment variable that holds its
            value (for example Authorization and ASCENT_DAST_AUTH). Ascent never stores the value;
            set the variable in the terminal that runs the scan.
          </span>
        </div>

        <div className="note" style={{ textAlign: "left" }}>
          Creating a scan writes a scope file. Running it is a separate, explicit step, and every
          exploit action still requires your approval in the gates.
        </div>

        {submit.status === "error" && (
          <div className="err" role="alert">
            {submit.message}
            {submit.rejected && submit.rejected.length > 0 && (
              <ul>
                {submit.rejected.map((t) => (
                  <li key={t}>
                    <code>{t}</code>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        <button type="submit" className="submit" disabled={busy}>
          {busy ? "Creating…" : "Create scan"}
        </button>
      </form>

      {submit.status === "created" && (
        <div className="newscan">
          <div className="ok-card" role="status">
            <h4>Scan defined: {submit.result.name}</h4>
            <ScopeList label="Hosts" items={submit.result.scope.hosts} />
            <ScopeList label="CIDRs" items={submit.result.scope.cidrs} />
            <ScopeList label="URLs" items={submit.result.scope.urls} />
            {submit.result.source !== "" && (
              <div className="scope-list">
                <b>SAST source:</b> <span className="loc">{submit.result.source}</span>
              </div>
            )}
            <div className="scope-list">
              <span>{`Profile: ${submit.result.dast.profile}`}</span>
              {submit.result.dast.auth_header !== "" && (
                <span>{`Auth header: ${submit.result.dast.auth_header}`}</span>
              )}
            </div>
            <div>
              <div className="hint" style={{ marginBottom: 6 }}>
                Run it from your terminal:
              </div>
              <div className="cmd-row">
                <div className="cmd">{submit.result.run_command}</div>
                <button
                  type="button"
                  className="copy"
                  onClick={() => copyCommand(submit.result.run_command)}
                >
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="hint" style={{ marginTop: 6 }}>
                Add <code>--policy samples/ascent-policy.example.yaml</code> to gate the run: the command then exits 1 when the
                policy fails, ready for CI.
              </div>
            </div>
            <div className="note" style={{ textAlign: "left" }}>
              The console now reflects this engagement. Findings, gates and the report fill in once
              the run completes.
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function ScopeList({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="scope-list">
      <b>{label}:</b>
      {items.map((it) => (
        <span className="loc" key={it}>
          {it}
        </span>
      ))}
    </div>
  );
}
