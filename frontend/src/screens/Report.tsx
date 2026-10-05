import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import type { Components } from "react-markdown";
import { getReport } from "../api";

// The markdown contains text derived from scanned targets (titles, URLs), so it
// is attacker-controlled. Safety rules, all enforced here:
//  - no raw HTML (no rehype-raw; react-markdown drops it) and no
//    dangerouslySetInnerHTML;
//  - no <img> is ever created, because the browser would fetch the URL
//    automatically and beacon data out; images render as their alt text;
//  - react-markdown's default URL sanitising stays on (no javascript: hrefs);
//  - links open in a new tab with noopener noreferrer.
const components: Components = {
  // glass.css keeps the mockup's `h1{font-size:0}`, so the title is not an <h1>.
  h1: ({ children }) => <div className="report-title">{children}</div>,
  img: ({ alt }) => (alt ? <span>[image: {alt}]</span> : null),
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  ),
};

type State =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; markdown: string };

export function Report() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let live = true;
    getReport().then(
      (markdown) => live && setState({ status: "ready", markdown }),
      () => live && setState({ status: "error" }),
    );
    return () => {
      live = false;
    };
  }, []);

  if (state.status === "loading") {
    return (
      <section className="panel glass" role="status">
        <div className="phead">
          <span className="ptitle">Loading report…</span>
        </div>
      </section>
    );
  }

  if (state.status === "error") {
    return (
      <section className="panel glass" role="alert">
        <div className="phead">
          <span className="ptitle">Could not load the report</span>
          <span className="count">check that the Ascent backend is running</span>
        </div>
      </section>
    );
  }

  if (state.markdown.trim() === "") {
    return (
      <section className="panel glass">
        <div className="phead">
          <span className="ptitle">Report</span>
        </div>
        <div className="note">No report yet. Run a scan to generate one.</div>
      </section>
    );
  }

  return (
    <section className="panel glass">
      <div className="report">
        <ReactMarkdown components={components}>
          {state.markdown}
        </ReactMarkdown>
      </div>
    </section>
  );
}
