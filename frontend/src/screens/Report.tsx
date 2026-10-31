import { useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import type { Components } from "react-markdown";
import { EmptyState } from "../components/EmptyState";
import { ErrorCard, LoadingCard } from "../components/StateCards";
import { useStaleResource } from "../data/resources";
import { sectionIds, sectionLabel } from "../data/reportSections";

// The markdown contains text derived from scanned targets (titles, URLs), so it
// is attacker-controlled. Safety rules, all enforced here:
//  - no raw HTML (no rehype-raw; react-markdown drops it) and no
//    dangerouslySetInnerHTML;
//  - no <img> is ever created, because the browser would fetch the URL
//    automatically and beacon data out; images render as their alt text;
//  - react-markdown's default URL sanitising stays on (no javascript: hrefs);
//  - links open in a new tab with noopener noreferrer.
const components: Components = {
  // The page's one h1 is the top-bar title, so the report's own title is a styled div.
  h1: ({ children }) => <div className="report-title">{children}</div>,
  img: ({ alt }) => (alt ? <span>[image: {alt}]</span> : null),
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  ),
};

interface Section {
  id: string;
  label: string;
}

/**
 * The id of the section being read: the first heading inside the top band of the viewport. Without
 * IntersectionObserver (old browsers, jsdom) nothing is ever marked, which is only cosmetic.
 */
function useActiveSection(body: React.RefObject<HTMLElement | null>, sections: readonly Section[]) {
  const [active, setActive] = useState<string | null>(null);
  useEffect(() => {
    setActive(null);
    const root = body.current;
    if (!root || sections.length === 0 || typeof IntersectionObserver === "undefined") return;
    const ids = new Set(sections.map((s) => s.id));
    const heads = Array.from(root.querySelectorAll("h2")).filter((h) => ids.has(h.id));
    // Where each heading is relative to the observed band, from its latest report: in it, scrolled
    // past it (above), or still to come (below).
    const place = new Map<string, "in" | "above" | "below">();
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          const id = (e.target as HTMLElement).id;
          if (e.isIntersecting) place.set(id, "in");
          else {
            const bandTop = e.rootBounds?.top ?? 0;
            place.set(id, e.boundingClientRect.top < bandTop ? "above" : "below");
          }
        }
        // The first heading in the band is the one being read. With none in it, the section is the
        // last heading scrolled past (so scrolling back up moves the mark up too), or none at all
        // above the first heading.
        const inBand = sections.find((s) => place.get(s.id) === "in");
        if (inBand) return setActive(inBand.id);
        const passed = sections.filter((s) => place.get(s.id) === "above");
        setActive(passed.length > 0 ? passed[passed.length - 1].id : null);
      },
      { rootMargin: "0px 0px -65% 0px" },
    );
    for (const h of heads) io.observe(h);
    return () => io.disconnect();
  }, [body, sections]);
  return active;
}

function ReportBody({ markdown }: { markdown: string }) {
  const body = useRef<HTMLElement>(null);
  const [sections, setSections] = useState<Section[]>([]);
  // Rendering the markdown once per document keeps the active-section updates from re-rendering it.
  const rendered = useMemo(
    () => <ReactMarkdown components={components}>{markdown}</ReactMarkdown>,
    [markdown],
  );

  // After the markdown is in the DOM, give each h2 an id and build the index from its text.
  useEffect(() => {
    const heads = Array.from(body.current?.querySelectorAll("h2") ?? []);
    const ids = sectionIds(heads.map((h) => h.textContent ?? ""));
    heads.forEach((h, i) => {
      h.id = ids[i];
    });
    setSections(heads.map((h, i) => ({ id: ids[i], label: sectionLabel(h.textContent ?? "", i) })));
  }, [markdown]);

  const active = useActiveSection(body, sections);

  return (
    <div className="report-layout">
      <article className="card report" ref={body}>
        {rendered}
      </article>
      {sections.length > 0 && (
        <nav className="report-index card" aria-label="Report sections">
          <div className="idx-title">On this page</div>
          <ul className="list-plain">
            {sections.map((s) => (
              <li key={s.id}>
                <a href={`#${s.id}`} aria-current={active === s.id ? "location" : undefined}>
                  {s.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      )}
    </div>
  );
}

export function Report({ version = 0 }: { version?: number } = {}) {
  const state = useStaleResource("report", version);

  if (state.status === "loading") return <LoadingCard caption="Loading report…" rows={5} />;
  if (state.status === "error") return <ErrorCard title="Could not load the report" onRetry={state.retry} />;

  const markdown = state.data;
  if (markdown.trim() === "") {
    return (
      <section className="card" aria-labelledby="report-empty-title">
        <div className="card-head">
          <h2 className="card-title" id="report-empty-title">
            Report
          </h2>
        </div>
        <EmptyState size={160} title="No report yet. Run a scan to generate one." />
      </section>
    );
  }

  return <ReportBody markdown={markdown} />;
}
