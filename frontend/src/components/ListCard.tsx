import { useId } from "react";
import type { ReactNode, Ref } from "react";
import { Button } from "./Button";

export interface ListCardProps {
  title: string;
  /** Count pill next to the title, e.g. "3 pending". */
  count?: ReactNode;
  /**
   * "See all" button. `label` is the noun that makes the accessible name unique
   * ("findings" gives "See all findings"); it is read by assistive tech only.
   */
  seeAll?: { label: string; onClick(): void };
  headExtra?: ReactNode;
  /** Given: the title can take focus from script (`tabIndex=-1`), e.g. after a row removes itself. */
  titleRef?: Ref<HTMLHeadingElement>;
  children: ReactNode;
}

/** Card with a heading row (title, count, extras, See all) over a list of rows. */
export function ListCard({ title, count, seeAll, headExtra, titleRef, children }: ListCardProps) {
  const titleId = useId();
  return (
    <section className="card list-card" aria-labelledby={titleId}>
      <div className="card-head">
        <h2 className="card-title" id={titleId} ref={titleRef} tabIndex={titleRef ? -1 : undefined}>
          {title}
        </h2>
        {count !== undefined && count !== null && count !== false ? (
          <span className="count">{count}</span>
        ) : null}
        {headExtra}
        {seeAll ? (
          <Button variant="secondary" size="sm" onClick={seeAll.onClick}>
            See all<span className="sr-only"> {seeAll.label}</span>
          </Button>
        ) : null}
      </div>
      {children}
    </section>
  );
}
