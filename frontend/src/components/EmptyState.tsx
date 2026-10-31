import type { ReactNode } from "react";
import { Mascot } from "./Mascot";
import type { MascotPose } from "./Mascot";

/** Centred "nothing here" block: the resting watchdog, a title, optional body and action. */
export function EmptyState({
  pose = "rest",
  size = 96,
  title,
  children,
  action,
}: {
  pose?: MascotPose;
  size?: number;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <Mascot pose={pose} size={size} />
      <p className="es-title">{title}</p>
      {children ? <div className="es-body">{children}</div> : null}
      {action ? <div className="es-action">{action}</div> : null}
    </div>
  );
}
