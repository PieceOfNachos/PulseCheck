import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS_STYLES = {
  UP: "border-transparent bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  DOWN: "border-transparent bg-red-500/15 text-red-600 dark:text-red-400",
  PAUSED: "border-transparent bg-muted text-muted-foreground",
  UNKNOWN: "border-transparent bg-muted text-muted-foreground",
};

const STATUS_DOT = {
  UP: "bg-emerald-500",
  DOWN: "bg-red-500",
  PAUSED: "bg-muted-foreground",
  UNKNOWN: "bg-muted-foreground",
};

/**
 * @param {{ active: boolean, lastStatus: 'UP' | 'DOWN' | null | undefined }} props
 */
export default function StatusBadge({ active, lastStatus }) {
  const key = !active ? "PAUSED" : lastStatus === "UP" || lastStatus === "DOWN" ? lastStatus : "UNKNOWN";
  const label = !active ? "Paused" : lastStatus === "UP" ? "Up" : lastStatus === "DOWN" ? "Down" : "Pending";

  return (
    <Badge variant="outline" className={cn("gap-1.5", STATUS_STYLES[key])}>
      <span className={cn("size-1.5 shrink-0 rounded-full", STATUS_DOT[key])} />
      {label}
    </Badge>
  );
}
