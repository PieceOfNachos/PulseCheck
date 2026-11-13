import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS_STYLES = {
  INVESTIGATING: "border-transparent bg-sky-500/15 text-sky-600 dark:text-sky-400",
  AWAITING_APPROVAL:
    "border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400",
  RESOLVED: "border-transparent bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  FAILED: "border-transparent bg-red-500/15 text-red-600 dark:text-red-400",
};

const STATUS_DOT = {
  INVESTIGATING: "bg-sky-500 animate-pulse",
  AWAITING_APPROVAL: "bg-amber-500 animate-pulse",
  RESOLVED: "bg-emerald-500",
  FAILED: "bg-red-500",
};

const STATUS_LABELS = {
  INVESTIGATING: "Investigating",
  AWAITING_APPROVAL: "Awaiting approval",
  RESOLVED: "Resolved",
  FAILED: "Failed",
};

/**
 * @param {{ status: 'INVESTIGATING' | 'AWAITING_APPROVAL' | 'RESOLVED' | 'FAILED' }} props
 */
export default function IncidentStatusBadge({ status }) {
  const style = STATUS_STYLES[status] || "border-transparent bg-muted text-muted-foreground";
  const dot = STATUS_DOT[status] || "bg-muted-foreground";

  return (
    <Badge variant="outline" className={cn("gap-1.5", style)}>
      <span className={cn("size-1.5 shrink-0 rounded-full", dot)} />
      {STATUS_LABELS[status] || status}
    </Badge>
  );
}
