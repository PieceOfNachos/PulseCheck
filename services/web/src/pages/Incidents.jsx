import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listIncidents } from "@/lib/api";
import {
  categoryLabel,
  formatConfidence,
  formatTime,
  isAutoRecovered,
  unwrapList,
} from "@/lib/incidents";
import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import IncidentStatusBadge from "@/components/IncidentStatusBadge";
import { cn } from "@/lib/utils";
import { BookOpenIcon, BotIcon, RotateCcwIcon } from "lucide-react";

const POLL_INTERVAL_MS = 15_000;

function SkeletonRow() {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-5 w-1/3" />
        <Skeleton className="h-4 w-1/2" />
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-2/3" />
      </CardContent>
    </Card>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border py-20 text-center">
      <BotIcon className="size-8 text-muted-foreground" />
      <div>
        <p className="font-medium">No incidents yet</p>
        <p className="max-w-md text-sm text-muted-foreground">
          When a monitor goes down, the agent investigates and posts its findings here.
        </p>
      </div>
    </div>
  );
}

function IncidentRow({ incident }) {
  const navigate = useNavigate();
  const diagnosis = incident.diagnosis;
  const category = categoryLabel(incident);
  const confidence = formatConfidence(diagnosis?.confidence);
  const awaiting = incident.status === "AWAITING_APPROVAL";

  return (
    <Card
      className={cn(
        "cursor-pointer transition-colors hover:ring-foreground/20",
        awaiting && "ring-amber-500/40 hover:ring-amber-500/60",
      )}
      onClick={() => navigate(`/incidents/${encodeURIComponent(incident.id)}`)}
    >
      <CardHeader>
        <CardTitle className="truncate">{incident.monitorName}</CardTitle>
        <p className="truncate text-sm text-muted-foreground" title={incident.monitorUrl}>
          {incident.monitorUrl}
        </p>
        <CardAction>
          <IncidentStatusBadge status={incident.status} />
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {diagnosis ? (
          <p className="line-clamp-2 text-sm">{diagnosis.root_cause}</p>
        ) : (
          <p className="text-sm text-muted-foreground">
            {incident.status === "FAILED"
              ? incident.error || "The investigation failed before a diagnosis was made."
              : "Gathering evidence…"}
          </p>
        )}
        {isAutoRecovered(incident) && (
          <p className="flex items-center gap-1.5 text-sm text-emerald-600 dark:text-emerald-400">
            <RotateCcwIcon className="size-3.5 shrink-0" />
            Auto-closed: monitor recovered before approval — no actions taken
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          {category && <Badge variant="secondary">{category}</Badge>}
          {confidence && <span>{confidence} confidence</span>}
          {diagnosis?.cited_sources?.map((source) => (
            <Badge key={source} variant="outline" className="text-muted-foreground">
              <BookOpenIcon /> {source}
            </Badge>
          ))}
          <span className="ml-auto">{formatTime(incident.createdAt)}</span>
        </div>
      </CardContent>
    </Card>
  );
}

export default function Incidents() {
  const [incidents, setIncidents] = useState(null);
  const [error, setError] = useState("");

  const fetchIncidents = useCallback(async ({ silent = false } = {}) => {
    try {
      const data = await listIncidents();
      const list = [...unwrapList(data)].sort((a, b) =>
        (b.createdAt || "").localeCompare(a.createdAt || ""),
      );
      setIncidents(list);
      setError("");
    } catch (err) {
      if (!silent) setError(err.message || "Failed to load incidents");
    }
  }, []);

  useEffect(() => {
    fetchIncidents();

    const interval = setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchIncidents({ silent: true });
      }
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [fetchIncidents]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-heading text-xl font-semibold">Incidents</h1>
        <p className="text-sm text-muted-foreground">
          What the agent found when your monitors went down, and what it wants to do about it.
        </p>
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      {incidents === null ? (
        !error && (
          <div className="flex flex-col gap-4">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )
      ) : incidents.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="flex flex-col gap-4">
          {incidents.map((incident) => (
            <IncidentRow key={incident.id} incident={incident} />
          ))}
        </div>
      )}
    </div>
  );
}
