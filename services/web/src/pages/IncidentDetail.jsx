import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { approveIncident, getIncident, rejectIncident } from "@/lib/api";
import {
  actionLabel,
  categoryLabel,
  formatConfidence,
  formatTime,
  formatTokens,
  isAutoRecovered,
  unwrapIncident,
} from "@/lib/incidents";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import IncidentStatusBadge from "@/components/IncidentStatusBadge";
import { cn } from "@/lib/utils";
import {
  ArrowLeftIcon,
  BookOpenIcon,
  CheckIcon,
  ChevronDownIcon,
  CircleCheckIcon,
  CircleXIcon,
  CpuIcon,
  RotateCcwIcon,
  SearchIcon,
  ShieldCheckIcon,
  ShieldXIcon,
  TriangleAlertIcon,
  UserCheckIcon,
  XIcon,
} from "lucide-react";

const POLL_INTERVAL_MS = 15_000;
// Envelope fields of an audit entry; the interesting payload lives in entry.data.
const AUDIT_HIDDEN_KEYS = new Set([
  "_id",
  "id",
  "incident_id",
  "user_id",
  "event",
  "at",
  "seq",
  "data",
]);
const AUDIT_VALUE_MAX = 80;
const AUDIT_KEY_LABELS = {
  duration_ms: "duration",
  tokens: "tokens",
  tokens_used: "tokens",
};

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isLowConfidenceReason(reason) {
  return typeof reason === "string" && reason.trim().toLowerCase().startsWith("low confidence");
}

function Section({ title, description, action, children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
        {action && <CardAction>{action}</CardAction>}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">{children}</CardContent>
    </Card>
  );
}

function Muted({ children }) {
  return <p className="text-sm text-muted-foreground">{children}</p>;
}

function DetailSkeleton() {
  return (
    <div className="flex flex-col gap-4">
      <Skeleton className="h-7 w-1/3" />
      <Skeleton className="h-4 w-1/2" />
      {Array.from({ length: 3 }).map((_, i) => (
        <Card key={i}>
          <CardHeader>
            <Skeleton className="h-5 w-1/4" />
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-2/3" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function VerificationNote({ verification }) {
  if (!isPlainObject(verification)) return null;

  const dropped = Array.isArray(verification.dropped_citations)
    ? verification.dropped_citations.filter(Boolean)
    : [];
  const grounded = verification.grounded === true && dropped.length === 0;
  const ungrounded = dropped.length > 0 || verification.grounded === false;

  return (
    <>
      {grounded && (
        <p className="flex items-center gap-1.5 text-sm text-emerald-600 dark:text-emerald-400">
          <ShieldCheckIcon className="size-4 shrink-0" /> Grounded in runbooks
        </p>
      )}
      {ungrounded && (
        <div className="flex flex-col gap-1.5">
          <p className="flex items-center gap-1.5 text-sm text-amber-600 dark:text-amber-400">
            <TriangleAlertIcon className="size-4 shrink-0" />
            {dropped.length > 0 ? "Ungrounded citations removed" : "Not grounded in runbooks"}
          </p>
          {dropped.length > 0 && (
            <div className="flex flex-wrap gap-2 pl-5.5">
              {dropped.map((source) => (
                <Badge
                  key={source}
                  variant="outline"
                  className="border-amber-500/40 text-muted-foreground line-through"
                >
                  {String(source)}
                </Badge>
              ))}
            </div>
          )}
        </div>
      )}
      {verification.low_confidence === true && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-400">
          <TriangleAlertIcon className="mt-0.5 size-4 shrink-0" />
          Low confidence — destructive actions held back
        </div>
      )}
    </>
  );
}

function DiagnosisSection({ incident }) {
  const diagnosis = incident.diagnosis;
  const verification = incident.verification ?? diagnosis?.verification;
  const category = categoryLabel(incident);
  const confidence = formatConfidence(diagnosis?.confidence);

  return (
    <Section
      title="Diagnosis"
      action={category && <Badge variant="secondary">{category}</Badge>}
    >
      {!diagnosis ? (
        <Muted>
          {incident.status === "INVESTIGATING"
            ? "The agent is still investigating."
            : "No diagnosis was produced."}
        </Muted>
      ) : (
        <>
          <p>{diagnosis.root_cause}</p>
          {confidence && (
            <div className="flex items-center gap-3">
              <div className="h-1.5 w-32 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary"
                  style={{ width: confidence }}
                />
              </div>
              <span className="text-sm text-muted-foreground">{confidence} confidence</span>
            </div>
          )}
          {diagnosis.evidence?.length > 0 && (
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-muted-foreground">
              {diagnosis.evidence.map((item, i) => (
                <li key={i}>{item}</li>
              ))}
            </ul>
          )}
          {diagnosis.cited_sources?.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm text-muted-foreground">Sources:</span>
              {diagnosis.cited_sources.map((source) => (
                <Badge key={source} variant="outline" className="text-muted-foreground">
                  <BookOpenIcon /> {source}
                </Badge>
              ))}
            </div>
          )}
          <VerificationNote verification={verification} />
        </>
      )}
    </Section>
  );
}

function EvidenceSection({ evidence }) {
  return (
    <Section title="Evidence" description="What the investigator checked.">
      {evidence.length === 0 ? (
        <Muted>No evidence collected yet.</Muted>
      ) : (
        <ul className="flex flex-col divide-y divide-border">
          {evidence.map((item, i) => (
            <li key={i} className="flex items-start gap-3 py-2 first:pt-0 last:pb-0">
              <Badge variant="secondary" className="mt-0.5 font-mono">
                <SearchIcon /> {item.tool}
              </Badge>
              <span className="text-sm">{item.summary}</span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function RunbooksSection({ retrieved }) {
  return (
    <Section title="Runbooks consulted" description="Retrieved from runbooks and past incidents.">
      {retrieved.length === 0 ? (
        <Muted>Nothing retrieved.</Muted>
      ) : (
        <ul className="flex flex-col divide-y divide-border">
          {retrieved.map((doc, i) => (
            <li
              key={`${doc.source}-${i}`}
              className="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{doc.title}</p>
                <p className="truncate font-mono text-xs text-muted-foreground">
                  {doc.source}
                </p>
              </div>
              {typeof doc.score === "number" && (
                <span className="shrink-0 text-xs text-muted-foreground">
                  {doc.score.toFixed(2)}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function DecisionLine({ incident }) {
  const decision = incident.decision;

  if (isAutoRecovered(incident)) {
    return (
      <p className="flex items-center gap-1.5 text-sm text-emerald-600 dark:text-emerald-400">
        <RotateCcwIcon className="size-4 shrink-0" />
        Auto-closed: monitor recovered before approval — no actions taken
      </p>
    );
  }

  if (!decision?.approver) return null;

  return (
    <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
      <UserCheckIcon className="size-4 shrink-0" />
      {decision.approved ? "Approved" : "Rejected"} by{" "}
      <span className="truncate font-mono text-xs">{decision.approver}</span>
    </p>
  );
}

function ActionsSection({ incident, onRefresh }) {
  const proposed = incident.proposed_actions || [];
  const blocked = incident.rejected_actions || [];
  const awaiting = incident.status === "AWAITING_APPROVAL";
  const decided = incident.decision?.actions || [];

  // Track what the user unticked, so every proposal starts checked and polling
  // doesn't wipe their choices.
  const [unchecked, setUnchecked] = useState(() => new Set());
  const [busy, setBusy] = useState(false);
  const [approveOpen, setApproveOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);

  const selected = [...new Set(proposed.map((a) => a.action))].filter(
    (action) => !unchecked.has(action),
  );

  function toggle(action) {
    setUnchecked((prev) => {
      const next = new Set(prev);
      if (next.has(action)) next.delete(action);
      else next.add(action);
      return next;
    });
  }

  async function handleApprove() {
    setBusy(true);
    try {
      await approveIncident(incident.id, selected);
      toast.success(
        `Approved ${selected.length} action${selected.length === 1 ? "" : "s"}`,
      );
      await onRefresh();
    } catch (err) {
      toast.error(err.message || "Failed to approve incident");
    } finally {
      setBusy(false);
      setApproveOpen(false);
    }
  }

  async function handleReject() {
    setBusy(true);
    try {
      await rejectIncident(incident.id);
      toast.success("Rejected — no actions will run");
      await onRefresh();
    } catch (err) {
      toast.error(err.message || "Failed to reject incident");
    } finally {
      setBusy(false);
      setRejectOpen(false);
    }
  }

  return (
    <Section
      title="Proposed actions"
      description={
        awaiting
          ? "Nothing runs until you approve. Untick anything you don't want."
          : undefined
      }
    >
      {proposed.length === 0 ? (
        <Muted>No actions proposed.</Muted>
      ) : (
        <ul className="flex flex-col gap-2">
          {proposed.map((item, i) => {
            const checked = awaiting ? !unchecked.has(item.action) : decided.includes(item.action);
            return (
              <li key={`${item.action}-${i}`}>
                <label
                  className={cn(
                    "flex items-start gap-3 rounded-lg border border-border p-3",
                    awaiting && "cursor-pointer hover:bg-muted/50",
                  )}
                >
                  <input
                    type="checkbox"
                    className="mt-0.5 size-4 shrink-0 cursor-pointer accent-primary disabled:cursor-default"
                    checked={checked}
                    disabled={!awaiting || busy}
                    onChange={() => toggle(item.action)}
                  />
                  <div className="flex min-w-0 flex-col gap-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{actionLabel(item.action)}</span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {item.action}
                      </span>
                      {!awaiting && incident.decision && (
                        <Badge variant={checked ? "secondary" : "outline"}>
                          {checked ? "Approved" : "Skipped"}
                        </Badge>
                      )}
                    </div>
                    <span className="text-sm text-muted-foreground">{item.reason}</span>
                  </div>
                </label>
              </li>
            );
          })}
        </ul>
      )}

      {incident.decision && <DecisionLine incident={incident} />}

      {blocked.length > 0 && (
        <div className="flex flex-col gap-2 rounded-lg border border-dashed border-border p-3">
          <p className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground uppercase">
            <ShieldXIcon className="size-3.5" /> Blocked by policy
          </p>
          <ul className="flex flex-col gap-1.5">
            {blocked.map((item, i) => (
              <li
                key={`${item.action}-${i}`}
                className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground"
              >
                <span className="font-mono line-through opacity-70">{item.action}</span>
                {isLowConfidenceReason(item.reason) && (
                  <Badge
                    variant="outline"
                    className="border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400"
                  >
                    Low confidence
                  </Badge>
                )}
                {item.reason && <span>{item.reason}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {awaiting && (
        <div className="flex items-center justify-end gap-2 pt-1">
          <AlertDialog open={rejectOpen} onOpenChange={setRejectOpen}>
            <AlertDialogTrigger render={<Button variant="outline" disabled={busy} />}>
              <XIcon /> Reject
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Reject all proposed actions?</AlertDialogTitle>
                <AlertDialogDescription>
                  The diagnosis is kept, but nothing will run for this incident.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
                <AlertDialogAction variant="destructive" disabled={busy} onClick={handleReject}>
                  Reject
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>

          <AlertDialog open={approveOpen} onOpenChange={setApproveOpen}>
            <AlertDialogTrigger
              render={<Button disabled={busy || selected.length === 0} />}
            >
              <CheckIcon /> Approve selected
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  Run {selected.length} action{selected.length === 1 ? "" : "s"}?
                </AlertDialogTitle>
                <AlertDialogDescription>
                  {selected.map(actionLabel).join(", ")} will run against "
                  {incident.monitorName}".
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
                <AlertDialogAction disabled={busy} onClick={handleApprove}>
                  Approve
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      )}
    </Section>
  );
}

function ResultsSection({ results }) {
  return (
    <Section title="Results">
      <ul className="flex flex-col gap-2">
        {results.map((result, i) => (
          <li key={`${result.action}-${i}`} className="flex items-start gap-2 text-sm">
            {result.ok ? (
              <CircleCheckIcon className="mt-0.5 size-4 shrink-0 text-emerald-500" />
            ) : (
              <CircleXIcon className="mt-0.5 size-4 shrink-0 text-red-500" />
            )}
            <span>
              <span className="font-medium">{actionLabel(result.action)}</span>
              {result.detail && (
                <span className="text-muted-foreground"> — {result.detail}</span>
              )}
            </span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function stringifyCompact(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function formatAuditValue(key, value) {
  if (key === "duration_ms" && typeof value === "number") {
    return `${Math.round(value).toLocaleString()} ms`;
  }
  if ((key === "tokens" || key === "tokens_used") && typeof value === "number") {
    return value.toLocaleString();
  }
  if (key === "tool" && isPlainObject(value)) {
    return String(value.name ?? value.tool ?? stringifyCompact(value));
  }
  if (Array.isArray(value)) {
    return value.every((v) => v === null || typeof v !== "object")
      ? value.join(", ")
      : stringifyCompact(value);
  }
  if (isPlainObject(value)) return stringifyCompact(value);
  return String(value);
}

// Entries are {incident_id, user_id, event, at, seq, data}; older rows may be flat.
function auditFields(entry) {
  const payload = isPlainObject(entry.data)
    ? entry.data
    : Object.fromEntries(Object.entries(entry).filter(([key]) => !AUDIT_HIDDEN_KEYS.has(key)));

  return Object.entries(payload)
    .filter(([, value]) => value != null && value !== "" && !(Array.isArray(value) && value.length === 0))
    .map(([key, value]) => {
      const full = formatAuditValue(key, value);
      const short =
        full.length > AUDIT_VALUE_MAX ? `${full.slice(0, AUDIT_VALUE_MAX)}…` : full;
      return {
        key,
        label: AUDIT_KEY_LABELS[key] || key,
        value: short,
        title: full,
      };
    });
}

function AuditTrail({ audit }) {
  const [open, setOpen] = useState(false);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Audit trail</CardTitle>
        <CardDescription>
          {audit.length} event{audit.length === 1 ? "" : "s"}
        </CardDescription>
        <CardAction>
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={open}
            disabled={audit.length === 0}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Hide" : "Show"}
            <ChevronDownIcon className={cn("transition-transform", open && "rotate-180")} />
          </Button>
        </CardAction>
      </CardHeader>
      {open && (
        <CardContent>
          <ol className="flex flex-col divide-y divide-border">
            {audit.map((entry, i) => {
              const fields = auditFields(entry);
              return (
                <li
                  key={entry.seq ?? i}
                  className="flex flex-col gap-1.5 py-2 first:pt-0 last:pb-0"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-mono text-sm">{entry.event}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {formatTime(entry.at)}
                    </span>
                  </div>
                  {fields.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {fields.map((field) => (
                        <span
                          key={field.key}
                          title={field.title}
                          className="inline-flex max-w-full items-center gap-1 rounded-md border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-xs"
                        >
                          <span className="shrink-0 text-muted-foreground">{field.label}:</span>
                          <span className="truncate">{field.value}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
        </CardContent>
      )}
    </Card>
  );
}

export default function IncidentDetail() {
  const { id } = useParams();
  const [incident, setIncident] = useState(null);
  const [error, setError] = useState("");
  const tokens = formatTokens(incident?.tokens_used);

  const fetchIncident = useCallback(
    async ({ silent = false } = {}) => {
      try {
        const data = await getIncident(id);
        setIncident(unwrapIncident(data));
        setError("");
      } catch (err) {
        if (!silent) setError(err.message || "Failed to load incident");
      }
    },
    [id],
  );

  useEffect(() => {
    fetchIncident();

    const interval = setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchIncident({ silent: true });
      }
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [fetchIncident]);

  return (
    <div className="flex flex-col gap-6">
      <Link
        to="/incidents"
        className="flex w-fit items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeftIcon className="size-4" /> All incidents
      </Link>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      {!incident ? (
        !error && <DetailSkeleton />
      ) : (
        <>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <h1 className="truncate font-heading text-xl font-semibold">
                {incident.monitorName}
              </h1>
              <p className="truncate text-sm text-muted-foreground" title={incident.monitorUrl}>
                {incident.monitorUrl}
              </p>
              <p className="text-xs text-muted-foreground">
                Opened {formatTime(incident.createdAt)} · updated{" "}
                {formatTime(incident.updatedAt)}
              </p>
            </div>
            <div className="flex flex-col items-end gap-1.5">
              <IncidentStatusBadge status={incident.status} />
              {tokens && (
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <CpuIcon className="size-3.5" /> Model usage: {tokens} tokens
                </span>
              )}
            </div>
          </div>

          {incident.error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-600 dark:text-red-400"
            >
              <TriangleAlertIcon className="mt-0.5 size-4 shrink-0" />
              {incident.error}
            </div>
          )}

          <DiagnosisSection incident={incident} />

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <EvidenceSection evidence={incident.evidence || []} />
            <RunbooksSection retrieved={incident.retrieved || []} />
          </div>

          <ActionsSection key={incident.id} incident={incident} onRefresh={fetchIncident} />

          {incident.results?.length > 0 && <ResultsSection results={incident.results} />}

          <AuditTrail audit={incident.audit || []} />
        </>
      )}
    </div>
  );
}
