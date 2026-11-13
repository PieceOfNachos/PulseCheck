import { useNavigate } from "react-router-dom";
import { useState } from "react";
import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import StatusBadge from "@/components/StatusBadge";
import { PauseIcon, PlayIcon, Trash2Icon } from "lucide-react";

export default function MonitorCard({ monitor, onToggleActive, onDelete }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  async function handleToggle(e) {
    e.stopPropagation();
    setBusy(true);
    try {
      await onToggleActive(monitor);
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    setBusy(true);
    try {
      await onDelete(monitor);
    } finally {
      setBusy(false);
      setDeleteOpen(false);
    }
  }

  return (
    <Card
      className="cursor-pointer transition-colors hover:ring-foreground/20"
      onClick={() => navigate(`/monitors/${monitor._id}`)}
    >
      <CardHeader>
        <CardTitle className="truncate">{monitor.name}</CardTitle>
        <CardAction>
          <StatusBadge active={monitor.active} lastStatus={monitor.lastStatus} />
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Badge variant="secondary" className="shrink-0">
            {monitor.method || "GET"}
          </Badge>
          <span className="truncate" title={monitor.url}>
            {monitor.url}
          </span>
        </div>
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>
            {monitor.lastLatencyMs != null ? `${monitor.lastLatencyMs} ms` : "No checks yet"}
          </span>
          <span>every {monitor.intervalSeconds}s</span>
        </div>
        <div className="flex items-center justify-end gap-2 pt-1" onClick={(e) => e.stopPropagation()}>
          <Button variant="outline" size="sm" disabled={busy} onClick={handleToggle}>
            {monitor.active ? (
              <>
                <PauseIcon /> Pause
              </>
            ) : (
              <>
                <PlayIcon /> Resume
              </>
            )}
          </Button>
          <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
            <AlertDialogTrigger render={<Button variant="destructive" size="sm" />}>
              <Trash2Icon /> Delete
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete "{monitor.name}"?</AlertDialogTitle>
                <AlertDialogDescription>
                  This permanently deletes the monitor and all of its check history. This
                  can't be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  variant="destructive"
                  disabled={busy}
                  onClick={handleDelete}
                >
                  Delete
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </CardContent>
    </Card>
  );
}
