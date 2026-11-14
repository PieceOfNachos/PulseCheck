import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { monitorApi } from "@/lib/api";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import MonitorCard from "@/components/MonitorCard";
import MonitorFormModal from "@/components/MonitorFormModal";
import { ActivityIcon } from "lucide-react";

const POLL_INTERVAL_MS = 15_000;

function SkeletonCard() {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-5 w-2/3" />
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-1/2" />
        <Skeleton className="h-8 w-full" />
      </CardContent>
    </Card>
  );
}

function EmptyState({ onCreate }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border py-20 text-center">
      <ActivityIcon className="size-8 text-muted-foreground" />
      <div>
        <p className="font-medium">No monitors yet</p>
        <p className="text-sm text-muted-foreground">
          Create your first monitor to start tracking uptime.
        </p>
      </div>
      <MonitorFormModal onCreate={onCreate} />
    </div>
  );
}

export default function Dashboard() {
  const [monitors, setMonitors] = useState(null);
  const [error, setError] = useState("");

  const fetchMonitors = useCallback(async ({ silent = false } = {}) => {
    try {
      const data = await monitorApi.get("/api/monitors");
      setMonitors(data.monitors);
      setError("");
    } catch (err) {
      if (!silent) setError(err.message || "Failed to load monitors");
    }
  }, []);

  useEffect(() => {
    fetchMonitors();

    const interval = setInterval(() => {
      if (document.visibilityState === "visible") {
        fetchMonitors({ silent: true });
      }
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [fetchMonitors]);

  async function handleCreate(payload) {
    const data = await monitorApi.post("/api/monitors", payload);
    setMonitors((prev) => [data.monitor, ...(prev || [])]);
    toast.success(`Monitor "${data.monitor.name}" created`);
  }

  async function handleToggleActive(monitor) {
    try {
      const data = await monitorApi.put(`/api/monitors/${monitor._id}`, {
        active: !monitor.active,
      });
      setMonitors((prev) =>
        prev.map((m) => (m._id === monitor._id ? { ...m, ...data.monitor } : m)),
      );
    } catch (err) {
      toast.error(err.message || "Failed to update monitor");
    }
  }

  async function handleDelete(monitor) {
    try {
      await monitorApi.delete(`/api/monitors/${monitor._id}`);
      setMonitors((prev) => prev.filter((m) => m._id !== monitor._id));
      toast.success(`Monitor "${monitor.name}" deleted`);
    } catch (err) {
      toast.error(err.message || "Failed to delete monitor");
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-xl font-semibold">Monitors</h1>
          <p className="text-sm text-muted-foreground">
            Live status of your tracked API endpoints.
          </p>
        </div>
        {monitors && monitors.length > 0 && (
          <MonitorFormModal onCreate={handleCreate} />
        )}
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      {monitors === null ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      ) : monitors.length === 0 ? (
        <EmptyState onCreate={handleCreate} />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {monitors.map((monitor) => (
            <MonitorCard
              key={monitor._id}
              monitor={monitor}
              onToggleActive={handleToggleActive}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}
    </div>
  );
}
