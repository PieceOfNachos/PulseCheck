import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PlusIcon } from "lucide-react";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const DEFAULT_FORM = {
  name: "",
  url: "",
  method: "GET",
  intervalSeconds: 30,
  timeoutMs: 5000,
  expectedStatusCode: 200,
};

export default function MonitorFormModal({ onCreate }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function update(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  function reset() {
    setForm(DEFAULT_FORM);
    setError("");
  }

  function validate() {
    if (!form.name.trim()) return "Name is required.";
    try {
      new URL(form.url);
    } catch {
      return "Enter a valid URL, e.g. https://api.example.com/health";
    }
    if (form.intervalSeconds < 10 || form.intervalSeconds > 3600)
      return "Interval must be between 10 and 3600 seconds.";
    if (form.timeoutMs < 1000 || form.timeoutMs > 30000)
      return "Timeout must be between 1000 and 30000 ms.";
    return "";
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const clientError = validate();
    if (clientError) {
      setError(clientError);
      return;
    }
    setError("");
    setSubmitting(true);
    try {
      await onCreate({
        ...form,
        intervalSeconds: Number(form.intervalSeconds),
        timeoutMs: Number(form.timeoutMs),
        expectedStatusCode: Number(form.expectedStatusCode),
      });
      setOpen(false);
      reset();
    } catch (err) {
      setError(err.message || "Failed to create monitor");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) reset();
      }}
    >
      <DialogTrigger render={<Button />}>
        <PlusIcon /> Add monitor
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New monitor</DialogTitle>
          <DialogDescription>
            PulseCheck will poll this endpoint on the interval you choose.
          </DialogDescription>
        </DialogHeader>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="m-name">Name</Label>
            <Input
              id="m-name"
              value={form.name}
              onChange={(e) => update("name", e.target.value)}
              placeholder="Production API"
              required
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="m-url">URL</Label>
            <Input
              id="m-url"
              type="url"
              value={form.url}
              onChange={(e) => update("url", e.target.value)}
              placeholder="https://api.example.com/health"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="m-method">Method</Label>
              <Select value={form.method} onValueChange={(v) => update("method", v)}>
                <SelectTrigger id="m-method" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {METHODS.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="m-status">Expected status</Label>
              <Input
                id="m-status"
                type="number"
                value={form.expectedStatusCode}
                onChange={(e) => update("expectedStatusCode", e.target.value)}
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="m-interval">Interval (s)</Label>
              <Input
                id="m-interval"
                type="number"
                min={10}
                max={3600}
                value={form.intervalSeconds}
                onChange={(e) => update("intervalSeconds", e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="m-timeout">Timeout (ms)</Label>
              <Input
                id="m-timeout"
                type="number"
                min={1000}
                max={30000}
                value={form.timeoutMs}
                onChange={(e) => update("timeoutMs", e.target.value)}
              />
            </div>
          </div>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="submit" disabled={submitting}>
              {submitting ? "Creating…" : "Create monitor"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
