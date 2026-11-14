export const CATEGORY_LABELS = {
  timeout: "Timeout",
  dns: "DNS",
  tls: "TLS",
  connection: "Connection",
  server_error: "Server error",
  client_error: "Client error",
  auth: "Auth",
  unknown: "Unknown",
};

export const ACTION_LABELS = {
  pause_monitor: "Pause monitor",
  escalate: "Escalate",
  no_action: "No action",
};

export function categoryLabel(incident) {
  const category = incident?.category || incident?.diagnosis?.category;
  if (!category) return null;
  return CATEGORY_LABELS[category] || category;
}

export function actionLabel(action) {
  return ACTION_LABELS[action] || action;
}

export function formatConfidence(value) {
  if (typeof value !== "number") return null;
  return `${Math.round(value * 100)}%`;
}

export function formatTime(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// The list endpoint may return a bare array or { incidents: [...] }
export function unwrapList(data) {
  if (Array.isArray(data)) return data;
  return data?.incidents || [];
}

export function unwrapIncident(data) {
  return data?.incident || data;
}

export const AUTO_RECOVERY_APPROVER = "system:auto-recovery";

export function isAutoRecovered(incident) {
  return incident?.decision?.approver === AUTO_RECOVERY_APPROVER;
}

export function formatTokens(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return value.toLocaleString();
}
