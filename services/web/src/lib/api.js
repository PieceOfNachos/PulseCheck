const BASE_URLS = {
  auth: import.meta.env.VITE_AUTH_URL || "http://localhost:3001",
  monitoring: import.meta.env.VITE_MONITORING_URL || "http://localhost:3002",
  notification:
    import.meta.env.VITE_NOTIFICATION_URL || "http://localhost:3003",
};

const TOKEN_KEY = "pulsecheck_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

// ProtectedRoute (Phase 2) listens for this to redirect on an expired/invalid token.
function dispatchUnauthorized() {
  window.dispatchEvent(new Event("pulsecheck:unauthorized"));
}

async function request(base, path, options = {}) {
  const token = getToken();
  const headers = { ...options.headers };
  if (options.body) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${base}${path}`, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    dispatchUnauthorized();
  }

  const isJson = res.headers.get("content-type")?.includes("application/json");
  const data = isJson ? await res.json() : null;

  if (!res.ok) {
    throw new Error(data?.error || res.statusText || "Request failed");
  }

  return data;
}

function makeApi(base) {
  return {
    get: (path) => request(base, path, { method: "GET" }),
    post: (path, body) =>
      request(base, path, { method: "POST", body: JSON.stringify(body) }),
    put: (path, body) =>
      request(base, path, { method: "PUT", body: JSON.stringify(body) }),
    delete: (path) => request(base, path, { method: "DELETE" }),
  };
}

export const authApi = makeApi(BASE_URLS.auth);
export const monitorApi = makeApi(BASE_URLS.monitoring);
export const notifyApi = makeApi(BASE_URLS.notification);
