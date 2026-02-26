import http from "k6/http";
import { check, fail } from "k6";

/**
 *  k6 BENCHMARK SCRIPT
 * -----------------------------------
 * Executor: constant-arrival-rate
 * Rate: 1000 requests per second
 * Target: /api/monitors (Authenticated GET)
 */

export const options = {
  scenarios: {
    api_load_test: {
      executor: "constant-arrival-rate",
      rate: 1000,
      timeUnit: "1s",
      duration: "2m",
      preAllocatedVUs: 300,
      maxVUs: 1000,
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<120"], // 95% of requests must be under 120ms
    http_req_failed: ["rate<0.01"], // Error rate must be under 1%
  },
};

const AUTH_URL = "http://host.docker.internal:3001/api/auth";
const MONITORING_URL = "http://host.docker.internal:3002/api/monitors";

/**
 * Setup function runs once before the load test.
 * We authenticate the benchmarker user and get the JWT.
 */
export function setup() {
  const credentials = {
    email: `benchmark_${Date.now()}@test.com`,
    password: "Benchmark123!",
  };

  // 1. Register a new benchmark user
  const regRes = http.post(
    `${AUTH_URL}/register`,
    JSON.stringify(credentials),
    {
      headers: { "Content-Type": "application/json" },
    },
  );

  if (regRes.status !== 201 && regRes.status !== 409) {
    fail(`Setup failed: Unable to register user (Status: ${regRes.status})`);
  }

  // 2. Login to get the JWT
  const loginRes = http.post(`${AUTH_URL}/login`, JSON.stringify(credentials), {
    headers: { "Content-Type": "application/json" },
  });

  if (loginRes.status !== 200) {
    fail(`Setup failed: Unable to login (Status: ${loginRes.status})`);
  }

  const token = loginRes.json().token;
  if (!token) {
    fail("Setup failed: No token received in login response");
  }

  console.log(`[Setup] Benchmarker authenticated successfully.`);
  return { token };
}

/**
 * Main function runs for every iteration.
 * No sleep() added as per requirements.
 */
export default function (data) {
  const params = {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${data.token}`,
    },
  };

  const res = http.get(MONITORING_URL, params);

  check(res, {
    "status is 200": (r) => r.status === 200,
    "response has monitors": (r) => r.json().monitors !== undefined,
  });
}
