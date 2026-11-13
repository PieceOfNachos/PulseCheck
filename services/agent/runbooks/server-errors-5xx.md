# Server errors (HTTP 5xx)

The server answered, but with a 5xx status. Something behind the edge is failing:
the application, a dependency, or the proxy in front of it.

## Symptoms

- `Expected 200, got 500` — Internal Server Error, unhandled exception in the app.
- `Expected 200, got 502` — Bad Gateway, proxy could not get a valid response upstream.
- `Expected 200, got 503` — Service Unavailable, no healthy backends or app in maintenance.
- `Expected 200, got 504` — Gateway Timeout, upstream took too long.
- Response arrives quickly (low latency), unlike a timeout.

## Likely causes

- Bad deploy: new release crashes on a code path or is missing config / secrets.
- Pods in `CrashLoopBackOff` or failing readiness probes, so the LB has no healthy targets (503).
- Database or cache unavailable, connection pool exhausted, failed migration.
- Upstream third-party API outage propagating as 502 / 504.
- Out-of-memory kills (`OOMKilled`) under load.

## Diagnose

```bash
curl -sv https://api.example.com/health -o /dev/null 2>&1 | grep -E "^< HTTP|^< server|^< retry-after"

kubectl get pods -n api
kubectl describe pod <pod> -n api | grep -A5 "Last State"
kubectl logs deploy/api -n api --since=15m | grep -iE "error|exception|fatal"
kubectl rollout history deploy/api -n api

# Ingress / proxy view of the failures
kubectl logs -n ingress-nginx deploy/ingress-nginx-controller --since=15m | grep " 50[234] "
```

- 503 with zero ready pods → readiness or crash problem, look at pod events.
- 502 from nginx with "upstream prematurely closed" → app crashing mid-request.
- 500 with a stack trace in app logs → code or data bug; correlate with deploy time.

## Remediate

- Roll back the last deploy: `kubectl rollout undo deploy/api -n api`.
- Restore missing config / secrets and restart: `kubectl rollout restart deploy/api -n api`.
- Restart or fail over the database / cache; raise the pool size if it is exhausted.
- Raise memory limits for `OOMKilled` pods, then investigate the leak.
- For an upstream outage, enable the fallback / circuit breaker and check their status page.

## When to pause the monitor / escalate

- Pause only for announced maintenance that returns 503 on purpose.
- Escalate to the on-call owner of the service for any sustained 5xx: it is user-facing.
- Escalate to the database / platform team when pods are healthy but dependencies fail.
