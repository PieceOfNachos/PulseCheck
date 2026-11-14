# Not found (404) after a deploy or routing change

The server is reachable and healthy enough to answer, but the monitored path no longer
exists. Almost always a route, ingress or base-path change shipped in a recent deploy.

## Symptoms

- `Expected 200, got 404` — Not Found on a path that previously returned 200.
- Starts right after a release, ingress update, or CDN / gateway configuration change.
- Other paths on the same host still respond normally.
- Body is a framework or proxy default page (e.g. nginx "404 Not Found", `Cannot GET /health`).

## Likely causes

- Route renamed or versioned (`/health` → `/api/v2/health`) without a redirect.
- Ingress `path` / `pathType` or rewrite annotation changed, stripping a prefix.
- Service deployed under a new base path or behind a different host name.
- Static site deploy missing files, or the CDN still points at an old bucket / origin.
- Blue/green switch sent traffic to an environment without the route.

## Diagnose

```bash
curl -si https://api.example.com/health | head -15
curl -si https://api.example.com/api/v2/health | head -5

# What changed recently?
kubectl rollout history deploy/api -n api
kubectl get ingress -n api -o yaml | grep -A6 "paths:"
git log --oneline --since="1 day ago" -- routes/ ingress/ k8s/

# Which routes does the running app expose?
kubectl logs deploy/api -n api --since=10m | grep -iE "route|mapped|listening"
```

- 404 from nginx / the ingress (not the app) → ingress rule or rewrite issue.
- 404 from the app framework → route removed or renamed in code.

## Remediate

- Roll back the deploy or ingress change: `kubectl rollout undo deploy/api -n api`.
- Restore the old route, or add a permanent redirect from the old path.
- Fix the ingress path / rewrite annotation and re-apply.
- If the move was intentional, update the monitor URL to the new path.

## When to pause the monitor / escalate

- Pause the monitor if the endpoint was intentionally removed or moved and the monitor
  just needs a new URL; there is no outage to chase.
- Escalate to the team that shipped the deploy if public clients depend on the old path.
