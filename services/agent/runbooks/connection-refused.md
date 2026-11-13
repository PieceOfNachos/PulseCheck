# Connection refused or reset

The host resolved and is reachable, but nothing accepted the TCP connection on that port,
or the connection was torn down mid-request. The process is down or not listening.

## Symptoms

- `connect ECONNREFUSED 203.0.113.10:443` — the host actively rejected the connection.
- `read ECONNRESET` / `socket hang up` — connection dropped before a response arrived.
- Failures are immediate (very low latency), unlike timeouts.
- Often begins with a restart, deploy, host reboot or scale-to-zero event.

## Likely causes

- Application process crashed or is restarting; nothing bound to the port.
- Service listens on a different port or only on `127.0.0.1` after a config change.
- Load balancer has no registered targets, or the target group port is wrong.
- Container killed for memory (`OOMKilled`) and stuck in `CrashLoopBackOff`.
- Reverse proxy (nginx, envoy) restarted with a bad config and closes connections.

## Diagnose

```bash
# Is anything listening?
nc -vz api.example.com 443
curl -v https://api.example.com/health 2>&1 | grep -iE "connect|refused|reset"

# On the host / container
ss -ltnp | grep -E ":443|:8080"
systemctl status api
journalctl -u api --since "30 min ago" | tail -50

# Kubernetes
kubectl get pods -n api -o wide
kubectl get endpoints api -n api
kubectl describe pod <pod> -n api | grep -iE "OOMKilled|Back-off|Exit Code"
kubectl logs <pod> -n api --previous
```

- Empty `kubectl get endpoints` → no ready pods behind the service.
- `--previous` logs show the crash reason of the last container instance.

## Remediate

- Restart the service: `systemctl restart api` or `kubectl rollout restart deploy/api -n api`.
- Roll back if crashes started with the latest release.
- Fix the bind address / port in config (`0.0.0.0:8080`) and the LB target port.
- Raise memory limits if the container is being `OOMKilled`.
- Validate proxy config before reload (`nginx -t`, `envoy --mode validate`).

## When to pause the monitor / escalate

- Pause only if the host was intentionally decommissioned or scaled to zero.
- Escalate to the service owner if the process will not stay up after a restart.
- Escalate to the platform team if the host itself is unreachable or rebooting repeatedly.
