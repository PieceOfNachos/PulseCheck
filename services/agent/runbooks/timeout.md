# Request timeouts

The monitor connected (or tried to) but got no complete response within its timeout.
The server is slow, overloaded, or a network path is silently dropping packets.

## Symptoms

- Check fails with `timeout of 5000ms exceeded` and code `ECONNABORTED`.
- Check fails with `connect ETIMEDOUT 203.0.113.10:443` (TCP handshake never completed).
- Recorded latency sits right at the monitor's timeout value.
- Preceding checks show latency creeping up before the first failure.

## Likely causes

- Application saturated: thread/worker pool exhausted, long GC pauses, CPU throttling.
- Slow dependency: database lock contention, slow queries, an upstream API hanging.
- Autoscaling lag after a traffic spike; new instances not yet healthy.
- Firewall / security group change dropping packets (shows as `ETIMEDOUT`, not refused).
- Load balancer idle timeout shorter than the request duration.

## Diagnose

```bash
# Where is the time going? DNS, connect, TLS, first byte
curl -o /dev/null -s -w 'dns=%{time_namelookup} connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total}\n' https://api.example.com/health

# Is the port reachable at all?
nc -vz -w 5 api.example.com 443

# Application side
kubectl top pods -n api
kubectl logs deploy/api -n api --since=15m | grep -iE "timeout|slow|pool"
kubectl get hpa -n api
```

- `connect` is slow or never completes → network / firewall / LB problem.
- `connect` fast but `ttfb` huge → the application or its dependencies are slow.
- Check database slow-query logs and connection pool metrics for the same window.

## Remediate

- Scale out the service (`kubectl scale deploy/api --replicas=N`) if CPU or pool is pegged.
- Kill or roll back the long-running query / migration holding locks.
- Roll back the most recent deploy if latency rose right after it.
- Revert the firewall or security group change if the TCP connect is timing out.
- If the endpoint is legitimately slow, raise the monitor timeout rather than paging on it.

## When to pause the monitor / escalate

- Pause only during planned maintenance or a known, already-tracked degradation.
- Escalate to the service owner if timeouts persist for more than 10 minutes or
  latency keeps climbing: a saturated service can tip into a full outage.
- Escalate to the network / platform team when `ETIMEDOUT` happens on connect.
