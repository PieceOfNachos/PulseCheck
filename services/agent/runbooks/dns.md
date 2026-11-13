# DNS resolution failures

The monitor could not turn the endpoint's hostname into an IP address, so no HTTP request
was ever sent. The service itself may be perfectly healthy.

## Symptoms

- Check fails with `getaddrinfo ENOTFOUND api.example.com` (name does not exist).
- Check fails with `getaddrinfo EAI_AGAIN api.example.com` (resolver timed out or SERVFAIL).
- Latency is near zero or very small: the check never reached the server.
- Often affects every monitor on the same domain at once.

## Likely causes

- Domain expired or registrar suspended it (NXDOMAIN for every record).
- Record deleted or renamed during a DNS change, or a typo in the monitor URL.
- Broken delegation: NS records at the registrar don't match the hosted zone.
- DNSSEC signatures expired or DS record mismatch (validating resolvers return SERVFAIL).
- CNAME points at a load balancer / CDN hostname that was deprovisioned.
- Upstream resolver outage (usually shows as `EAI_AGAIN`, intermittent).

## Diagnose

```bash
# Does the name resolve at all, and through which chain?
dig +short api.example.com
dig api.example.com A +trace

# Compare public resolvers with the authoritative servers
dig @1.1.1.1 api.example.com
dig @8.8.8.8 api.example.com
dig NS example.com +short
dig @<authoritative-ns> api.example.com

# DNSSEC problems: SERVFAIL here but NOERROR with +cd means validation is failing
dig @8.8.8.8 api.example.com +dnssec
dig @8.8.8.8 api.example.com +cd

# Registration status
whois example.com | grep -iE "expir|status"
```

- `status: NXDOMAIN` from the authoritative server → the record really is gone.
- NXDOMAIN only from some resolvers → recent change still propagating; check TTLs.
- `SERVFAIL` → delegation or DNSSEC issue, not the application.

## Remediate

- Restore the missing record from the DNS provider's change history or IaC (`terraform plan`).
- Renew the domain and confirm the registrar lock / hold status is cleared.
- Fix NS delegation at the registrar to match the hosted zone's name servers.
- For CNAME targets, repoint to the current load balancer hostname.
- After the fix, lower TTL temporarily and verify with `dig @1.1.1.1` and `dig @8.8.8.8`.

## When to pause the monitor / escalate

- Pause the monitor if the hostname was intentionally retired or the URL is mistyped;
  otherwise alerts keep firing with nothing to fix on the service side.
- Escalate to whoever owns the domain / DNS provider account if the domain expired,
  delegation is broken, or DNSSEC keys need rolling. These need registrar access.
- Escalate immediately if several domains fail together: likely a provider-wide outage.
