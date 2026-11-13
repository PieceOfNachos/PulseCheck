# TLS and certificate errors

The TCP connection succeeded but the TLS handshake failed, so the monitor refused to
trust the server. Browsers and API clients will be failing the same way.

## Symptoms

- `certificate has expired` / `CERT_HAS_EXPIRED`.
- `unable to verify the first certificate` / `UNABLE_TO_VERIFY_LEAF_SIGNATURE`.
- `self signed certificate in certificate chain` / `SELF_SIGNED_CERT_IN_CHAIN`.
- `Hostname/IP does not match certificate's altnames` / `ERR_TLS_CERT_ALTNAME_INVALID`.
- `EPROTO` or `wrong version number` when TLS is spoken to a plain-HTTP port.

## Likely causes

- Certificate expired because automated renewal (cert-manager, certbot, ACME) failed.
- Server sends only the leaf certificate, without the intermediate chain.
- New certificate issued for the wrong hostname or missing a SAN entry.
- A load balancer or CDN still serves an old certificate after rotation.
- Port mismatch: HTTPS monitor pointed at an HTTP-only listener.

## Diagnose

```bash
# Expiry dates and subject / SANs of what is actually served
echo | openssl s_client -connect api.example.com:443 -servername api.example.com 2>/dev/null \
  | openssl x509 -noout -dates -subject -ext subjectAltName

# Full chain the server presents (look for missing intermediates)
openssl s_client -connect api.example.com:443 -servername api.example.com -showcerts

# Client's view, including the verification error
curl -vI https://api.example.com 2>&1 | grep -iE "expire|issuer|subject|SSL"

# Renewal automation
kubectl get certificate -A
kubectl describe certificate api-tls -n api
journalctl -u certbot --since "3 days ago"
```

- `notAfter` in the past → expired certificate.
- `Verify return code: 21 (unable to verify the first certificate)` → missing chain.

## Remediate

- Renew now: `certbot renew --force-renewal` or delete the cert-manager `CertificateRequest`
  to trigger reissue, then reload the web server / ingress.
- Serve the full chain (`fullchain.pem`, not `cert.pem`).
- Reissue with the correct SANs; update the LB / CDN certificate binding.
- Fix the ACME challenge (DNS record or `/.well-known/acme-challenge/` route) so renewal
  stops failing, and add an expiry alert at 14 days.

## When to pause the monitor / escalate

- Do not pause: an expired certificate is a real, user-facing outage.
- Pause only if the monitor intentionally targets a staging host with a self-signed cert.
- Escalate to the platform team if the certificate lives on a managed LB / CDN or the
  renewal pipeline is broken for more than one domain.
