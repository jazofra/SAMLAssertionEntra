# entra-acs-audit

Read-only audit of Entra ID reply URLs and SAML ACS allowlists, looking for conditions that let an attacker receive a SAML assertion or OAuth authorization code intended for someone else.

## Why this exists

Entra ID does not validate AuthnRequest signatures unless *Require verification certificates* is enabled on the application. Requestor verification is provided **solely** by the reply URL allowlist: Entra honours the `AssertionConsumerServiceURL` sent in an AuthnRequest as long as it exactly matches a registered reply URL, and returns `AADSTS50011` otherwise. That check happens *after* the user has authenticated.

Two things follow:

1. `AuthnRequestsSigned="false"` on the SP is, by itself, not exploitable against Entra. Reports demonstrating that "the login page rendered with no error" and that the injected URL appears in `sCtx` prove nothing — that is expected behaviour, and validation has not run yet.
2. The allowlist is only as strong as your control over every host on it. A registered reply URL whose DNS is dangling, or whose host lives in a claimable third-party namespace, is an assertion-delivery endpoint for whoever claims the name. No misconfiguration in Entra required.

The stolen artifact is **post-authentication**, so phishing-resistant MFA, device compliance and Conditional Access do not mitigate any of this. Prevention lives in the allowlist, in signed-request enforcement, and in SP-side replay controls.

## Install

```bash
pip install -r requirements.txt
```

`dnspython` is optional but recommended — without it the tool falls back to basic resolution and cannot follow CNAME chains into claimable namespaces.

## Usage

```bash
# interactive, delegated
python acs_audit.py --tenant contoso.onmicrosoft.com --device-code -v

# app-only
python acs_audit.py --tenant <tenant-id> \
  --client-id <id> --client-secret <secret> \
  --out-json findings.json --out-csv findings.csv

# bring your own token
GRAPH_TOKEN=eyJ0... python acs_audit.py --tenant <tenant-id>

# CI gate
python acs_audit.py --tenant <tenant-id> --client-id ... --client-secret ... \
  --skip-dns --fail-on HIGH
```

Required Graph permissions, both read-only: `Application.Read.All`, `Directory.Read.All`.

The tool issues `GET` requests only. It never writes to the directory.

### Answering a specific report: "which of my apps would accept this URL?"

When a report hands you the injected ACS URL an attacker used (e.g.
`https://attacker.oast.me/saml/acs`), pass it with `--check-acs-url` to test it
against every app's reply-URL allowlist — the exact-match check Entra actually
performs after authentication. The flag is repeatable and accepts
comma-separated values. Any app that would deliver an assertion to that URL is
flagged `ACS_URL_ACCEPTED` (CRITICAL); if nothing matches, Entra would return
`AADSTS50011` and the tool says so.

```bash
python acs_audit.py --tenant <tenant-id> --device-code \
  --check-acs-url "https://attacker.oast.me/saml/acs" \
  --check-acs-url "https://sp.example.com/portal/Shibboleth.sso/SAML2/POST"
```

Add `--saml-only` to restrict the whole report to SAML-capable apps.

### Running offline, without tenant credentials

If you cannot get an app registration or a delegated token, export the two
Graph collections to a JSON file and analyse them with `--from-dump` — no
network and no credentials are needed (add `--skip-dns` to stay fully offline).
A worked example is in [`examples/sample_dump.json`](examples/sample_dump.json),
which mirrors a two-SP Shibboleth SAML scenario using fictional hosts:

```bash
python acs_audit.py --from-dump examples/sample_dump.json --skip-dns \
  --check-acs-url "https://sp.example.com/portal/Shibboleth.sso/SAML2/POST"
```

The dump is a JSON object with two arrays of **raw** Graph objects:

```jsonc
{
  "tenantId": "<optional>",
  "verifiedDomains": ["contoso.com"],          // optional ownership baseline
  "servicePrincipals": [ /* GET /servicePrincipals value[] */ ],
  "applications":      [ /* GET /applications value[] */ ]
}
```

Export the two collections however you like. The simplest is to let the tool do
it and then re-read it offline — `--out-json findings.json` is a *report*, not a
dump, so use a small helper that follows `@odata.nextLink` (a single Graph page
is only 999 objects; a raw `$top=999` call silently drops the rest of a large
tenant). Save as `export_dump.py` and run it with the same auth as the audit:

```python
# export_dump.py - writes dump.json for `acs_audit.py --from-dump dump.json`
import json, os, requests
TOKEN = os.environ["GRAPH_TOKEN"]                      # a Graph access token
G = "https://graph.microsoft.com/v1.0"
H = {"Authorization": f"Bearer {TOKEN}"}

def collect(path):
    items, url = [], G + path
    while url:
        r = requests.get(url, headers=H, timeout=60); r.raise_for_status()
        d = r.json(); items += d.get("value", []); url = d.get("@odata.nextLink")
    return items

json.dump({
    "servicePrincipals": collect("/servicePrincipals?$select=id,appId,displayName,"
        "replyUrls,preferredSingleSignOnMode,accountEnabled,servicePrincipalType,"
        "appOwnerOrganizationId,tags,preferredTokenSigningKeyThumbprint&$top=999"),
    "applications": collect("/applications?$select=id,appId,displayName,web,spa,"
        "publicClient,keyCredentials,identifierUris,signInAudience,"
        "requestSignatureVerification&$top=999"),
}, open("dump.json", "w"), indent=2)
print("wrote dump.json")
```

```powershell
# PowerShell: get a token with the Azure CLI, then export and analyse offline
$env:GRAPH_TOKEN = (az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
python .\export_dump.py
python .\acs_audit.py --from-dump dump.json
```

### Useful flags

| Flag | Effect |
|---|---|
| `--check-acs-url URL` | Test an injected ACS URL against every app's allowlist; repeatable and comma-separated. Matches are flagged `ACS_URL_ACCEPTED` (CRITICAL) |
| `--from-dump FILE` | Analyse a pre-exported Graph JSON offline; no tenant, no credentials |
| `--saml-only` | Restrict the report to SAML-capable apps |
| `--owned-domains a.com,b.com` | Override the ownership baseline; defaults to the tenant's verified domains |
| `--skip-dns` | Skip resolution (fast pass, or for air-gapped/egress-restricted runs) |
| `--include-clean` | Emit apps with no findings, for full inventory |
| `--quiet-info` | Suppress LOW/INFO in console output |
| `--fail-on SEVERITY` | Exit 2 if anything at or above that severity is found |
| `--proxy URL` | Route Graph **and sign-in** through an HTTP(S) proxy (overrides `HTTPS_PROXY`) |
| `--ca-bundle PATH` | Trust this CA bundle for both Graph and sign-in (overrides `REQUESTS_CA_BUNDLE`) |

Either `--tenant` or `--from-dump` is required.

### Behind a corporate proxy / firewall

If authentication succeeds but the first Graph call dies with
`RemoteDisconnected` / `Connection aborted`, a proxy, firewall or TLS-inspection
appliance is between you and `graph.microsoft.com`. The tool now retries
transport errors with backoff and, on exhaustion, prints an actionable message
instead of a traceback. To get through:

```powershell
# PowerShell — point the tool (and MSAL) at your proxy
$env:HTTPS_PROXY = "http://your-proxy:8080"
# If the proxy re-signs TLS, trust its root CA (export it as a PEM first):
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corp-root-ca.pem"
python .\acs_audit.py --tenant <tenant-id> --client-id <id> --client-secret <secret>

# …or pass them explicitly instead of env vars (these apply to sign-in too):
python .\acs_audit.py --tenant <tenant-id> --client-id <id> --client-secret <secret> `
  --proxy "http://your-proxy:8080" --ca-bundle "C:\path\to\corp-root-ca.pem"
```

Do not disable TLS verification to work around inspection — trust the proxy's CA
instead. If Graph stays blocked, run from a host with the same egress as your
users, or export the two collections elsewhere and analyse them with
`--from-dump`.

## Findings

| Code | Severity | Meaning |
|---|---|---|
| `ACS_URL_ACCEPTED` | CRITICAL | A `--check-acs-url` candidate exactly matches a registered reply URL. Entra would deliver the assertion there — this app is affected by that specific URL. |
| `ACS_URL_ACCEPTED_VIA_WILDCARD` | CRITICAL | A `--check-acs-url` candidate is covered by a wildcard reply URL. |
| `ASSERTION_HIJACKABLE` | CRITICAL | **The reported ROSS pattern.** A SAML app that does not enforce signed AuthnRequests *and* has a reply URL an attacker can receive at (wildcard / dangling-unowned / claimable). A victim's signed assertion can be redirected and replayed. This is the finding that answers "which other apps have the same live exposure". Requires a DNS pass (do not use `--skip-dns`). |
| `WILDCARD_REPLY_URL` | CRITICAL | Wildcard in the reply URL — the exact-match allowlist no longer constrains delivery. |
| `DANGLING_DNS` | HIGH | Reply URL host does not resolve **and is not under a verified domain**. If its registrable domain is unregistered/expired, whoever registers it receives assertions. Verify the domain registration. |
| `CNAME_TO_CLAIMABLE_SERVICE` | HIGH | CNAME chain terminates in a takeover-prone namespace whose target resource may be deleted and re-created by anyone. |
| `TAKEOVER_PRONE_NAMESPACE` | HIGH | Host itself sits in a claimable namespace (`*.azurewebsites.net`, `*.herokuapp.com`, S3, etc.). |
| `NON_HTTPS` | HIGH | Assertion or authorization code would traverse cleartext. Loopback is excluded. |
| `SAML_UNSIGNED_REQUESTS_ACCEPTED` | MEDIUM | `requestSignatureVerification.isSignedRequestRequired` is not `true`. The allowlist is the only control. |
| `SIGNING_ENFORCED_NO_VERIFY_CERT` | MEDIUM | Signed requests required but no `keyCredential` with `usage=Verify`. |
| `UNVERIFIED_DOMAIN` | MEDIUM / LOW | Host is not under a domain verified in this tenant. Expected for SaaS; confirm the recipient is intended. |
| `LOOPBACK_OR_PRIVATE` | MEDIUM / LOW | Loopback or RFC1918 host registered. Leftover dev config, and a candidate target when no explicit ACS URL is supplied. |
| `DANGLING_DNS_OWNED_ZONE` | LOW | Reply URL under a **verified** domain does not resolve. Stale config to prune — not attacker-claimable unless your DNS zone is compromised. |
| `DNS_LOOKUP_FAILED` | LOW | The resolver could not answer for this host (throttling/network); it was **not** evaluated. Re-run (lower `--dns-workers`) before trusting the result. |
| `USERINFO_IN_URL` | MEDIUM | URL contains a userinfo component. |
| `LARGE_REPLY_URL_SURFACE` | LOW | 10+ registered URLs. Each is a permitted delivery target. |
| `DISABLED_SP_WITH_URLS` | LOW | Service principal disabled but reply URLs remain. |
| `MULTITENANT_APP` | INFO | App owned by another tenant; hygiene is the vendor's responsibility. |

`ASSERTION_HIJACKABLE`, `WILDCARD_REPLY_URL` and `CNAME_TO_CLAIMABLE_SERVICE` are the ones that mean *act today* — `ASSERTION_HIJACKABLE` is precisely the reported ROSS condition found in another app. `SAML_UNSIGNED_REQUESTS_ACCEPTED` on its own is the reported *precondition* and will fire across most of the estate: it is a real takeover only when combined with an attacker-reachable reply URL (which is what `ASSERTION_HIJACKABLE` reports), so on its own treat it as a hardening backlog, not an incident.

> **Note on `--dns-workers`:** DNS resolution is the only tunable worker pool (the Graph enumerations are a fixed pool of the four independent queries). 50–100 is a sensible range; above that you are limited by your own resolver, and an overloaded resolver returns `DNS_LOOKUP_FAILED`, not a wrong verdict. Because dangling/claimable detection depends on this pass, do not conclude an app is clean from a `--skip-dns` run.

## Triage

A finding is not a confirmed vulnerability. To confirm one, in your own tenant against a non-production app with a test identity:

1. Craft an AuthnRequest with the ACS set to a collaborator endpoint you control.
2. Complete the authentication with a real test account.
3. Observe the outcome. `AADSTS50011` means the allowlist held. A POST to the collaborator means it did not.

Anything short of completing step 2 is inconclusive, because Entra validates the reply URL only after authorization succeeds.

## Remediation

- Prune reply URLs to the minimum. Exact match, HTTPS only, no wildcards, nothing pointing at a host you cannot prove ownership of today. Stale entries are not inert — when a request carries no explicit ACS URL, Entra may select any configured reply URL.
- Enable signed-request enforcement on tier-0 SAML apps and upload the SP signing certificate. Set `AuthnRequestsSigned="true"` on the SP side to match.
- Treat reply-URL write as a privileged operation. Application Administrator, Cloud Application Administrator and per-app Owner all grant it, and each is a silent assertion-redirect primitive.
- Monitor `AuditLogs` for `AppAddresses` / `ReplyUrls` modifications, and `SigninLogs` for `ResultType == 50011` bursts.
- On the SP side: enforce `InResponseTo` correlation, `Destination`/`Recipient`/`Audience` validation, a working one-time-use replay cache, and disable unsolicited SSO where it is not needed.

## Tests

```bash
python3 test_acs_audit.py
```

Runs the detection logic against synthetic Graph responses. No tenant or network required.

## Caveats

- `requestSignatureVerification` is not selectable on every API surface. If the `$select` is rejected the tool retries without it and reports signed-request state as unknown rather than failing the run.
- `preferredSingleSignOnMode` is not always populated for gallery apps, so SAML capability is inferred from SSO mode *or* SSO-related service principal tags. Some SAML apps may be classified as non-SAML.
- The takeover-namespace list is conservative, not exhaustive. Extend `TAKEOVER_SUFFIXES` for your environment.
- DNS resolution reflects the resolver's view. Run from a host with the same egress as your users before concluding a name is dangling; split-horizon DNS produces false positives.
