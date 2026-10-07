#!/usr/bin/env python3
"""
acs_audit.py - Entra ID SAML ACS / reply URL exposure audit.

Read-only. Enumerates every service principal and application registration in a
tenant, then evaluates each reply URL / redirect URI for conditions that would
let an attacker receive a SAML assertion or OAuth authorization code intended
for someone else.

Threat model
------------
Entra ID does not validate AuthnRequest signatures unless "Require verification
certificates" is enabled on the application. Requestor verification is provided
solely by the reply URL allowlist: Entra honours the AssertionConsumerServiceURL
sent in the AuthnRequest as long as it exactly matches a registered reply URL,
and returns AADSTS50011 otherwise. That check happens *after* the user has
authenticated.

Consequences this tool looks for:

  1. The allowlist is only as strong as your control over the hosts on it.
     A registered reply URL whose DNS is dangling, or whose host lives in a
     claimable third-party namespace, is an assertion-delivery endpoint for
     whoever claims it. No misconfiguration in Entra required.
  2. Wildcard reply URLs collapse the allowlist entirely.
  3. Without signed-request enforcement, an unsigned AuthnRequest can freely
     select *any* registered reply URL, including stale ones from decommissioned
     environments, vendors, or test deployments.

Because the stolen artifact is post-authentication, phishing-resistant MFA,
device compliance and Conditional Access do not mitigate any of this.

Usage
-----
  # delegated, interactive (device code)
  python acs_audit.py --tenant contoso.onmicrosoft.com --device-code

  # app-only
  python acs_audit.py --tenant <tenant-id> --client-id <id> --client-secret <secret>

  # bring your own token
  GRAPH_TOKEN=eyJ0... python acs_audit.py --tenant <tenant-id>

Required Graph permissions (read only):
  Application.Read.All, Directory.Read.All
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable
from urllib.parse import urlsplit

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("missing dependency: pip install requests")

try:
    import dns.resolver
    import dns.exception

    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAVE_DNSPYTHON = False

GRAPH = "https://graph.microsoft.com/v1.0"
# Microsoft Graph Command Line Tools - public client, usable for device code flow.
DEFAULT_PUBLIC_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# ---------------------------------------------------------------------------
# Takeover-prone namespaces. A host that IS one of these, or CNAMEs into one,
# is only as safe as the corresponding account/resource still being yours.
# Extend freely - this list is deliberately conservative rather than exhaustive.
# ---------------------------------------------------------------------------
TAKEOVER_SUFFIXES = [
    # Azure
    "azurewebsites.net", "scm.azurewebsites.net", "azurewebsites.windows.net",
    "cloudapp.azure.com", "cloudapp.net", "trafficmanager.net",
    "blob.core.windows.net", "web.core.windows.net", "azureedge.net",
    "azurefd.net", "azure-api.net", "azurecontainer.io", "azurehdinsight.net",
    "azure-mobile.net", "redis.cache.windows.net", "search.windows.net",
    "servicebus.windows.net", "database.windows.net",
    # AWS
    "amazonaws.com", "elasticbeanstalk.com", "cloudfront.net",
    "awsapprunner.com", "amplifyapp.com",
    # GCP / Firebase
    "appspot.com", "firebaseapp.com", "web.app", "run.app", "cloudfunctions.net",
    # PaaS / static hosting
    "herokuapp.com", "herokudns.com", "herokussl.com",
    "github.io", "gitlab.io", "bitbucket.io",
    "netlify.app", "netlify.com", "vercel.app", "now.sh",
    "pages.dev", "workers.dev", "surge.sh", "render.com", "onrender.com",
    "fly.dev", "railway.app", "pythonanywhere.com", "readthedocs.io",
    "pantheonsite.io", "wpengine.com", "ghost.io", "myshopify.com",
    "squarespace.com", "webflow.io", "unbouncepages.com", "launchrock.com",
    "helpjuice.com", "helpscoutdocs.com", "statuspage.io", "zendesk.com",
    "freshdesk.com", "uservoice.com", "cargocollective.com", "strikinglydns.com",
    "tilda.ws", "wixdns.net", "bubbleapps.io", "teamwork.com", "campaignmonitor.com",
]

# Non-http schemes that are legitimate for native / broker redirect URIs and
# should not be reported as "non-https".
BENIGN_NATIVE_SCHEME_PREFIXES = ("ms-appx-web", "msauth", "msal", "urn:ietf:wg:oauth")

SAML_SSO_TAGS = {
    "WindowsAzureActiveDirectoryCustomSingleSignOnApplication",
    "WindowsAzureActiveDirectoryGalleryApplicationNonPrimaryV1",
}

# CLEAN is the severity of an app with no findings at all; it only appears in the
# report with --include-clean and never trips --fail-on.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "CLEAN": 5}
REPORTED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# The logout URL is registered on the app but never receives an assertion or
# authorization code, so it is not an ACS candidate.
LOGOUT_SOURCE = "app.web.logoutUrl"

GUID_RE = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.IGNORECASE)

GRAPH_ATTEMPTS = 6


def log(msg: str) -> None:
    """Always-on progress line to stderr, flushed immediately so the user sees
    each phase as it happens rather than after a long silent buffer."""
    print(f"[*] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Graph client
# ---------------------------------------------------------------------------
class GraphClient:
    def __init__(
        self,
        token: str,
        timeout: int = 60,
        verbose: bool = False,
        proxy: str | None = None,
        ca_bundle: str | None = None,
    ):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "ConsistencyLevel": "eventual",
                "User-Agent": "acs-audit/1.0",
            }
        )
        # requests honours HTTP(S)_PROXY / NO_PROXY and REQUESTS_CA_BUNDLE from the
        # environment by default; an explicit flag overrides that for this run.
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        if ca_bundle:
            self.session.verify = ca_bundle
        self.timeout = timeout
        self.verbose = verbose

    def get(self, url: str, params: dict | None = None) -> dict:
        for attempt in range(1, GRAPH_ATTEMPTS + 1):
            final = attempt == GRAPH_ATTEMPTS
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ChunkedEncodingError) as exc:
                # Transport-level failure (connection reset/closed, DNS, read
                # timeout). Common behind a corporate proxy / TLS inspection or a
                # firewall that blocks graph.microsoft.com. Back off and retry
                # rather than crashing with a raw traceback.
                if final:
                    raise GraphError(
                        0,
                        f"connection to Graph failed after {GRAPH_ATTEMPTS} attempts "
                        f"({type(exc).__name__}: {exc}). If auth succeeded but this call did "
                        f"not, a proxy/firewall or TLS inspection is likely blocking {GRAPH}. "
                        f"Set HTTPS_PROXY (or --proxy) and, for TLS interception, "
                        f"REQUESTS_CA_BUNDLE (or --ca-bundle).",
                        url,
                    ) from exc
                wait = retry_delay(None, attempt)
                if self.verbose:
                    print(f"[!] {type(exc).__name__} talking to Graph, retrying in {wait:.0f}s "
                          f"(attempt {attempt}/{GRAPH_ATTEMPTS})", file=sys.stderr)
                time.sleep(wait)
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                if final:
                    raise GraphError(resp.status_code,
                                     f"still failing after {GRAPH_ATTEMPTS} attempts: "
                                     f"{resp.text[:1000]}", url)
                wait = retry_delay(resp, attempt)
                if self.verbose:
                    print(f"[!] {resp.status_code} from Graph, retrying in {wait:.0f}s "
                          f"(attempt {attempt}/{GRAPH_ATTEMPTS})", file=sys.stderr)
                time.sleep(wait)
                continue
            if not resp.ok:
                raise GraphError(resp.status_code, resp.text[:1000], url)
            try:
                return resp.json()
            except ValueError:
                raise GraphError(
                    resp.status_code,
                    "response was not JSON - a proxy or captive portal is probably answering "
                    f"instead of Graph: {resp.text[:200]}",
                    url,
                ) from None
        raise AssertionError("unreachable")

    def paged(self, path: str, params: dict | None = None,
              label: str | None = None) -> Iterable[dict]:
        url = f"{GRAPH}{path}"
        first = True
        page = 0
        total = 0
        while url:
            data = self.get(url, params=params if first else None)
            first = False
            batch = data.get("value", [])
            page += 1
            total += len(batch)
            if label:
                more = " (more pages)" if data.get("@odata.nextLink") else ""
                log(f"  {label}: fetched page {page}, {total} so far{more}")
            yield from batch
            url = data.get("@odata.nextLink")


class GraphError(Exception):
    def __init__(self, status: int, body: str, url: str):
        self.status = status
        self.body = body
        super().__init__(f"Graph {status} on {url}: {body}")


def retry_delay(resp: requests.Response | None, attempt: int) -> float:
    """Seconds to wait before retrying after failed `attempt` (1-based). Honours
    Retry-After when Graph sends one, in either of its forms (delta-seconds or
    HTTP-date), and otherwise backs off exponentially. Capped either way so a
    hostile or broken header cannot stall the run."""
    header = resp.headers.get("Retry-After") if resp is not None else None
    if header:
        try:
            return float(min(max(int(header), 0), 120))
        except ValueError:
            pass
        try:
            delta = parsedate_to_datetime(header) - datetime.now(timezone.utc)
            return min(max(delta.total_seconds(), 0.0), 120.0)
        except (TypeError, ValueError):
            pass
    return float(min(2 ** (attempt - 1), 30))


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def acquire_token(args: argparse.Namespace) -> str:
    if args.access_token:
        return args.access_token
    env = os.environ.get("GRAPH_TOKEN")
    if env:
        return env

    try:
        import msal
    except ImportError:
        sys.exit("missing dependency: pip install msal (or pass --access-token / $GRAPH_TOKEN)")

    authority = f"https://login.microsoftonline.com/{args.tenant}"
    scope = ["https://graph.microsoft.com/.default"]
    # Send sign-in through the same proxy / CA bundle as the Graph calls; without
    # this, --proxy and --ca-bundle get past Graph but not login.microsoftonline.com.
    transport: dict[str, Any] = {"verify": args.ca_bundle or True}
    if args.proxy:
        transport["proxies"] = {"http": args.proxy, "https": args.proxy}

    if args.client_secret:
        app = msal.ConfidentialClientApplication(
            args.client_id, authority=authority, client_credential=args.client_secret,
            **transport,
        )
        result = app.acquire_token_for_client(scopes=scope)
    else:
        client_id = args.client_id or DEFAULT_PUBLIC_CLIENT_ID
        app = msal.PublicClientApplication(client_id, authority=authority, **transport)
        flow = app.initiate_device_flow(scopes=scope)
        if "user_code" not in flow:
            sys.exit(f"device flow failed: {json.dumps(flow, indent=2)}")
        print(flow["message"], file=sys.stderr)
        result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        sys.exit(f"token acquisition failed: {result.get('error_description', result)}")
    return result["access_token"]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str
    code: str
    detail: str


@dataclass
class UrlRecord:
    url: str
    source: str  # sp.replyUrls | app.web | app.spa | app.publicClient
    scheme: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""
    dns_status: str = "unchecked"
    dns_chain: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class AppRecord:
    app_id: str
    display_name: str
    sp_object_id: str | None = None
    app_object_id: str | None = None
    sso_mode: str | None = None
    saml_capable: bool = False
    account_enabled: bool | None = None
    is_foreign_tenant: bool = False
    signed_requests_required: bool | None = None
    verify_certs: int = 0  # usage=Verify keyCredentials valid right now
    invalid_verify_certs: int = 0  # usage=Verify keyCredentials expired or not yet valid
    tags: list[str] = field(default_factory=list)
    urls: list[UrlRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        sevs = [f.severity for f in self.findings]
        for u in self.urls:
            sevs.extend(f.severity for f in u.findings)
        if not sevs:
            return "CLEAN"
        return min(sevs, key=lambda s: SEVERITY_ORDER[s])


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------
def fetch_verified_domains(client: GraphClient) -> set[str]:
    domains = set()
    for d in client.paged("/domains"):
        if d.get("isVerified"):
            domains.add(d["id"].lower())
    return domains


def fetch_service_principals(client: GraphClient) -> list[dict]:
    select = ",".join(
        [
            "id", "appId", "displayName", "replyUrls", "preferredSingleSignOnMode",
            "accountEnabled", "servicePrincipalType", "appOwnerOrganizationId", "tags",
        ]
    )
    return list(client.paged("/servicePrincipals", {"$select": select, "$top": "999"},
                             label="service principals"))


def fetch_applications(client: GraphClient) -> list[dict]:
    base = ["id", "appId", "displayName", "web", "spa", "publicClient",
            "keyCredentials", "identifierUris", "signInAudience"]
    # requestSignatureVerification is the property that actually controls whether
    # Entra rejects unsigned AuthnRequests. Older tenants/API surfaces reject it
    # in $select, so fall back rather than failing the whole run.
    try:
        return list(
            client.paged(
                "/applications",
                {"$select": ",".join(base + ["requestSignatureVerification"]), "$top": "999"},
                label="applications",
            )
        )
    except GraphError as e:
        if e.status != 400:
            raise
        print("[!] requestSignatureVerification not selectable; retrying without it "
              "(signed-request state will be reported as unknown)", file=sys.stderr)
        return list(client.paged("/applications", {"$select": ",".join(base), "$top": "999"},
                                 label="applications"))


def fetch_tenant_id(client: GraphClient) -> str | None:
    try:
        org = client.get(f"{GRAPH}/organization")
        vals = org.get("value") or []
        return vals[0]["id"] if vals else None
    except GraphError:
        return None


def load_dump(path: str) -> tuple[list[dict], list[dict], str | None, set[str]]:
    """Load service principals and application registrations from a pre-exported
    JSON file so the analysis can run offline, with no tenant credentials.

    Accepted shapes:
      * {"servicePrincipals": [...], "applications": [...],
         "tenantId": "...", "verifiedDomains": ["contoso.com", ...]}
      * a `findings.json` previously written by this tool: the raw SP/app arrays
        are not stored there, so only the two top-level arrays above are read.

    Each array element is the raw Microsoft Graph object, exactly as returned by
    GET /servicePrincipals and GET /applications. Export them however you like,
    e.g. `az rest` or Graph Explorer piped into a JSON file.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        sys.exit(f"[!] cannot read {path}: {exc.strerror or exc}")
    # Windows PowerShell 5.1 `>` redirection writes UTF-16 with a BOM, and other
    # Windows tools add a UTF-8 BOM; accept both rather than failing to decode.
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    try:
        data = json.loads(raw.decode(encoding))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        sys.exit(f"[!] {path} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        sys.exit(f"[!] {path}: expected a JSON object with 'servicePrincipals'/'applications' keys")
    sps = data.get("servicePrincipals") or data.get("service_principals") or []
    apps = data.get("applications") or data.get("apps") or []
    if not isinstance(sps, list) or not isinstance(apps, list):
        sys.exit(f"[!] {path}: 'servicePrincipals' and 'applications' must be JSON arrays")
    tenant_id = data.get("tenantId") or data.get("tenant_id")
    domains = {
        d.strip().lower()
        for d in (data.get("verifiedDomains") or data.get("ownedDomains") or [])
        if isinstance(d, str) and d.strip()
    }
    return sps, apps, tenant_id, domains


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------
def parse_url(raw: str, source: str) -> UrlRecord:
    rec = UrlRecord(url=raw, source=source)
    try:
        parts = urlsplit(raw)
        rec.scheme = (parts.scheme or "").lower()
        rec.host = (parts.hostname or "").lower()
        rec.port = parts.port
        rec.path = parts.path or ""
    except ValueError:
        rec.findings.append(Finding("LOW", "UNPARSEABLE_URL", "URL could not be parsed"))
    return rec


def registrable_match(host: str, owned: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in owned)


def normalise_for_match(raw: str, keep_query: bool = True) -> str:
    """Canonical (scheme://host:port/path?query) form used to compare a candidate
    ACS URL against a registered reply URL. Host is lowercased and the default
    port for the scheme is filled in, mirroring how Entra normalises before its
    exact-match reply-URL check. Path, query and fragment are left byte-for-byte:
    Entra compares them case-sensitively, and `/acs?a=1` is a different reply URL
    from `/acs`. keep_query=False drops query and fragment; only the permissive
    wildcard comparison uses that. A URL that cannot be parsed (bad IPv6 literal,
    port out of range) is returned stripped, so it can still match itself."""
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return raw.strip()
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if port is None:
        port = {"https": 443, "http": 80}.get(scheme)
    path = parts.path or "/"
    if keep_query:
        if parts.query:
            path += "?" + parts.query
        if parts.fragment:
            path += "#" + parts.fragment
    return f"{scheme}://{host}:{port}{path}"


def acs_candidate_match(registered: str, candidate: str) -> str | None:
    """Would an AuthnRequest carrying `candidate` as AssertionConsumerServiceURL
    be honoured against this `registered` reply URL? Returns "exact", "wildcard",
    or None. This models the only requestor check Entra performs on an unsigned
    request: exact match against the reply-URL allowlist (AADSTS50011 otherwise).
    A wildcard registered URL is expanded permissively because, once present, it
    collapses the allowlist regardless of what the attacker supplies."""
    norm_registered = normalise_for_match(registered)
    norm_candidate = normalise_for_match(candidate)
    if "*" in registered:
        # Compare raw against raw, canonical against canonical, and canonical
        # without the query, so neither a default port, host casing nor an
        # appended query string hides a match.
        comparisons = (
            (registered, candidate),
            (norm_registered, norm_candidate),
            (normalise_for_match(registered, keep_query=False),
             normalise_for_match(candidate, keep_query=False)),
        )
        for pattern, target in comparisons:
            if re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), target):
                return "wildcard"
    if registered == candidate or norm_registered == norm_candidate:
        return "exact"
    return None


def takeover_suffix(host: str) -> str | None:
    for suf in TAKEOVER_SUFFIXES:
        if host == suf or host.endswith("." + suf):
            return suf
    return None


def is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def is_loopback_name(host: str) -> bool:
    return host == "localhost" or host.endswith(".localhost")


def has_userinfo(raw: str) -> bool:
    try:
        return "@" in urlsplit(raw).netloc
    except ValueError:
        return False


def analyse_url(
    rec: UrlRecord,
    owned_domains: set[str],
    saml_capable: bool,
    acs_candidates: list[str] | None = None,
) -> None:
    raw = rec.url
    loopback = is_loopback_name(rec.host) or is_private_host(rec.host)
    # parse_url already reported it; its scheme is empty only because parsing
    # failed, so judging the scheme would just add noise.
    unparseable = any(f.code == "UNPARSEABLE_URL" for f in rec.findings)

    # If the operator supplied the ACS URL(s) an attacker would try to inject
    # (e.g. the one from a bug-bounty report), flag every app whose allowlist
    # would actually deliver an assertion there. This is the concrete answer to
    # "which of my apps are affected by this specific URL?".
    candidates = [] if rec.source == LOGOUT_SOURCE else (acs_candidates or [])
    for cand in candidates:
        match = acs_candidate_match(raw, cand)
        if match == "exact":
            rec.findings.append(
                Finding("CRITICAL", "ACS_URL_ACCEPTED",
                        f"Injected ACS URL '{cand}' matches this registered reply URL - Entra "
                        "would deliver the victim's signed assertion here, no AADSTS50011")
            )
        elif match == "wildcard":
            rec.findings.append(
                Finding("CRITICAL", "ACS_URL_ACCEPTED_VIA_WILDCARD",
                        f"Injected ACS URL '{cand}' is covered by this wildcard reply URL - Entra "
                        "would deliver the victim's signed assertion here")
            )

    if "*" in raw:
        rec.findings.append(
            Finding("CRITICAL", "WILDCARD_REPLY_URL",
                    "Wildcard in reply URL - the exact-match allowlist no longer constrains "
                    "where the assertion/code is delivered")
        )

    # Cleartext over loopback is normal for local development, so only flag it
    # where the traffic would actually leave the machine.
    if rec.scheme == "http" and not loopback:
        rec.findings.append(
            Finding("HIGH", "NON_HTTPS",
                    "Assertion or authorization code would traverse cleartext")
        )
    elif not unparseable and rec.scheme not in ("https", "http") and not raw.lower().startswith(
        BENIGN_NATIVE_SCHEME_PREFIXES
    ):
        rec.findings.append(
            Finding("LOW", "UNUSUAL_SCHEME",
                    f"Non-HTTPS scheme '{rec.scheme}'" if rec.scheme else "URL has no scheme")
        )

    if loopback:
        sev = "MEDIUM" if saml_capable else "LOW"
        rec.findings.append(
            Finding(sev, "LOOPBACK_OR_PRIVATE",
                    "Loopback/private host registered - leftover dev config; also a candidate "
                    "target when no explicit ACS URL is supplied")
        )

    if has_userinfo(raw):
        rec.findings.append(
            Finding("MEDIUM", "USERINFO_IN_URL", "URL contains userinfo component")
        )

    suf = takeover_suffix(rec.host)
    if suf:
        rec.findings.append(
            Finding("HIGH", "TAKEOVER_PRONE_NAMESPACE",
                    f"Host sits in claimable namespace '{suf}' - verify the resource is still "
                    "provisioned and owned by you")
        )

    if owned_domains and rec.host and not loopback \
            and not registrable_match(rec.host, owned_domains):
        sev = "MEDIUM" if saml_capable else "LOW"
        rec.findings.append(
            Finding(sev, "UNVERIFIED_DOMAIN",
                    "Host is not under a domain verified in this tenant - confirm ownership "
                    "and that the third party is an intended assertion recipient")
        )


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
def dns_checkable(host: str) -> bool:
    """False for hosts public DNS cannot meaningfully answer for: IP literals,
    loopback names (dnspython does not read the hosts file), wildcards, and
    single-label names that only resolve through the local search suffix.
    Querying those produces NXDOMAIN and a false DANGLING_DNS."""
    if not host or "*" in host or "." not in host or is_loopback_name(host):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def resolve_host(host: str, timeout: float = 5.0) -> tuple[str, list[str]]:
    """Return (status, cname_chain). Status is one of resolves / nxdomain /
    no_address / error / skipped. Only nxdomain and no_address mean the name is
    dangling; a timeout or server failure is "error", never dangling."""
    if not dns_checkable(host):
        return "skipped", []
    if not HAVE_DNSPYTHON:
        try:
            socket.getaddrinfo(host, None)
            return "resolves", []
        except socket.gaierror as exc:
            not_found = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)}
            return ("nxdomain" if exc.errno in not_found else "error"), []
        except (OSError, UnicodeError):
            return "error", []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    chain: list[str] = []
    current = host
    for _ in range(8):
        try:
            answer = resolver.resolve(current, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            break
        except dns.resolver.NXDOMAIN:
            return "nxdomain", chain
        except dns.exception.DNSException:
            return "error", chain
        target = str(answer[0].target).rstrip(".").lower()
        chain.append(target)
        current = target

    for rtype in ("A", "AAAA"):
        try:
            resolver.resolve(current, rtype)
            return "resolves", chain
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return "nxdomain", chain
        except dns.exception.DNSException:
            return "error", chain
    return "no_address", chain


def safe_resolve(host: str) -> tuple[str, list[str]]:
    """resolve_host for the worker pool: one bad name or a missing resolver
    configuration must not abort every other lookup."""
    try:
        return resolve_host(host)
    except Exception:
        return "error", []


def run_dns_checks(apps: list[AppRecord], workers: int, verbose: bool) -> None:
    hosts = sorted({u.host for a in apps for u in a.urls if dns_checkable(u.host)})
    if not hosts:
        log("DNS: no resolvable hosts to check")
        return
    log(f"DNS: resolving {len(hosts)} distinct hosts with {workers} workers "
        "(use --skip-dns to skip)")

    total = len(hosts)
    step = max(1, total // 10)  # report roughly every 10%
    results: dict[str, tuple[str, list[str]]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, (host, res) in enumerate(zip(hosts, pool.map(safe_resolve, hosts)), 1):
            results[host] = res
            if i % step == 0 or i == total:
                log(f"  DNS: {i}/{total} hosts resolved")

    errors = sum(1 for status, _ in results.values() if status == "error")
    if errors:
        log(f"DNS: {errors} host(s) could not be checked (timeout/server failure) - "
            "they are not reported as dangling; re-run with working DNS to cover them")

    for app in apps:
        for u in app.urls:
            status, chain = results.get(u.host, ("skipped", []))
            u.dns_status = status
            u.dns_chain = chain

            if status in ("nxdomain", "no_address"):
                if u.source == LOGOUT_SOURCE:
                    # Logout requests carry NameID/SessionIndex, not an assertion.
                    u.findings.append(
                        Finding("HIGH", "DANGLING_DNS",
                                f"Logout URL host does not resolve ({status}) - anyone able to "
                                "claim this name receives this app's logout messages")
                    )
                else:
                    u.findings.append(
                        Finding("CRITICAL", "DANGLING_DNS",
                                f"Host does not resolve ({status}) but is an accepted reply URL - "
                                "anyone able to claim this name receives assertions for this app")
                    )
            for target in chain:
                suf = takeover_suffix(target)
                if suf:
                    u.findings.append(
                        Finding("HIGH", "CNAME_TO_CLAIMABLE_SERVICE",
                                f"CNAME chain reaches '{target}' in claimable namespace '{suf}'")
                    )
                    break


# ---------------------------------------------------------------------------
# Correlation and app-level analysis
# ---------------------------------------------------------------------------
def parse_graph_datetime(value: Any) -> datetime | None:
    """Parse a Graph DateTimeOffset ("2027-01-01T00:00:00Z", sometimes with up
    to 7 fractional digits) to an aware datetime. None if absent or unreadable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = re.sub(r"[zZ]$", "+00:00", value.strip())
    # Older Pythons' fromisoformat only takes exactly 3 or 6 fractional digits.
    text = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def credential_valid_at(cred: dict, now: datetime) -> bool:
    """True when the keyCredential's validity window contains `now`. A missing
    or unreadable date counts as open-ended, so a malformed export never invents
    an expired-certificate finding."""
    start = parse_graph_datetime(cred.get("startDateTime"))
    end = parse_graph_datetime(cred.get("endDateTime"))
    return (start is None or start <= now) and (end is None or now < end)


def build_records(
    sps: list[dict],
    apps: list[dict],
    owned_domains: set[str],
    tenant_id: str | None,
    include_all: bool,
    acs_candidates: list[str] | None = None,
    saml_only: bool = False,
) -> list[AppRecord]:
    by_app_id: dict[str, AppRecord] = {}
    now = datetime.now(timezone.utc)

    for sp in sps:
        app_id = sp.get("appId")
        if not app_id:
            continue
        tags = sp.get("tags") or []
        sso = sp.get("preferredSingleSignOnMode")
        reply_urls = sp.get("replyUrls") or []

        saml_capable = sso == "saml" or bool(SAML_SSO_TAGS.intersection(tags))
        rec = AppRecord(
            app_id=app_id,
            display_name=sp.get("displayName") or "(unnamed)",
            sp_object_id=sp.get("id"),
            sso_mode=sso,
            saml_capable=saml_capable,
            account_enabled=sp.get("accountEnabled"),
            tags=tags,
        )
        owner_org = sp.get("appOwnerOrganizationId")
        rec.is_foreign_tenant = bool(owner_org and tenant_id and owner_org != tenant_id)

        for u in reply_urls:
            rec.urls.append(parse_url(u, "sp.replyUrls"))
        by_app_id[app_id] = rec

    for app in apps:
        app_id = app.get("appId")
        if not app_id:
            continue
        rec = by_app_id.get(app_id)
        if rec is None:
            rec = AppRecord(app_id=app_id, display_name=app.get("displayName") or "(unnamed)")
            by_app_id[app_id] = rec

        rec.app_object_id = app.get("id")
        rsv = app.get("requestSignatureVerification")
        if isinstance(rsv, dict):
            rec.signed_requests_required = rsv.get("isSignedRequestRequired")
        verify = [k for k in (app.get("keyCredentials") or [])
                  if (k.get("usage") or "").lower() == "verify"]
        rec.verify_certs = sum(1 for k in verify if credential_valid_at(k, now))
        rec.invalid_verify_certs = len(verify) - rec.verify_certs

        seen = {u.url for u in rec.urls}
        for key, source in (("web", "app.web"), ("spa", "app.spa"), ("publicClient", "app.publicClient")):
            block = app.get(key) or {}
            for u in block.get("redirectUris") or []:
                if u not in seen:
                    rec.urls.append(parse_url(u, source))
                    seen.add(u)
            logout = block.get("logoutUrl")
            if key == "web" and logout and logout not in seen:
                rec.urls.append(parse_url(logout, LOGOUT_SOURCE))
                seen.add(logout)

    records = list(by_app_id.values())

    for rec in records:
        for u in rec.urls:
            analyse_url(u, owned_domains, rec.saml_capable, acs_candidates)

        if rec.saml_capable:
            if rec.signed_requests_required is not True:
                state = "disabled" if rec.signed_requests_required is False else "unknown/not configured"
                sev = "MEDIUM" if rec.app_object_id else "LOW"
                rec.findings.append(
                    Finding(sev, "SAML_UNSIGNED_REQUESTS_ACCEPTED",
                            f"Signed AuthnRequest enforcement is {state}. Entra will honour the "
                            "AssertionConsumerServiceURL from any unsigned request that matches a "
                            "registered reply URL, so the allowlist is the only control.")
                )
            if rec.signed_requests_required is True and rec.verify_certs == 0:
                if rec.invalid_verify_certs:
                    detail = (f"Signed requests required but none of the "
                              f"{rec.invalid_verify_certs} keyCredential(s) with usage=Verify is "
                              "currently valid (expired or not yet valid)")
                else:
                    detail = "Signed requests required but no keyCredential with usage=Verify"
                rec.findings.append(Finding("MEDIUM", "SIGNING_ENFORCED_NO_VERIFY_CERT", detail))

        # The logout URL never receives an assertion or code, so it is not part
        # of the delivery surface these two checks are about.
        delivery_urls = [u for u in rec.urls if u.source != LOGOUT_SOURCE]
        if len(delivery_urls) >= 10:
            rec.findings.append(
                Finding("LOW", "LARGE_REPLY_URL_SURFACE",
                        f"{len(delivery_urls)} registered reply/redirect URLs - each one is a "
                        "permitted delivery target; prune anything unused")
            )

        if rec.account_enabled is False and delivery_urls:
            rec.findings.append(
                Finding("LOW", "DISABLED_SP_WITH_URLS",
                        "Service principal disabled but reply URLs remain registered")
            )

        if rec.is_foreign_tenant and rec.saml_capable:
            rec.findings.append(
                Finding("INFO", "MULTITENANT_APP",
                        "App is owned by another tenant; signed-request enforcement and reply "
                        "URL hygiene are the vendor's responsibility - verify contractually")
            )

    if saml_only:
        records = [r for r in records if r.saml_capable]

    return filter_records(records, include_all)


def filter_records(records: list[AppRecord], include_all: bool) -> list[AppRecord]:
    """Drop apps with no findings (unless include_all) and sort worst-first.
    Run this again after DNS checks: an app with no findings beforehand can
    still turn out to have a dangling reply URL, and DNS findings can raise an
    app's severity."""
    if not include_all:
        records = [r for r in records if r.severity != "CLEAN"]
    return sorted(records, key=lambda r: (SEVERITY_ORDER[r.severity], r.display_name.lower()))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
CSV_FIELDS = [
    "severity", "app", "appId", "ssoMode", "samlCapable", "signedRequestsRequired",
    "url", "urlSource", "dnsStatus", "dnsChain", "codes", "details",
]


def _row(r: AppRecord, findings: list[Finding], u: UrlRecord | None = None) -> dict[str, Any]:
    severity = (min((f.severity for f in findings), key=lambda s: SEVERITY_ORDER[s])
                if findings else "CLEAN")
    return {
        "severity": severity, "app": r.display_name, "appId": r.app_id,
        "ssoMode": r.sso_mode, "samlCapable": r.saml_capable,
        "signedRequestsRequired": r.signed_requests_required,
        "url": u.url if u else "", "urlSource": u.source if u else "",
        "dnsStatus": u.dns_status if u else "", "dnsChain": " -> ".join(u.dns_chain) if u else "",
        "codes": ";".join(f.code for f in findings),
        "details": " | ".join(f.detail for f in findings),
    }


def flatten(records: list[AppRecord]) -> list[dict[str, Any]]:
    """One row per (app, URL) carrying a finding. App-level findings repeat on
    every URL of the app, since each URL is a delivery target they apply to.
    Clean apps (only present with --include-clean) get a CLEAN row per URL, so
    the CSV doubles as a reply-URL inventory."""
    rows = []
    for r in records:
        clean_app = r.severity == "CLEAN"
        if not r.urls:
            rows.append(_row(r, r.findings))
            continue
        for u in r.urls:
            combined = r.findings + u.findings
            if combined or clean_app:
                rows.append(_row(r, combined, u))
    rows.sort(key=lambda r: (SEVERITY_ORDER[r["severity"]], r["app"].lower()))
    return rows


def finding_counts(records: list[AppRecord]) -> Counter:
    """How often each code was raised: once per app for app-level codes, once
    per URL for URL-level ones. Counting flattened rows instead would multiply
    app-level codes by the app's URL count."""
    counts: Counter = Counter()
    for r in records:
        counts.update(f.code for f in r.findings)
        for u in r.urls:
            counts.update(f.code for f in u.findings)
    return counts


def print_console(records: list[AppRecord], rows: list[dict], quiet_info: bool) -> None:
    print("\n=== Entra ID reply URL / SAML ACS exposure ===\n")
    for sev in REPORTED_SEVERITIES:
        subset = [r for r in rows if r["severity"] == sev]
        if subset:
            apps = len({r["appId"] for r in subset})
            print(f"  {sev:<9} {len(subset):>4}  ({apps} app{'' if apps == 1 else 's'})")
    clean = sum(1 for r in records if r.severity == "CLEAN")
    if clean:
        print(f"  {'CLEAN':<9} {clean:>4}  app(s) with no findings - listed in CSV/JSON only")
    print()

    for sev in REPORTED_SEVERITIES:
        if quiet_info and sev in ("LOW", "INFO"):
            continue
        subset = [r for r in rows if r["severity"] == sev]
        if not subset:
            continue
        print(f"--- {sev} ---")
        for r in subset:
            print(f"  [{r['app']}]  ({r['appId']})")
            if r["url"]:
                dns = f"  dns={r['dnsStatus']}" if r["dnsStatus"] not in ("unchecked", "skipped") else ""
                print(f"      {r['url']}{dns}")
                if r["dnsChain"]:
                    print(f"      cname: {r['dnsChain']}")
            print(f"      {r['codes']}")
            print(f"      {r['details']}")
            print()

    code_counts = finding_counts(records)
    if code_counts:
        print("--- finding frequency (apps, or URLs for URL-level codes) ---")
        for code, n in code_counts.most_common():
            print(f"  {n:>5}  {code}")
    print()


def write_json(path: str, records: list[AppRecord], meta: dict) -> None:
    payload = {
        "metadata": meta,
        "applications": [{"severity": r.severity, **asdict(r)} for r in records],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


def write_csv(path: str, rows: list[dict]) -> None:
    # Always write the header, so a clean run still leaves a valid (empty) CSV
    # rather than a stale file from an earlier run.
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(
        description="Audit Entra ID reply URLs / SAML ACS allowlists for assertion-hijack exposure.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--tenant", help="tenant ID or domain (required unless --from-dump)")
    p.add_argument("--from-dump", help="analyse a pre-exported Graph JSON file offline "
                                       "(no credentials, no network); see load_dump() for the shape")
    p.add_argument("--check-acs-url", action="append", metavar="URL",
                   help="candidate injected ACS URL(s) to test against every app's reply-URL "
                        "allowlist; repeatable and/or comma-separated. Apps that would accept "
                        "delivery are flagged CRITICAL (ACS_URL_ACCEPTED)")
    p.add_argument("--saml-only", action="store_true",
                   help="restrict the report to SAML-capable apps")
    p.add_argument("--client-id", help="app registration client ID")
    p.add_argument("--client-secret", help="client secret (app-only flow; needs --client-id)")
    p.add_argument("--device-code", action="store_true",
                   help="interactive device code flow (the default when no secret or token is given)")
    p.add_argument("--access-token", help="pre-acquired Graph token (or set $GRAPH_TOKEN)")
    p.add_argument("--owned-domains", help="comma-separated domains you control; "
                                           "defaults to the tenant's verified domains")
    p.add_argument("--skip-dns", action="store_true", help="skip DNS resolution checks")
    p.add_argument("--dns-workers", type=int, default=20,
                   help="parallel DNS lookups (default 20)")
    p.add_argument("--include-clean", action="store_true", help="include apps with no findings")
    p.add_argument("--quiet-info", action="store_true", help="hide LOW/INFO in console output")
    p.add_argument("--out-json", help="write full results to this JSON path")
    p.add_argument("--out-csv", help="write flattened findings to this CSV path")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="exit non-zero if any finding at or above this severity (for CI)")
    p.add_argument("--proxy", help="HTTP(S) proxy URL for sign-in and Graph calls, e.g. "
                                   "http://proxy:8080 (overrides HTTPS_PROXY for this run)")
    p.add_argument("--ca-bundle", help="path to a CA bundle to trust, for proxies that perform "
                                       "TLS inspection (overrides REQUESTS_CA_BUNDLE)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    if not args.from_dump and not args.tenant:
        p.error("--tenant is required unless --from-dump is given")
    if args.client_secret and not args.client_id:
        p.error("--client-secret needs --client-id")
    if args.dns_workers < 1:
        p.error("--dns-workers must be at least 1")

    # Candidate ACS URLs may be repeated and/or comma-separated. Reject anything
    # that is not an absolute http(s) URL: it could never match a reply URL, and
    # the report would then wrongly say no app accepts it.
    acs_candidates: list[str] = []
    for chunk in args.check_acs_url or []:
        acs_candidates.extend(c.strip() for c in chunk.split(",") if c.strip())
    for cand in acs_candidates:
        try:
            parts = urlsplit(cand)
            parts.port  # raises ValueError for a malformed port
        except ValueError as exc:
            p.error(f"--check-acs-url {cand!r} is not a valid URL ({exc})")
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            p.error(f"--check-acs-url {cand!r} must be an absolute http(s) URL, "
                    "e.g. https://attacker.example/saml/acs")

    dump_domains: set[str] = set()
    if args.from_dump:
        log(f"loading pre-exported Graph data from {args.from_dump}")
        sps, apps, tenant_id, dump_domains = load_dump(args.from_dump)
        log(f"loaded {len(sps)} service principals and {len(apps)} applications from dump")
    else:
        log(f"authenticating to tenant {args.tenant} ...")
        token = acquire_token(args)
        log("authenticated; connecting to Microsoft Graph (read-only)")
        client = GraphClient(token, verbose=args.verbose,
                             proxy=args.proxy, ca_bundle=args.ca_bundle)

        log("step 1/4: enumerating service principals (enabled apps) ...")
        sps = fetch_service_principals(client)
        log(f"step 1/4: done - {len(sps)} service principals")

        log("step 2/4: enumerating application registrations ...")
        apps = fetch_applications(client)
        log(f"step 2/4: done - {len(apps)} applications")

        log("step 3/4: reading tenant identity ...")
        tenant_id = fetch_tenant_id(client)
        if not tenant_id and GUID_RE.fullmatch(args.tenant):
            tenant_id = args.tenant.lower()

    if not tenant_id:
        log("tenant ID unknown - apps owned by other tenants cannot be told apart, so "
            "MULTITENANT_APP will not be reported")

    if args.owned_domains:
        owned = {d.strip().lower() for d in args.owned_domains.split(",") if d.strip()}
        log(f"using {len(owned)} owned domain(s) from --owned-domains")
    elif args.from_dump:
        owned = dump_domains
        log(f"using {len(owned)} verified domain(s) from dump")
    else:
        log("step 3/4: reading verified tenant domains ...")
        owned = fetch_verified_domains(client)
        log(f"step 3/4: done - {len(owned)} verified tenant domains")
    if not owned:
        log("no owned/verified domains known - UNVERIFIED_DOMAIN will not be reported "
            "(pass --owned-domains to enable it)")

    log(f"analysing {len(sps)} service principals and {len(apps)} app registrations ...")
    if acs_candidates:
        log(f"  also testing {len(acs_candidates)} supplied ACS URL(s) against every allowlist")
    # Keep every app until DNS has run: an app with no findings yet can still
    # turn out to have a dangling reply URL, the most urgent finding there is.
    records = build_records(
        sps, apps, owned, tenant_id, include_all=True,
        acs_candidates=acs_candidates, saml_only=args.saml_only,
    )

    if not args.skip_dns:
        log("step 4/4: DNS resolution of registered hosts ...")
        if not HAVE_DNSPYTHON:
            print("[!] dnspython not installed - CNAME chain analysis unavailable, "
                  "falling back to basic resolution", file=sys.stderr)
        run_dns_checks(records, args.dns_workers, args.verbose)
        log("step 4/4: DNS resolution done")
    else:
        log("step 4/4: DNS resolution skipped (--skip-dns)")

    records = filter_records(records, args.include_clean)
    log(f"analysis done - {len(records)} app(s) to report")

    log("building report ...")
    rows = flatten(records)
    print_console(records, rows, args.quiet_info)

    if acs_candidates:
        accepted = sorted(
            {r.display_name for r in records
             for f in (r.findings + [f for u in r.urls for f in u.findings])
             if f.code in ("ACS_URL_ACCEPTED", "ACS_URL_ACCEPTED_VIA_WILDCARD")}
        )
        print(f"=== injected ACS URL check ({len(acs_candidates)} URL(s)) ===")
        for c in acs_candidates:
            print(f"    tested: {c}")
        if accepted:
            print(f"[!] {len(accepted)} app(s) would ACCEPT delivery to a tested URL:")
            for name in accepted:
                print(f"      - {name}")
        else:
            print("[+] No app's reply-URL allowlist would accept any tested URL "
                  "(Entra would return AADSTS50011).")
        print()

    meta = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "tenant": args.tenant,
        "tenantId": tenant_id,
        "source": f"dump:{args.from_dump}" if args.from_dump else "graph",
        "servicePrincipalCount": len(sps),
        "applicationCount": len(apps),
        "ownedDomains": sorted(owned),
        "checkedAcsUrls": acs_candidates,
        "samlOnly": args.saml_only,
        "dnsChecked": not args.skip_dns,
        "dnspythonAvailable": HAVE_DNSPYTHON,
    }
    if args.out_json:
        write_json(args.out_json, records, meta)
        print(f"[+] JSON written to {args.out_json}")
    if args.out_csv:
        write_csv(args.out_csv, rows)
        print(f"[+] CSV written to {args.out_csv}")

    log("done")
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[r["severity"]] <= threshold for r in rows):
            return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except GraphError as exc:
        hint = ""
        if exc.status in (401, 403):
            hint = ("\n[!] The token was rejected or lacks permission. The tool needs "
                    "Application.Read.All and Directory.Read.All (admin consent for app-only).")
        sys.exit(f"[!] {exc}{hint}")
