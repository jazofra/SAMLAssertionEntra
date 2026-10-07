#!/usr/bin/env python3
"""Offline tests for the detection logic. No tenant or network required.

    python3 test_acs_audit.py
"""

import contextlib
import io
import json
import os
import sys
import tempfile

import acs_audit
from acs_audit import (
    acs_candidate_match,
    build_records,
    finding_counts,
    flatten,
    normalise_for_match,
    print_console,
    resolve_host,
    retry_delay,
)

TENANT_ID = "11111111-1111-1111-1111-111111111111"
OWNED = {"contoso.com", "contoso.onmicrosoft.com"}

SPS = [
    {   # SAML app, unsigned requests, one dangling-looking host, one wildcard
        "id": "sp-1", "appId": "app-1", "displayName": "Acme Portal",
        "preferredSingleSignOnMode": "saml", "accountEnabled": True,
        "appOwnerOrganizationId": TENANT_ID,
        "tags": ["WindowsAzureActiveDirectoryCustomSingleSignOnApplication"],
        "replyUrls": [
            "https://sp.contoso.com/portal/Shibboleth.sso/SAML2/POST",
            "https://legacy-sp.azurewebsites.net/Shibboleth.sso/SAML2/POST",
            "https://*.dev.contoso.com/saml/acs",
            "http://old-sp.contoso.com/saml/acs",
        ],
    },
    {   # SAML app with signing enforced - should be much quieter
        "id": "sp-2", "appId": "app-2", "displayName": "Finance SAML",
        "preferredSingleSignOnMode": "saml", "accountEnabled": True,
        "appOwnerOrganizationId": TENANT_ID, "tags": [],
        "replyUrls": ["https://finance.contoso.com/acs"],
    },
    {   # third-party SaaS
        "id": "sp-3", "appId": "app-3", "displayName": "VendorSaaS",
        "preferredSingleSignOnMode": "saml", "accountEnabled": True,
        "appOwnerOrganizationId": "22222222-2222-2222-2222-222222222222", "tags": [],
        "replyUrls": ["https://contoso.vendorsaas.io/sso/saml"],
    },
    {   # disabled SP still carrying URLs
        "id": "sp-4", "appId": "app-4", "displayName": "Retired App",
        "preferredSingleSignOnMode": "saml", "accountEnabled": False,
        "appOwnerOrganizationId": TENANT_ID, "tags": [],
        "replyUrls": ["https://retired.contoso.com/acs"],
    },
    {   # clean OIDC app
        "id": "sp-5", "appId": "app-5", "displayName": "Internal API Client",
        "preferredSingleSignOnMode": None, "accountEnabled": True,
        "appOwnerOrganizationId": TENANT_ID, "tags": [], "replyUrls": [],
    },
]

APPS = [
    {"id": "a-1", "appId": "app-1", "displayName": "Acme Portal",
     "requestSignatureVerification": {"isSignedRequestRequired": False},
     "keyCredentials": [], "web": {"redirectUris": []}},
    {"id": "a-2", "appId": "app-2", "displayName": "Finance SAML",
     "requestSignatureVerification": {"isSignedRequestRequired": True},
     "keyCredentials": [{"usage": "Verify"}], "web": {"redirectUris": []}},
    {"id": "a-4", "appId": "app-4", "displayName": "Retired App",
     "requestSignatureVerification": None, "keyCredentials": [],
     "web": {"redirectUris": []}},
    {"id": "a-5", "appId": "app-5", "displayName": "Internal API Client",
     "keyCredentials": [],
     "web": {"redirectUris": ["https://app.contoso.com/signin-oidc",
                              "http://localhost:5001/signin-oidc"]},
     "spa": {"redirectUris": ["https://legacy-spa.herokuapp.com/callback"]}},
]


def test_match_helpers() -> bool:
    ok = True

    # Exact match after normalisation (default port filled in, host lowercased).
    if acs_candidate_match(
        "https://sp.contoso.com/portal/Shibboleth.sso/SAML2/POST",
        "https://SP.contoso.com:443/portal/Shibboleth.sso/SAML2/POST",
    ) != "exact":
        print("FAIL - normalised exact match not detected")
        ok = False

    # A brand-new attacker URL matches nothing (Entra would return AADSTS50011).
    if acs_candidate_match(
        "https://sp.contoso.com/portal/Shibboleth.sso/SAML2/POST",
        "https://attacker.oast.me/saml/acs",
    ) is not None:
        print("FAIL - unrelated attacker URL should not match a real reply URL")
        ok = False

    # A wildcard reply URL swallows anything under it.
    if acs_candidate_match(
        "https://*.dev.contoso.com/saml/acs",
        "https://attacker.dev.contoso.com/saml/acs",
    ) != "wildcard":
        print("FAIL - wildcard reply URL did not match candidate under it")
        ok = False

    if normalise_for_match("https://Host.Example/") != "https://host.example:443/":
        print("FAIL - normalise_for_match did not canonicalise host/port/path")
        ok = False

    return ok


def test_acs_url_check() -> bool:
    ok = True

    # The exact SP reply URL is registered on app-1; supplying it as the
    # injected ACS URL must flag app-1 as ACCEPTED, and the wildcard on app-1
    # must also accept a host beneath *.dev.contoso.com.
    records = build_records(
        SPS, APPS, OWNED, TENANT_ID, include_all=False,
        acs_candidates=[
            "https://sp.contoso.com/portal/Shibboleth.sso/SAML2/POST",
            "https://evil.dev.contoso.com/saml/acs",
            "https://attacker.oast.me/saml/acs",
        ],
    )
    rows = flatten(records)
    codes = {c for r in rows for c in r["codes"].split(";") if c}
    if "ACS_URL_ACCEPTED" not in codes:
        print("FAIL - exact injected ACS URL was not flagged as accepted")
        ok = False
    if "ACS_URL_ACCEPTED_VIA_WILDCARD" not in codes:
        print("FAIL - wildcard-covered injected ACS URL was not flagged")
        ok = False

    accepting_apps = {
        r["app"] for r in rows
        if "ACS_URL_ACCEPTED" in r["codes"] or "ACS_URL_ACCEPTED_VIA_WILDCARD" in r["codes"]
    }
    if accepting_apps != {"Acme Portal"}:
        print(f"FAIL - unexpected apps accepted the injected URL: {accepting_apps}")
        ok = False

    return ok


def test_saml_only() -> bool:
    records = build_records(SPS, APPS, OWNED, TENANT_ID, include_all=True, saml_only=True)
    if any(not r.saml_capable for r in records):
        print("FAIL - --saml-only leaked a non-SAML app")
        return False
    return True


def test_malformed_and_logout_urls() -> bool:
    ok = True

    # Malformed reply URLs are reported, not fatal - even with ACS candidates,
    # which normalise every registered URL.
    sps = [{"id": "sp-x", "appId": "app-x", "displayName": "Broken", "tags": [],
            "replyUrls": ["http://[::1/acs", "https://h.contoso.com:99999/acs"]}]
    try:
        records = build_records(sps, [], OWNED, TENANT_ID, include_all=False,
                                acs_candidates=["https://attacker.oast.me/saml/acs"])
    except ValueError as exc:
        print(f"FAIL - malformed reply URL crashed the run: {exc}")
        return False
    codes = {f.code for r in records for u in r.urls for f in u.findings}
    if "UNPARSEABLE_URL" not in codes:
        print("FAIL - malformed reply URL was not reported as UNPARSEABLE_URL")
        ok = False

    # The logout URL never receives an assertion, so it is not an ACS match.
    apps = [{"id": "a-x", "appId": "app-y", "displayName": "Logout Only",
             "web": {"redirectUris": [], "logoutUrl": "https://sp.contoso.com/logout"}}]
    records = build_records([], apps, OWNED, TENANT_ID, include_all=False,
                            acs_candidates=["https://sp.contoso.com/logout"])
    if any(f.code.startswith("ACS_URL_ACCEPTED") for r in records for u in r.urls
           for f in u.findings):
        print("FAIL - logout URL was reported as an accepted ACS URL")
        ok = False

    return ok


def test_dns_host_selection() -> bool:
    # None of these can be answered by public DNS; querying them would turn
    # into a false DANGLING_DNS. resolve_host must skip them without a lookup.
    for host in ("localhost", "app.localhost", "8.8.8.8", "::1", "10.0.0.5",
                 "intranet", "*.contoso.com", ""):
        status, _ = resolve_host(host)
        if status != "skipped":
            print(f"FAIL - resolve_host({host!r}) returned {status!r}, expected 'skipped'")
            return False
    return True


def test_retry_delay() -> bool:
    class Resp:
        def __init__(self, headers):
            self.headers = headers

    cases = [
        (Resp({"Retry-After": "7"}), 1, 7.0),
        (Resp({"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}), 1, 0.0),  # date in the past
        (Resp({"Retry-After": "99999"}), 1, 120.0),                         # capped
        (Resp({"Retry-After": "soon"}), 3, 4.0),                            # unparseable -> backoff
        (None, 6, 30.0),                                                    # transport error
    ]
    for resp, attempt, expected in cases:
        got = retry_delay(resp, attempt)
        if got != expected:
            print(f"FAIL - retry_delay({resp and resp.headers}, {attempt}) = {got}, expected {expected}")
            return False
    return True


def test_include_clean_and_counts() -> bool:
    ok = True
    records = build_records(SPS, APPS, OWNED, TENANT_ID, include_all=True)
    rows = flatten(records)
    clean_rows = [r for r in rows if r["app"] == "Finance SAML"]
    if not clean_rows or any(r["severity"] != "CLEAN" for r in clean_rows):
        print(f"FAIL - --include-clean did not emit CLEAN rows for the clean app: {clean_rows}")
        ok = False

    # App-level codes count once per app, not once per URL row.
    unsigned = finding_counts(records)["SAML_UNSIGNED_REQUESTS_ACCEPTED"]
    if unsigned != 3:
        print(f"FAIL - SAML_UNSIGNED_REQUESTS_ACCEPTED counted {unsigned} times, expected 3 apps")
        ok = False
    return ok


def test_end_to_end_dump() -> bool:
    """main() on a dump: DNS must run before clean apps are dropped, so a
    hardened app whose only problem is a dangling reply URL is still reported."""
    dangling = "finance.contoso.com"
    fake_dns = lambda host, timeout=5.0: (("nxdomain", []) if host == dangling
                                          else ("resolves", []))
    with tempfile.TemporaryDirectory() as tmp:
        dump = os.path.join(tmp, "dump.json")
        out_json = os.path.join(tmp, "findings.json")
        out_csv = os.path.join(tmp, "findings.csv")
        # UTF-16 with BOM, as Windows PowerShell 5.1 `>` redirection writes it.
        with open(dump, "w", encoding="utf-16") as fh:
            json.dump({"tenantId": TENANT_ID, "verifiedDomains": sorted(OWNED),
                       "servicePrincipals": SPS, "applications": APPS}, fh)

        argv = ["acs_audit.py", "--from-dump", dump, "--out-json", out_json,
                "--out-csv", out_csv, "--fail-on", "CRITICAL"]
        saved = sys.argv, acs_audit.resolve_host
        sys.argv, acs_audit.resolve_host = argv, fake_dns
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = acs_audit.main()
        finally:
            sys.argv, acs_audit.resolve_host = saved

        with open(out_json, encoding="utf-8") as fh:
            report = json.load(fh)
        with open(out_csv, encoding="utf-8") as fh:
            csv_text = fh.read()

    if rc != 2:
        print(f"FAIL - --fail-on CRITICAL returned {rc}, expected 2")
        return False
    finance = [a for a in report["applications"] if a["display_name"] == "Finance SAML"]
    if not finance or finance[0]["severity"] != "CRITICAL" or not any(
        f["code"] == "DANGLING_DNS" for u in finance[0]["urls"] for f in u["findings"]
    ):
        print("FAIL - dangling reply URL on an otherwise clean app was not reported")
        return False
    if "Finance SAML" not in csv_text or not csv_text.startswith("severity,app,appId"):
        print("FAIL - CSV output missing the dangling-DNS row or its header")
        return False
    return True


def main() -> int:
    records = build_records(SPS, APPS, OWNED, TENANT_ID, include_all=False)
    rows = flatten(records)
    print_console(records, rows, quiet_info=False)

    codes = {c for r in rows for c in r["codes"].split(";") if c}
    expected = {
        "WILDCARD_REPLY_URL",
        "NON_HTTPS",
        "TAKEOVER_PRONE_NAMESPACE",
        "SAML_UNSIGNED_REQUESTS_ACCEPTED",
        "UNVERIFIED_DOMAIN",
        "DISABLED_SP_WITH_URLS",
        "LOOPBACK_OR_PRIVATE",
        "MULTITENANT_APP",
    }
    missing = expected - codes
    if missing:
        print(f"FAIL - detections not fired: {sorted(missing)}")
        return 1

    finance = [r for r in rows if r["app"] == "Finance SAML"]
    if finance:
        print(f"FAIL - hardened app produced findings: {finance}")
        return 1

    critical_apps = {r["app"] for r in rows if r["severity"] == "CRITICAL"}
    if "Acme Portal" not in critical_apps:
        print("FAIL - wildcard reply URL did not escalate to CRITICAL")
        return 1

    if not test_match_helpers():
        return 1
    if not test_acs_url_check():
        return 1
    if not test_saml_only():
        return 1
    if not test_malformed_and_logout_urls():
        return 1
    if not test_dns_host_selection():
        return 1
    if not test_retry_delay():
        return 1
    if not test_include_clean_and_counts():
        return 1
    if not test_end_to_end_dump():
        return 1

    print("PASS - all expected detections fired, hardened app is clean")
    print("PASS - injected ACS URL check, wildcard match, and --saml-only behave correctly")
    print("PASS - malformed URLs, DNS host selection, retry delays, --include-clean and "
          "end-to-end dump run behave correctly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
