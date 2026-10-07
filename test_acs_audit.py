#!/usr/bin/env python3
"""Offline tests for the detection logic. No tenant or network required.

    python3 test_acs_audit.py
"""

import base64
import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import time
import types

import acs_audit
from acs_audit import (
    GraphError,
    acs_candidate_match,
    build_records,
    check_token,
    console_safe,
    fetch_verified_domains,
    finding_counts,
    flatten,
    load_dump,
    normalise_for_match,
    print_console,
    resolve_host,
    retry_delay,
    strip_bearer,
    token_claims,
    write_csv,
    write_dump,
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

    # The query string is part of the exact match: /acs and /acs?x=1 are
    # different reply URLs, in either direction.
    query_cases = [
        ("https://sp.contoso.com/acs", "https://sp.contoso.com/acs?x=1", None),
        ("https://sp.contoso.com/acs?x=1", "https://sp.contoso.com/acs", None),
        ("https://sp.contoso.com/acs?x=1", "https://SP.contoso.com:443/acs?x=1", "exact"),
        ("https://sp.contoso.com/acs?x=1", "https://sp.contoso.com/acs?X=1", None),
        # A wildcard stays permissive: an appended query does not escape it.
        ("https://*.dev.contoso.com/saml/acs", "https://a.dev.contoso.com/saml/acs?x=1", "wildcard"),
    ]
    for registered, candidate, expected in query_cases:
        got = acs_candidate_match(registered, candidate)
        if got != expected:
            print(f"FAIL - acs_candidate_match({registered!r}, {candidate!r}) = {got!r}, "
                  f"expected {expected!r}")
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


def test_rule_refinements() -> bool:
    ok = True

    def url_codes(records, url):
        return {f.code for r in records for u in r.urls if u.url == url for f in u.findings}

    # An unparseable URL is reported once, not also as UNUSUAL_SCHEME; a URL
    # that parses but has no scheme says so.
    sps = [{"id": "sp-u", "appId": "app-u", "displayName": "Odd URLs", "tags": [],
            "replyUrls": ["http://[::1/acs", "sp.contoso.com/acs"]}]
    records = build_records(sps, [], OWNED, TENANT_ID, include_all=True)
    if url_codes(records, "http://[::1/acs") != {"UNPARSEABLE_URL"}:
        print(f"FAIL - unparseable URL codes: {url_codes(records, 'http://[::1/acs')}")
        ok = False
    details = [f.detail for r in records for u in r.urls if u.url == "sp.contoso.com/acs"
               for f in u.findings if f.code == "UNUSUAL_SCHEME"]
    if details != ["URL has no scheme"]:
        print(f"FAIL - scheme-less URL not reported as such: {details}")
        ok = False

    # Signed requests required: only a currently valid Verify cert counts.
    def signing_codes(key_credentials):
        sp = {"id": "sp-s", "appId": "app-s", "displayName": "Signed", "tags": [],
              "preferredSingleSignOnMode": "saml", "replyUrls": ["https://s.contoso.com/acs"]}
        app = {"id": "a-s", "appId": "app-s",
               "requestSignatureVerification": {"isSignedRequestRequired": True},
               "keyCredentials": key_credentials}
        recs = build_records([sp], [app], OWNED, TENANT_ID, include_all=True)
        return {f.code for r in recs for f in r.findings}

    cert_cases = [
        ([{"usage": "Verify", "endDateTime": "2020-01-01T00:00:00Z"}], True),           # expired
        ([{"usage": "Verify", "startDateTime": "2999-01-01T00:00:00Z"}], True),         # not yet valid
        ([{"usage": "Verify", "endDateTime": "2999-01-01T00:00:00.1234567Z"}], False),  # valid, 7 digits
        ([{"usage": "Verify", "endDateTime": "not a date"}], False),                    # unreadable
        ([{"usage": "Verify", "endDateTime": "2020-01-01T00:00:00Z"},
          {"usage": "Verify", "endDateTime": "2999-01-01T00:00:00Z"}], False),          # one still valid
        ([{"usage": "Sign", "endDateTime": "2999-01-01T00:00:00Z"}], True),             # wrong usage
    ]
    for creds, should_fire in cert_cases:
        fired = "SIGNING_ENFORCED_NO_VERIFY_CERT" in signing_codes(creds)
        if fired != should_fire:
            print(f"FAIL - SIGNING_ENFORCED_NO_VERIFY_CERT fired={fired} for {creds}")
            ok = False

    # The logout URL counts towards neither the URL-surface threshold nor the
    # "disabled SP still has reply URLs" check.
    def app_codes(redirect_count, enabled=True):
        sp = {"id": "sp-l", "appId": "app-l", "displayName": "Logout", "tags": [],
              "accountEnabled": enabled, "replyUrls": []}
        app = {"id": "a-l", "appId": "app-l", "web": {
            "redirectUris": [f"https://r{i}.contoso.com/cb" for i in range(redirect_count)],
            "logoutUrl": "https://sp.contoso.com/logout"}}
        recs = build_records([sp], [app], OWNED, TENANT_ID, include_all=True)
        return {f.code for r in recs for f in r.findings}

    if "LARGE_REPLY_URL_SURFACE" in app_codes(9):
        print("FAIL - 9 redirect URIs plus a logout URL tripped LARGE_REPLY_URL_SURFACE")
        ok = False
    if "LARGE_REPLY_URL_SURFACE" not in app_codes(10):
        print("FAIL - 10 redirect URIs did not trip LARGE_REPLY_URL_SURFACE")
        ok = False
    if "DISABLED_SP_WITH_URLS" in app_codes(0, enabled=False):
        print("FAIL - disabled SP with only a logout URL reported DISABLED_SP_WITH_URLS")
        ok = False
    if "DISABLED_SP_WITH_URLS" not in app_codes(1, enabled=False):
        print("FAIL - disabled SP with a redirect URI did not report DISABLED_SP_WITH_URLS")
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


def fake_jwt(claims: dict) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


def run_main(argv: list[str]) -> tuple[int | str | None, str, str]:
    """Run acs_audit.main() with argv; returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    saved = sys.argv
    sys.argv = ["acs_audit.py"] + argv
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = acs_audit.main()
            except SystemExit as exc:
                rc = exc.code
    finally:
        sys.argv = saved
    return rc, out.getvalue(), err.getvalue()


def test_url_classification() -> bool:
    ok = True

    def codes(url, saml=True):
        sp = {"id": "sp-c", "appId": "app-c", "displayName": "C", "tags": [],
              "preferredSingleSignOnMode": "saml" if saml else None, "replyUrls": [url]}
        recs = build_records([sp], [], OWNED, TENANT_ID, include_all=True)
        return {f.code for r in recs for u in r.urls for f in u.findings}

    # Cleartext is fine only over loopback; private and link-local traffic
    # leaves the machine.
    for url, cleartext in [
        ("http://localhost:5001/cb", False), ("http://127.0.0.1/cb", False),
        ("http://[::1]:8080/cb", False), ("http://app.localhost/cb", False),
        ("http://10.0.0.5/acs", True), ("http://169.254.10.1/acs", True),
        ("http://192.168.1.10/acs", True),
    ]:
        if ("NON_HTTPS" in codes(url)) != cleartext:
            print(f"FAIL - NON_HTTPS for {url}: expected {cleartext}, codes {codes(url)}")
            ok = False

    # A trailing dot is the same host: it must not dodge the namespace check
    # nor trip UNVERIFIED_DOMAIN for an owned domain.
    got = codes("https://legacy.azurewebsites.net./acs")
    if "TAKEOVER_PRONE_NAMESPACE" not in got:
        print(f"FAIL - trailing-dot host escaped TAKEOVER_PRONE_NAMESPACE: {got}")
        ok = False
    got = codes("https://sp.contoso.com./acs")
    if "UNVERIFIED_DOMAIN" in got:
        print(f"FAIL - trailing-dot owned host reported UNVERIFIED_DOMAIN: {got}")
        ok = False

    # Public IP literals get their own finding instead of UNVERIFIED_DOMAIN;
    # private ones stay LOOPBACK_OR_PRIVATE.
    for url, expected in [
        ("https://52.10.20.30/saml/acs", {"IP_LITERAL_HOST"}),
        ("https://[2603:1030:20e::10]/saml/acs", {"IP_LITERAL_HOST"}),
        ("https://10.0.0.5/saml/acs", {"LOOPBACK_OR_PRIVATE"}),
    ]:
        if codes(url) != expected:
            print(f"FAIL - {url}: expected {expected}, got {codes(url)}")
            ok = False
    return ok


def test_hostile_directory_data() -> bool:
    ok = True

    # A wildcard reply URL with many stars once took minutes to match by regex.
    registered = "https://" + "*a" * 40 + ".contoso.com/x"
    candidate = "https://" + "a" * 200 + ".example.com/x"
    start = time.monotonic()
    result = acs_candidate_match(registered, candidate)
    if result is not None or time.monotonic() - start > 1:
        print(f"FAIL - hostile wildcard: result {result!r} after "
              f"{time.monotonic() - start:.1f}s")
        ok = False

    # Names and URLs from other tenants must not run as spreadsheet formulas
    # or terminal escape sequences.
    sps = [{"id": "sp-h", "appId": "app-h", "displayName": "=HYPERLINK(\"http://x\",\"y\")",
            "tags": [], "replyUrls": ["https://evil.example/acs"]}]
    rows = flatten(build_records(sps, [], OWNED, TENANT_ID, include_all=True))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "out.csv")
        write_csv(path, rows)
        with open(path, encoding="utf-8", newline="") as fh:
            apps = [r["app"] for r in csv.DictReader(fh)]
    if apps != ["'=HYPERLINK(\"http://x\",\"y\")"]:
        print(f"FAIL - formula-like display name not neutralised in CSV: {apps}")
        ok = False
    shown = console_safe("App\x1b[2J‮evil")
    if "\x1b" in shown or "‮" in shown or shown != "App\\u001b[2J\\u202eevil":
        print(f"FAIL - console_safe left control characters: {shown!r}")
        ok = False
    return ok


def test_token_handling() -> bool:
    ok = True
    other = "33333333-3333-3333-3333-333333333333"
    token = fake_jwt({"tid": TENANT_ID, "exp": time.time() + 3600})

    if token_claims(token).get("tid") != TENANT_ID or token_claims("opaque-token") != {}:
        print("FAIL - token_claims did not decode a JWT / tolerate an opaque token")
        ok = False
    if strip_bearer(f"Bearer {token}\n") != token:
        print("FAIL - strip_bearer did not remove the Bearer prefix")
        ok = False
    if check_token(token_claims(token), "contoso.com") != TENANT_ID \
            or check_token(token_claims(token), TENANT_ID.upper()) != TENANT_ID:
        print("FAIL - check_token did not return the token's tenant")
        ok = False
    for claims, label in [({"tid": TENANT_ID, "exp": time.time() - 60}, "expired token"),
                          ({"tid": other}, "token for another tenant")]:
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                check_token(claims, TENANT_ID)
            print(f"FAIL - check_token accepted an {label}")
            ok = False
        except SystemExit:
            pass
    return ok


def test_credential_selection() -> bool:
    """Which sign-in acquire_token picks, using a stand-in msal module."""
    calls = []

    class Confidential:
        def __init__(self, client_id, authority, client_credential, **kw):
            calls.append(("confidential", client_id, authority, client_credential))

        def acquire_token_for_client(self, scopes):
            calls.append(("scopes", scopes))
            return {"access_token": "app-token"}

    class Public:
        def __init__(self, client_id, authority, **kw):
            calls.append(("public", client_id, authority))

        def initiate_device_flow(self, scopes):
            calls.append(("scopes", scopes))
            return {"user_code": "X", "message": "sign in"}

        def acquire_token_by_device_flow(self, flow):
            return {"access_token": "user-token"}

    def args(**kw):
        base = dict(access_token=None, client_id=None, client_secret=None, client_cert=None,
                    device_code=False, tenant=TENANT_ID, cloud="global", proxy=None,
                    ca_bundle=None)
        base.update(kw)
        return types.SimpleNamespace(**base)

    ok = True
    saved_env = {k: os.environ.pop(k, None) for k in ("GRAPH_TOKEN", "AZURE_CLIENT_SECRET")}
    saved_msal = sys.modules.get("msal")
    sys.modules["msal"] = types.SimpleNamespace(ConfidentialClientApplication=Confidential,
                                                PublicClientApplication=Public)
    try:
        def pick(env=None, **kw):
            calls.clear()
            os.environ.update(env or {})
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    return acs_audit.acquire_token(args(**kw))
            finally:
                for k in env or {}:
                    os.environ.pop(k, None)

        cases = [
            # (env, flags, expected token, expected first msal call kind)
            ({"GRAPH_TOKEN": "env-token"}, {}, "env-token", None),
            ({"GRAPH_TOKEN": "env-token"}, {"client_id": "cid", "client_secret": "s"},
             "app-token", "confidential"),
            ({"GRAPH_TOKEN": "env-token"}, {"device_code": True}, "user-token", "public"),
            ({"AZURE_CLIENT_SECRET": "env-secret"}, {"client_id": "cid"}, "app-token",
             "confidential"),
            ({"AZURE_CLIENT_SECRET": "env-secret"}, {"client_id": "cid", "device_code": True},
             "user-token", "public"),
            ({}, {"access_token": "Bearer abc"}, "abc", None),
        ]
        for env, flags, want_token, want_kind in cases:
            got = pick(env, **flags)
            kind = calls[0][0] if calls else None
            if got != want_token or kind != want_kind:
                print(f"FAIL - acquire_token env={env} flags={flags}: got {got!r} via {kind}, "
                      f"expected {want_token!r} via {want_kind}")
                ok = False

        pick({"AZURE_CLIENT_SECRET": "env-secret"}, client_id="cid")
        if calls[0][3] != "env-secret":
            print(f"FAIL - $AZURE_CLIENT_SECRET was not used as the credential: {calls[0]}")
            ok = False

        pick(cloud="usgov")
        if calls[0][2] != f"https://login.microsoftonline.us/{TENANT_ID}" \
                or calls[1][1] != ["https://graph.microsoft.us/.default"]:
            print(f"FAIL - --cloud usgov used the wrong sign-in host or scope: {calls}")
            ok = False

        cert_ok = test_client_certificate(pick, calls)
    finally:
        if saved_msal is None:
            sys.modules.pop("msal", None)
        else:
            sys.modules["msal"] = saved_msal
        for k, v in saved_env.items():
            if v is not None:
                os.environ[k] = v
    return ok and cert_ok


def test_client_certificate(pick, calls) -> bool:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("SKIP - cryptography not installed; certificate auth not tested")
        return True
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acs-audit-test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    def key_pem(password=None):
        enc = (serialization.BestAvailableEncryption(password) if password
               else serialization.NoEncryption())
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8, enc)

    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        files = {
            "cert-then-key.pem": (cert_pem + key_pem(), None),
            "key-then-cert.pem": (key_pem() + cert_pem, None),
            "encrypted.pem": (key_pem(b"pw") + cert_pem, "pw"),
            "bundle.pfx": (pkcs12.serialize_key_and_certificates(
                b"t", key, cert, None, serialization.BestAvailableEncryption(b"pw")), "pw"),
        }
        for fname, (data, password) in files.items():
            path = os.path.join(tmp, fname)
            with open(path, "wb") as fh:
                fh.write(data)
            env = {"AZURE_CLIENT_CERTIFICATE_PASSWORD": password} if password else {}
            pick(env, client_id="cid", client_cert=path)
            credential = calls[0][3] if calls else None
            if not isinstance(credential, dict) or credential.get("thumbprint") != thumbprint \
                    or "BEGIN PRIVATE KEY" not in credential.get("private_key", ""):
                print(f"FAIL - --client-cert {fname} produced {credential!r}")
                ok = False
        try:
            pick({"AZURE_CLIENT_CERTIFICATE_PASSWORD": "wrong"}, client_id="cid",
                 client_cert=os.path.join(tmp, "bundle.pfx"))
            print("FAIL - a wrong PFX password was accepted")
            ok = False
        except SystemExit:
            pass
    return ok


def test_dump_and_domains() -> bool:
    ok = True

    # A token without Directory.Read.All cannot read /domains: lose the
    # ownership baseline, keep the run.
    class Denied:
        def paged(self, path, params=None, label=None):
            raise GraphError(403, "Authorization_RequestDenied", path)

    with contextlib.redirect_stderr(io.StringIO()):
        if fetch_verified_domains(Denied()) != set():
            print("FAIL - a 403 on /domains was not tolerated")
            ok = False

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "dump.json")
        write_dump(path, SPS, APPS, TENANT_ID, OWNED)
        if load_dump(path) != (SPS, APPS, TENANT_ID, OWNED):
            print("FAIL - --save-dump output does not load back unchanged")
            ok = False
        # A raw Graph page ({"value": [...]}) is accepted for either array.
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"servicePrincipals": {"value": SPS}, "applications": {"value": APPS}}, fh)
        if load_dump(path)[:2] != (SPS, APPS):
            print("FAIL - a raw Graph page was not accepted in a dump")
            ok = False
    return ok


def test_end_to_end_graph() -> bool:
    """main() against a stand-in Graph: a least-privilege token (no /domains,
    no /organization) still audits, takes the tenant ID from the token, and
    --save-dump writes a file --from-dump can read."""
    seen_roots = []

    class FakeGraph:
        def __init__(self, token, graph, **kw):
            self.graph = graph
            seen_roots.append(graph)

        def paged(self, path, params=None, label=None):
            if path == "/servicePrincipals":
                return iter(SPS)
            if path == "/applications":
                return iter(APPS)
            raise GraphError(403, "Authorization_RequestDenied", path)

        def get(self, url, params=None):
            raise GraphError(403, "Authorization_RequestDenied", url)

    token = fake_jwt({"tid": TENANT_ID, "exp": time.time() + 3600})
    saved = acs_audit.GraphClient, acs_audit.acquire_token
    acs_audit.GraphClient = FakeGraph
    acs_audit.acquire_token = lambda args: token
    ok = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            dump, out_json = os.path.join(tmp, "dump.json"), os.path.join(tmp, "f.json")
            rc, _, err = run_main(["--tenant", "contoso.com", "--skip-dns", "--cloud", "usgov",
                                   "--save-dump", dump, "--out-json", out_json])
            if rc != 0:
                print(f"FAIL - online run exited {rc}: {err[-500:]}")
                return False
            with open(out_json, encoding="utf-8") as fh:
                report = json.load(fh)
            codes = {f["code"] for a in report["applications"] for f in a["findings"]}
            if report["metadata"]["tenantId"] != TENANT_ID or "MULTITENANT_APP" not in codes:
                print("FAIL - tenant ID was not taken from the token when /organization is denied")
                ok = False
            if seen_roots != ["https://graph.microsoft.us/v1.0"]:
                print(f"FAIL - --cloud usgov did not select the US Gov Graph: {seen_roots}")
                ok = False
            if load_dump(dump) != (SPS, APPS, TENANT_ID, set()):
                print("FAIL - --save-dump did not write the enumerated data")
                ok = False

            # A token for another tenant than a GUID --tenant must stop the run.
            other = "33333333-3333-3333-3333-333333333333"
            rc, _, err = run_main(["--tenant", other, "--skip-dns"])
            if rc in (0, None) or "refusing to audit" not in str(rc):
                print(f"FAIL - token/tenant mismatch did not stop the run: {rc!r}")
                ok = False

            # Output paths are checked before anything runs.
            rc, _, err = run_main(["--from-dump", dump, "--out-csv",
                                   os.path.join(tmp, "missing", "f.csv")])
            if rc != 2 or "directory does not exist" not in err:
                print(f"FAIL - a missing output directory was not rejected up front: {rc!r}")
                ok = False
    finally:
        acs_audit.GraphClient, acs_audit.acquire_token = saved
    return ok


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
    if not test_rule_refinements():
        return 1
    if not test_dns_host_selection():
        return 1
    if not test_retry_delay():
        return 1
    if not test_include_clean_and_counts():
        return 1
    if not test_end_to_end_dump():
        return 1
    for test in (test_url_classification, test_hostile_directory_data, test_token_handling,
                 test_credential_selection, test_dump_and_domains, test_end_to_end_graph):
        if not test():
            return 1

    print("PASS - all expected detections fired, hardened app is clean")
    print("PASS - injected ACS URL check, wildcard match, and --saml-only behave correctly")
    print("PASS - malformed URLs, DNS host selection, retry delays, --include-clean and "
          "end-to-end dump run behave correctly")
    print("PASS - query-string matching, scheme reporting, Verify cert validity and "
          "logout-URL exclusions behave correctly")
    print("PASS - host classification, hostile directory data, token checks, credential "
          "selection, dumps and the online Graph path behave correctly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
