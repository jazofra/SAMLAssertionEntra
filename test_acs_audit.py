#!/usr/bin/env python3
"""Offline tests for the detection logic. No tenant or network required.

    python3 test_acs_audit.py
"""

import sys

from acs_audit import (
    acs_candidate_match,
    build_records,
    flatten,
    normalise_for_match,
    print_console,
)

TENANT_ID = "11111111-1111-1111-1111-111111111111"
OWNED = {"contoso.com", "contoso.onmicrosoft.com"}

SPS = [
    {   # SAML app, unsigned requests, one dangling-looking host, one wildcard
        "id": "sp-1", "appId": "app-1", "displayName": "ROSS Portal",
        "preferredSingleSignOnMode": "saml", "accountEnabled": True,
        "appOwnerOrganizationId": TENANT_ID,
        "tags": ["WindowsAzureActiveDirectoryCustomSingleSignOnApplication"],
        "replyUrls": [
            "https://ross.contoso.com/portal/Shibboleth.sso/SAML2/POST",
            "https://ross-legacy.azurewebsites.net/Shibboleth.sso/SAML2/POST",
            "https://*.dev.contoso.com/saml/acs",
            "http://ross-old.contoso.com/saml/acs",
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
    {"id": "a-1", "appId": "app-1", "displayName": "ROSS Portal",
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
        "https://ross.contoso.com/portal/Shibboleth.sso/SAML2/POST",
        "https://ROSS.contoso.com:443/portal/Shibboleth.sso/SAML2/POST",
    ) != "exact":
        print("FAIL - normalised exact match not detected")
        ok = False

    # A brand-new attacker URL matches nothing (Entra would return AADSTS50011).
    if acs_candidate_match(
        "https://ross.contoso.com/portal/Shibboleth.sso/SAML2/POST",
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

    # The exact ROSS reply URL is registered on app-1; supplying it as the
    # injected ACS URL must flag app-1 as ACCEPTED, and the wildcard on app-1
    # must also accept a host beneath *.dev.contoso.com.
    records = build_records(
        SPS, APPS, OWNED, TENANT_ID, include_all=False,
        acs_candidates=[
            "https://ross.contoso.com/portal/Shibboleth.sso/SAML2/POST",
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
    if accepting_apps != {"ROSS Portal"}:
        print(f"FAIL - unexpected apps accepted the injected URL: {accepting_apps}")
        ok = False

    return ok


def test_saml_only() -> bool:
    records = build_records(SPS, APPS, OWNED, TENANT_ID, include_all=True, saml_only=True)
    if any(not r.saml_capable for r in records):
        print("FAIL - --saml-only leaked a non-SAML app")
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
    if "ROSS Portal" not in critical_apps:
        print("FAIL - wildcard reply URL did not escalate to CRITICAL")
        return 1

    if not test_match_helpers():
        return 1
    if not test_acs_url_check():
        return 1
    if not test_saml_only():
        return 1

    print("PASS - all expected detections fired, hardened app is clean")
    print("PASS - injected ACS URL check, wildcard match, and --saml-only behave correctly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
