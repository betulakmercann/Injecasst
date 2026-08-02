import sys
import os
import time
import requests
import json
import re
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser

analysis_results = {
    "endpoint": "",
    "status": 0,
    "server": "Unknown",
    "transport": {
        "scheme": "Unknown",
        "final_url": "",
        "redirect_count": 0,
        "response_time_ms": 0,
        "content_type": "Unknown",
        "content_length": 0
    },
    "infrastructure": {
        "provider": "Not identified",
        "evidence": [],
        "confidence": "LOW"
    },
    "authentication": {
        "panel_detected": False,
        "password_field_detected": False,
        "username_field_detected": False,
        "email_field_detected": False,
        "forms_analyzed": 0,
        "authentication_forms": [],
        "discovered_endpoints": [],
        "authentication_references": [],
        "dynamic_indicators": [],
        "evidence": [],
        "confidence": "LOW"
    },
    "security_headers": {
        "present": [],
        "missing": [],
        "informational": []
    },
    "waf": {
        "provider": "Unknown",
        "infrastructure_detected": False,
        "enforcement_confirmed": False,
        "evidence": [],
        "confidence": "LOW"
    },
    "assessment": {
        "confirmed_findings": 0,
        "observed_findings": 0,
        "not_tested": 0,
        "risk_level": "UNDETERMINED",
        "scope": "PASSIVE HTTP / HTML / RESOURCE ANALYSIS",
        "confidence": "LIMITED"
    },
    "vulnerability_findings": [],
    "remediation_plan": [],
    "evidence": []
}

target_url = ""
menu_callback = None


class SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current_form = None
        self.links = []
        self.scripts = []
        self.inputs = []
        self.text_parts = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = {
            str(k).lower(): str(v) if v is not None else ""
            for k, v in attrs
        }

        if tag.lower() == "form":
            self.current_form = {
                "attributes": attrs_dict,
                "inputs": []
            }
            self.forms.append(self.current_form)

        elif tag.lower() == "input":
            item = attrs_dict.copy()
            self.inputs.append(item)
            if self.current_form is not None:
                self.current_form["inputs"].append(item)

        elif tag.lower() in ("a", "link"):
            value = attrs_dict.get("href", "")
            if value:
                self.links.append(value)

        elif tag.lower() == "script":
            value = attrs_dict.get("src", "")
            if value:
                self.scripts.append(value)

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self.current_form = None

    def handle_data(self, data):
        value = data.strip()
        if value:
            self.text_parts.append(value)


def local_clear():
    os.system("clear")
    print("\x1b[0m", end="")


def draw_local_box(title):
    print("\x1b[38;2;147;51;234m╔══════════════════════════════════════════════════════════════════════╗\x1b[0m")
    padding_total = max(0, 68 - len(title))
    pad_left = padding_total // 2
    pad_right = padding_total - pad_left
    print(
        "\x1b[38;2;147;51;234m║\x1b[0m"
        + " " * pad_left
        + f"\x1b[38;2;59;130;246m\x1b[1m{title}\x1b[0m"
        + " " * pad_right
        + "\x1b[38;2;147;51;234m║\x1b[0m"
    )
    print("\x1b[38;2;147;51;234m╚══════════════════════════════════════════════════════════════════════╝\x1b[0m")


def add_unique(items, value):
    if value and value not in items:
        items.append(value)


def same_origin(url_a, url_b):
    try:
        a = urlparse(url_a)
        b = urlparse(url_b)
        return (
            a.scheme.lower() == b.scheme.lower()
            and a.hostname.lower() == b.hostname.lower()
            and (a.port or (443 if a.scheme == "https" else 80))
            == (b.port or (443 if b.scheme == "https" else 80))
        )
    except Exception:
        return False


def normalize_url(value, base_url):
    if not value:
        return ""

    value = value.strip()

    if value.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return ""

    return urljoin(base_url, value)


def detect_infrastructure(response):
    headers = {
        key.lower(): str(value).lower()
        for key, value in response.headers.items()
    }

    cookies = " ".join(
        cookie.name.lower()
        for cookie in response.cookies
    )

    cloudflare = []

    if "cf-ray" in headers:
        cloudflare.append("CF-Ray response header")

    if "cf-cache-status" in headers:
        cloudflare.append("CF-Cache-Status response header")

    if "cloudflare" in headers.get("server", ""):
        cloudflare.append("Server response header identifies Cloudflare")

    if "__cf_bm" in cookies:
        cloudflare.append("__cf_bm cookie")

    if "cf_clearance" in cookies:
        cloudflare.append("cf_clearance cookie")

    if cloudflare:
        return (
            "Cloudflare",
            cloudflare,
            "HIGH" if len(cloudflare) >= 2 else "MEDIUM"
        )

    akamai = []

    if "akamai" in headers.get("server", ""):
        akamai.append("Server response header identifies Akamai")

    if "akamai-origin-hop" in headers:
        akamai.append("Akamai-Origin-Hop response header")

    if "x-akamai-transformed" in headers:
        akamai.append("X-Akamai-Transformed response header")

    if akamai:
        return (
            "Akamai",
            akamai,
            "HIGH" if len(akamai) >= 2 else "MEDIUM"
        )

    fastly = []

    if "fastly" in headers.get("via", ""):
        fastly.append("Via response header references Fastly")

    if "x-served-by" in headers:
        fastly.append("X-Served-By response header")

    if "x-cache" in headers:
        fastly.append("X-Cache response header")

    if fastly:
        return (
            "Fastly",
            fastly,
            "MEDIUM"
        )

    return "Not identified", [], "LOW"



def analyze_forms(parser, response):
    auth = analysis_results["authentication"]

    for index, form in enumerate(parser.forms, 1):
        attrs = form["attributes"]

        action = normalize_url(
            attrs.get("action", ""),
            response.url
        )

        if not action:
            action = response.url

        method = attrs.get("method", "GET").upper()

        password = False
        username = False
        email = False

        for field in form["inputs"]:
            field_type = field.get("type", "text").lower()
            name = field.get("name", "").lower()
            field_id = field.get("id", "").lower()
            autocomplete = field.get("autocomplete", "").lower()
            placeholder = field.get("placeholder", "").lower()
            aria = field.get("aria-label", "").lower()

            combined = " ".join([
                name,
                field_id,
                autocomplete,
                placeholder,
                aria
            ])

            if field_type == "password":
                password = True

            if any(
                token in combined
                for token in (
                    "username",
                    "user-name",
                    "user_name",
                    "login",
                    "identifier",
                    "useremail",
                    "user_email"
                )
            ):
                username = True

            if field_type == "email" or "email" in combined:
                email = True

        form_result = {
            "index": index,
            "action": action,
            "method": method,
            "password_field": password,
            "username_field": username,
            "email_field": email
        }

        auth["authentication_forms"].append(form_result)

        if password:
            auth["password_field_detected"] = True
            auth["panel_detected"] = True
            add_unique(
                auth["evidence"],
                f"Password input detected in form #{index}"
            )

        if username:
            auth["username_field_detected"] = True
            add_unique(
                auth["evidence"],
                f"Username-related input detected in form #{index}"
            )

        if email:
            auth["email_field_detected"] = True
            add_unique(
                auth["evidence"],
                f"Email-related input detected in form #{index}"
            )

        if password and method == "POST":
            add_unique(
                auth["evidence"],
                f"Password-bearing form #{index} submits via POST"
            )

        if password and method == "GET":
            add_unique(
                auth["evidence"],
                f"Password-bearing form #{index} submits via GET"
            )

        if (
            action
            and same_origin(response.url, action)
            and (
                password
                or username
                or email
                or any(
                    token in action.lower()
                    for token in (
                        "/login",
                        "/signin",
                        "/sign-in",
                        "/authenticate",
                        "/auth",
                        "/session",
                        "/account"
                    )
                )
            )
        ):
            add_unique(
                auth["discovered_endpoints"],
                action
            )


    auth["forms_analyzed"] = len(parser.forms)



def discover_authentication_surface(parser, response):
    auth = analysis_results["authentication"]

    html = response.text or ""
    html_lower = html.lower()

    # Strong authentication route indicators.
    # These are intentionally path-oriented to reduce false positives.
    auth_path_patterns = (
        r"/login(?:[/?#]|$)",
        r"/signin(?:[/?#]|$)",
        r"/sign-in(?:[/?#]|$)",
        r"/sign_in(?:[/?#]|$)",
        r"/giris(?:[/?#]|$)",
        r"/giriş(?:[/?#]|$)",
        r"/authenticate(?:[/?#]|$)",
        r"/authentication(?:[/?#]|$)",
        r"/auth(?:[/?#]|$)",
        r"/session(?:[/?#]|$)",
        r"/oauth(?:[/?#]|$)",
        r"/openid(?:[/?#]|$)",
        r"/account(?:[/?#]|$)"
    )

    # API-specific authentication paths.
    auth_api_patterns = (
        r"/api/(?:v\d+/)?(?:login|signin|sign-in|auth|authenticate|authentication|session|account)(?:[/?#]|$)",
        r"/api/(?:v\d+/)?(?:users?)/(?:login|signin|authenticate)(?:[/?#]|$)"
    )

    # UI language is treated separately from endpoints.
    ui_terms = (
        "login",
        "sign in",
        "signin",
        "log in",
        "giriş yap",
        "giris yap",
        "oturum aç",
        "oturum ac"
    )

    def is_valid_auth_reference(value):
        if not value:
            return False

        value = value.strip()

        # Reject obvious HTML / source-code fragments.
        if any(
            bad in value.lower()
            for bad in (
                "<script",
                "</script",
                "gtmscript",
                "window[",
                "network error",
                "snapchat.com",
                "pinterest.com",
                "googletagmanager.com",
                "google-analytics.com",
                "doubleclick.net"
            )
        ):
            return False

        try:
            parsed = urlparse(value)

            path_query = (
                parsed.path.lower()
                + "?"
                + parsed.query.lower()
            )

            return any(
                re.search(pattern, path_query, flags=re.IGNORECASE)
                for pattern in auth_path_patterns + auth_api_patterns
            )

        except Exception:
            return False

    def register_endpoint(value, source_label):
        if not value:
            return

        value = value.strip()

        # Remove trailing punctuation frequently found in JS strings.
        value = value.rstrip(" \t\r\n;,.)]}")

        normalized = normalize_url(
            value,
            response.url
        )

        if not normalized:
            return

        if not is_valid_auth_reference(normalized):
            return

        parsed = urlparse(normalized)

        # Only retain HTTP(S) URLs.
        if parsed.scheme.lower() not in ("http", "https"):
            return

        add_unique(
            auth["discovered_endpoints"],
            normalized
        )

        add_unique(
            auth["evidence"],
            f"{source_label}: {normalized}"
        )

    # ---------------------------------------------------------
    # 1. Analyze HTML links.
    # ---------------------------------------------------------

    for value in parser.links:
        normalized = normalize_url(
            value,
            response.url
        )

        if is_valid_auth_reference(normalized):
            register_endpoint(
                normalized,
                "Authentication-related link observed"
            )

    # ---------------------------------------------------------
    # 2. Analyze JavaScript resources.
    # ---------------------------------------------------------

    for value in parser.scripts:
        normalized = normalize_url(
            value,
            response.url
        )

        if is_valid_auth_reference(normalized):
            register_endpoint(
                normalized,
                "Authentication-related script reference observed"
            )

    # ---------------------------------------------------------
    # 3. Extract actual URL/path strings from HTML/JS.
    # ---------------------------------------------------------

    url_candidates = set()

    # Absolute URLs.
    absolute_urls = re.findall(
        r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""",
        html,
        flags=re.IGNORECASE
    )

    url_candidates.update(absolute_urls)

    # Relative paths.
    relative_paths = re.findall(
        r"""["'`]((?:/|\./|\.\./)[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,300})["'`]""",
        html,
        flags=re.IGNORECASE
    )

    url_candidates.update(relative_paths)

    for candidate in url_candidates:
        register_endpoint(
            candidate,
            "Authentication-related client reference observed"
        )

    # ---------------------------------------------------------
    # 4. Specifically inspect fetch / axios / XHR.
    #    Do NOT accept arbitrary strings after these APIs.
    # ---------------------------------------------------------

    api_call_pattern = re.compile(
        r"""
        (?:
            fetch
            |
            axios\.(?:get|post|put|patch|delete)
            |
            XMLHttpRequest
        )
        [\s\S]{0,250}?
        (?:
            ["'`]([^"'`]{1,300})["'`]
        )
        """,
        flags=re.IGNORECASE | re.VERBOSE
    )

    for match in api_call_pattern.finditer(html):
        candidate = match.group(1)

        if not candidate:
            continue

        register_endpoint(
            candidate,
            "Authentication-related client API reference observed"
        )

    # ---------------------------------------------------------
    # 5. Authentication UI references.
    # ---------------------------------------------------------

    ui_matches = 0

    for term in ui_terms:
        if term in html_lower:
            ui_matches += 1

    if ui_matches:
        add_unique(
            auth["authentication_references"],
            f"Authentication UI language ({ui_matches} indicator(s))"
        )

        add_unique(
            auth["evidence"],
            f"Authentication-related UI language observed ({ui_matches} indicator(s))"
        )

    # ---------------------------------------------------------
    # 6. Dynamic application indicators.
    # ---------------------------------------------------------

    if parser.scripts:
        add_unique(
            auth["dynamic_indicators"],
            f"{len(parser.scripts)} JavaScript resource reference(s) observed"
        )

    script_tags = len(
        re.findall(
            r"<script\b",
            html,
            flags=re.IGNORECASE
        )
    )

    if script_tags:
        add_unique(
            auth["dynamic_indicators"],
            f"{script_tags} script element(s) observed in analyzed HTML"
        )

    dynamic_terms = (
        "window.__next_data__",
        "__next_f.push",
        "webpack",
        "vite",
        "react",
        "angular",
        "vue",
        "graphql",
        "oauth",
        "openid",
        "fetch(",
        "axios.",
        "xmlhttprequest"
    )

    for term in dynamic_terms:
        if term in html_lower:
            add_unique(
                auth["dynamic_indicators"],
                f"Dynamic application indicator observed: {term}"
            )

    # ---------------------------------------------------------
    # 7. Determine authentication panel.
    # ---------------------------------------------------------

    if (
        auth["password_field_detected"]
        or auth["username_field_detected"]
        or auth["email_field_detected"]
    ):
        auth["panel_detected"] = True

    elif auth["discovered_endpoints"]:
        add_unique(
            auth["evidence"],
            "Authentication route(s) observed without a native HTML credential form."
        )

    elif ui_matches:
        add_unique(
            auth["evidence"],
            "Authentication UI indicators observed without a native HTML credential form."
        )

    # ---------------------------------------------------------
    # 8. Confidence.
    # ---------------------------------------------------------

    if auth["password_field_detected"]:
        auth["confidence"] = "HIGH"

    elif (
        auth["discovered_endpoints"]
        and auth["dynamic_indicators"]
    ):
        auth["confidence"] = "HIGH"

    elif (
        auth["discovered_endpoints"]
        or ui_matches
        or auth["forms_analyzed"] > 0
    ):
        auth["confidence"] = "MEDIUM"

    else:
        auth["confidence"] = "LOW"

def analyze_security_headers(response):
    header_definitions = {
        "Content-Security-Policy": "content-security-policy",
        "Strict-Transport-Security": "strict-transport-security",
        "X-Content-Type-Options": "x-content-type-options",
        "X-Frame-Options": "x-frame-options",
        "Referrer-Policy": "referrer-policy",
        "Permissions-Policy": "permissions-policy"
    }

    present = []
    missing = []

    response_headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    for display_name, header_name in header_definitions.items():
        if header_name in response_headers:
            present.append(display_name)
        else:
            missing.append(display_name)

    informational = []

    csp = response_headers.get(
        "content-security-policy",
        ""
    ).lower()

    x_frame = response_headers.get(
        "x-frame-options",
        ""
    ).lower()

    if x_frame:
        informational.append(
            "X-Frame-Options is explicitly present."
        )
    elif "frame-ancestors" in csp:
        informational.append(
            "X-Frame-Options is absent, but CSP frame-ancestors is present."
        )

        if "X-Frame-Options" in missing:
            missing.remove("X-Frame-Options")

    if "strict-transport-security" not in response_headers:
        if urlparse(response.url).scheme == "https":
            informational.append(
                "HSTS was not observed in the response headers."
            )

    analysis_results["security_headers"]["present"] = present
    analysis_results["security_headers"]["missing"] = missing
    analysis_results["security_headers"]["informational"] = informational

def evaluate_waf(provider, infrastructure_evidence):
    waf = analysis_results["waf"]

    waf["provider"] = provider

    if provider != "Not identified":
        waf["infrastructure_detected"] = True
        waf["enforcement_confirmed"] = False
        waf["confidence"] = analysis_results["infrastructure"]["confidence"]

        for evidence in infrastructure_evidence:
            add_unique(waf["evidence"], evidence)

        add_unique(
            waf["evidence"],
            "Edge security infrastructure fingerprint observed"
        )

        add_unique(
            waf["evidence"],
            "Active WAF enforcement was not verified by passive analysis"
        )
    else:
        waf["infrastructure_detected"] = False
        waf["enforcement_confirmed"] = False
        waf["confidence"] = "LOW"



def build_assessment():
    auth = analysis_results["authentication"]
    infrastructure = analysis_results["infrastructure"]
    security_headers = analysis_results["security_headers"]
    assessment = analysis_results["assessment"]

    observed = 0
    not_tested = 0

    if auth["panel_detected"]:
        observed += 1

    if auth["discovered_endpoints"]:
        observed += 1

    if auth["dynamic_indicators"]:
        observed += 1

    if infrastructure["provider"] != "Not identified":
        observed += 1

    if security_headers["missing"]:
        observed += 1

    not_tested += 1

    if not analysis_results["waf"]["enforcement_confirmed"]:
        not_tested += 1

    assessment["confirmed_findings"] = 0
    assessment["observed_findings"] = observed
    assessment["not_tested"] = not_tested
    assessment["risk_level"] = "UNDETERMINED"

    assessment["scope"] = (
        "PASSIVE HTTP / HTML / RESOURCE / CLIENT-SIDE REFERENCE ANALYSIS"
    )

    if (
        auth["password_field_detected"]
        or auth["discovered_endpoints"]
        or auth["authentication_references"]
    ):
        assessment["confidence"] = "HIGH"
    elif (
        auth["dynamic_indicators"]
        or auth["forms_analyzed"] > 0
        or infrastructure["provider"] != "Not identified"
    ):
        assessment["confidence"] = "MEDIUM"
    else:
        assessment["confidence"] = "LIMITED"

    findings = []
    remediation = []

    if auth["panel_detected"]:
        findings.append(
            "An authentication surface was observed in the analyzed response."
        )
    elif auth["discovered_endpoints"]:
        findings.append(
            "Authentication-related endpoint or client-side references were observed without a native credential form."
        )
    else:
        findings.append(
            "No definitive authentication form or endpoint was observed; authentication absence cannot be concluded from passive analysis."
        )

    if auth["dynamic_indicators"]:
        findings.append(
            f"{len(auth['dynamic_indicators'])} dynamic application indicator(s) were observed; client-rendered authentication surfaces may not be represented in the initial HTML."
        )

    if infrastructure["provider"] != "Not identified":
        findings.append(
            f"{infrastructure['provider']} edge infrastructure was identified from response-level fingerprints."
        )

    if security_headers["missing"]:
        findings.append(
            "One or more commonly evaluated security response headers were not observed; header absence alone does not establish a vulnerability."
        )

    findings.append(
        "No vulnerability was confirmed because this analyzer performs passive surface and response analysis only."
    )

    remediation.append(
        "Review authentication routes and client-side authentication behavior during an authorized active assessment."
    )

    remediation.append(
        "Validate session management, CSRF protections, authentication controls, and authorization behavior during an authorized assessment."
    )

    if security_headers["missing"]:
        remediation.append(
            "Review missing security headers against the application's actual browser security requirements and compensating controls."
        )

    analysis_results["vulnerability_findings"] = findings
    analysis_results["remediation_plan"] = remediation

    analysis_results["evidence"] = []

    evidence_sources = (
        infrastructure["evidence"],
        auth["evidence"],
        analysis_results["waf"]["evidence"]
    )

    for source in evidence_sources:
        for item in source:
            add_unique(
                analysis_results["evidence"],
                item
            )

def render_report_screen():
    local_clear()
    draw_local_box("AUTHENTICATION ENDPOINT ANALYSIS REPORT")

    print(
        f"  Target Endpoint  : {analysis_results['endpoint']}"
    )

    print(
        f"  HTTP Status Code : {analysis_results['status']} │ "
        f"Infrastructure: {analysis_results['infrastructure']['provider']}"
    )

    print(
        f"  Final URL        : {analysis_results['transport']['final_url']}"
    )

    print(
        f"  Response Time    : "
        f"{analysis_results['transport']['response_time_ms']} ms"
    )

    print(
        f"  Redirects        : "
        f"{analysis_results['transport']['redirect_count']}"
    )

    print(
        f"  Content Type     : "
        f"{analysis_results['transport']['content_type']}"
    )

    print(
        f"  Content Length   : "
        f"{analysis_results['transport']['content_length']} bytes"
    )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  AUTHENTICATION SURFACE ANALYSIS")

    auth = analysis_results["authentication"]

    print(
        f"   ├── Authentication Panel : "
        f"{'OBSERVED' if auth['panel_detected'] else 'NOT OBSERVED'}"
    )

    print(
        f"   ├── Password Field       : "
        f"{'DETECTED' if auth['password_field_detected'] else 'NOT DETECTED'}"
    )

    print(
        f"   ├── Username Field       : "
        f"{'DETECTED' if auth['username_field_detected'] else 'NOT DETECTED'}"
    )

    print(
        f"   ├── Email Field          : "
        f"{'DETECTED' if auth['email_field_detected'] else 'NOT DETECTED'}"
    )

    print(
        f"   ├── Forms Analyzed       : "
        f"{auth['forms_analyzed']}"
    )

    print(
        f"   ├── Auth References      : "
        f"{len(auth['authentication_references'])}"
    )

    print(
        f"   ├── Auth Endpoints Found : "
        f"{len(auth['discovered_endpoints'])}"
    )

    print(
        f"   ├── Dynamic Indicators   : "
        f"{len(auth['dynamic_indicators'])}"
    )

    print(
        f"   └── Detection Confidence : "
        f"{auth['confidence']}"
    )

    if auth["discovered_endpoints"]:
        print("       Authentication References:")

        for endpoint in auth["discovered_endpoints"]:
            print(
                f"       └── {endpoint}"
            )

    if auth["dynamic_indicators"]:
        print("       Dynamic Surface Indicators:")

        for indicator in auth["dynamic_indicators"]:
            print(
                f"       └── {indicator}"
            )

    if auth["authentication_forms"]:
        print("       Analyzed Forms:")

        for form in auth["authentication_forms"]:
            print(
                f"       └── Form #{form['index']} │ "
                f"{form['method']} │ "
                f"{form['action']}"
            )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  EDGE INFRASTRUCTURE & WAF OBSERVATIONS")

    infrastructure = analysis_results["infrastructure"]
    waf = analysis_results["waf"]

    print(
        f"   ├── Edge Provider        : "
        f"{infrastructure['provider']}"
    )

    print(
        f"   ├── Infrastructure       : "
        f"{'DETECTED' if infrastructure['provider'] != 'Not identified' else 'NOT IDENTIFIED'}"
    )

    print(
        f"   ├── WAF Enforcement      : "
        f"{'CONFIRMED' if waf['enforcement_confirmed'] else 'NOT CONFIRMED'}"
    )

    print(
        f"   └── Detection Confidence : "
        f"{waf['confidence']}"
    )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  SECURITY HEADER OBSERVATIONS")

    security_headers = analysis_results["security_headers"]

    print(
        f"   ├── Security Headers Present : "
        f"{len(security_headers['present'])}"
    )

    print(
        f"   └── Security Headers Missing : "
        f"{len(security_headers['missing'])}"
    )

    if security_headers["present"]:
        print(
            f"       Present: "
            f"{', '.join(security_headers['present'])}"
        )

    if security_headers["missing"]:
        print(
            f"       Missing: "
            f"{', '.join(security_headers['missing'])}"
        )

    if security_headers["informational"]:
        print("       Additional Observations:")

        for item in security_headers["informational"]:
            print(
                f"       └── {item}"
            )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  TECHNICAL ASSESSMENT & FINDINGS")

    assessment = analysis_results["assessment"]

    print(
        f"   ├── Confirmed Vulnerabilities : "
        f"{assessment['confirmed_findings']}"
    )

    print(
        f"   ├── Observed Findings        : "
        f"{assessment['observed_findings']}"
    )

    print(
        f"   ├── Not Tested               : "
        f"{assessment['not_tested']}"
    )

    print(
        f"   ├── Risk Rating              : "
        f"{assessment['risk_level']}"
    )

    print(
        f"   ├── Assessment Scope         : "
        f"{assessment['scope']}"
    )

    print(
        f"   └── Assessment Confidence    : "
        f"{assessment['confidence']}"
    )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  EVIDENCE SUMMARY")

    evidence = analysis_results["evidence"]

    if evidence:
        for index, item in enumerate(evidence, 1):
            print(
                f"   ├── [{index}] {item}"
            )
    else:
        print(
            "   └── No specific detection evidence collected."
        )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  TECHNICAL FINDINGS")

    for index, finding in enumerate(
        analysis_results["vulnerability_findings"],
        1
    ):
        print(
            f"   ├── [{index}] {finding}"
        )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  REMEDIATION ACTION PLAN")

    for index, recommendation in enumerate(
        analysis_results["remediation_plan"],
        1
    ):
        print(
            f"   ├── [{index}] {recommendation}"
        )

    print(" ────────────────────────────────────────────────────────────────────────")

    back_to_menu_prompt()


def back_to_menu_prompt():
    print("  Select Next Action Plan:")
    print("   1. Return to Main Management Console")
    print("   2. Export Structural Telemetry Matrix to Desktop (.json)")

    sys.stdout.write(
        "\n  Specify Option (1 or 2): "
    )

    sys.stdout.flush()

    try:
        choice = input().strip()
    except (KeyboardInterrupt, EOFError):
        local_clear()
        menu_callback()
        return

    if choice == "2":
        try:
            desktop_path = os.path.join(
                os.path.expanduser("~"),
                "Desktop"
            )

            os.makedirs(
                desktop_path,
                exist_ok=True
            )

            file_name = f"InjecAsst_AuthReport_{int(time.time())}.json"
            full_path = os.path.join(
                desktop_path,
                file_name
            )

            with open(
                full_path,
                "w",
                encoding="utf-8"
            ) as f:
                json.dump(
                    analysis_results,
                    f,
                    ensure_ascii=False,
                    indent=4
                )

            print(
                f"\n\x1b[32m  [SUCCESS] Telemetry payload saved securely to: "
                f"{file_name}\x1b[0m"
            )

        except Exception as error:
            print(
                f"\n\x1b[31m  [ERROR] Export operation failed: "
                f"{str(error)}\x1b[0m"
            )

        print(
            "\n  Press Enter to resume main session loop..."
        )

        try:
            input()
        except (KeyboardInterrupt, EOFError):
            pass

    local_clear()
    menu_callback()


def fail_safe_exit_prompt():
    print(
        "\n  Press Enter to return to main management console..."
    )

    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass

    local_clear()
    menu_callback()


def reset_results():
    analysis_results.clear()

    analysis_results.update({
        "endpoint": "",
        "status": 0,
        "server": "Unknown",
        "transport": {
            "scheme": "Unknown",
            "final_url": "",
            "redirect_count": 0,
            "response_time_ms": 0,
            "content_type": "Unknown",
            "content_length": 0
        },
        "infrastructure": {
            "provider": "Not identified",
            "evidence": [],
            "confidence": "LOW"
        },
        "authentication": {
            "panel_detected": False,
            "password_field_detected": False,
            "username_field_detected": False,
            "email_field_detected": False,
            "forms_analyzed": 0,
            "authentication_forms": [],
            "discovered_endpoints": [],
            "authentication_references": [],
            "dynamic_indicators": [],
            "evidence": [],
            "confidence": "LOW"
        },
        "security_headers": {
            "present": [],
            "missing": [],
            "informational": []
        },
        "waf": {
            "provider": "Unknown",
            "infrastructure_detected": False,
            "enforcement_confirmed": False,
            "evidence": [],
            "confidence": "LOW"
        },
        "assessment": {
            "confirmed_findings": 0,
            "observed_findings": 0,
            "not_tested": 0,
            "risk_level": "UNDETERMINED",
            "scope": "PASSIVE HTTP / HTML / RESOURCE ANALYSIS",
            "confidence": "LIMITED"
        },
        "vulnerability_findings": [],
        "remediation_plan": [],
        "evidence": []
    })


def execute_analysis():
    local_clear()

    draw_local_box(
        "ACTIVE AUDIT - SECURITY RECONNAISSANCE"
    )

    print(
        f"\n  Target Endpoint: {target_url}"
    )

    print(
        "  [*] Initiating HTTP, authentication surface, "
        "resource and security control analysis...\n"
    )

    if not (
        target_url.startswith("http://")
        or target_url.startswith("https://")
    ):
        local_clear()

        draw_local_box(
            "ERROR - VALIDATION FAILURE"
        )

        print(
            "\n  [FATAL] Absolute HTTP or HTTPS URL required."
        )

        fail_safe_exit_prompt()
        return

    analysis_results["endpoint"] = target_url

    try:
        headers = {
            "User-Agent": "InjecAsst-AuthAnalyzer/5.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Connection": "close"
        }

        start_time = time.perf_counter()

        response = requests.get(
            target_url,
            headers=headers,
            timeout=12,
            allow_redirects=True
        )

        elapsed = time.perf_counter() - start_time

        analysis_results["status"] = response.status_code

        analysis_results["server"] = response.headers.get(
            "Server",
            "Unknown Infrastructure"
        )

        analysis_results["transport"]["scheme"] = (
            urlparse(response.url).scheme
        )

        analysis_results["transport"]["final_url"] = response.url

        analysis_results["transport"]["redirect_count"] = len(
            response.history
        )

        analysis_results["transport"]["response_time_ms"] = round(
            elapsed * 1000,
            2
        )

        analysis_results["transport"]["content_type"] = response.headers.get(
            "Content-Type",
            "Unknown"
        )

        analysis_results["transport"]["content_length"] = len(
            response.content
        )

        provider, infrastructure_evidence, infrastructure_confidence = (
            detect_infrastructure(response)
        )

        analysis_results["infrastructure"]["provider"] = provider

        analysis_results["infrastructure"]["evidence"] = (
            infrastructure_evidence
        )

        analysis_results["infrastructure"]["confidence"] = (
            infrastructure_confidence
        )

        parser = SurfaceParser()

        parser.feed(response.text)

        analyze_forms(
            parser,
            response
        )

        discover_authentication_surface(
            parser,
            response
        )

        analyze_security_headers(
            response
        )

        evaluate_waf(
            provider,
            infrastructure_evidence
        )

        build_assessment()

        render_report_screen()

    except requests.exceptions.Timeout:
        print(
            "\n  [FATAL] Request timed out while waiting for target response."
        )

        fail_safe_exit_prompt()

    except requests.exceptions.SSLError as error:
        print(
            f"\n  [FATAL] TLS verification failure: {str(error)}"
        )

        fail_safe_exit_prompt()

    except requests.exceptions.RequestException as error:
        print(
            f"\n  [FATAL] HTTP request failed: {str(error)}"
        )

        fail_safe_exit_prompt()

    except Exception as error:
        print(
            f"\n  [FATAL] Analysis operation aborted: {str(error)}"
        )

        fail_safe_exit_prompt()


def prompt_target():
    global target_url

    local_clear()

    draw_local_box(
        "AUTHENTICATION ENDPOINT ANALYZER - TARGET SPECIFICATION"
    )

    sys.stdout.write(
        "\n  Enter Target Authentication URL: "
    )

    sys.stdout.flush()

    try:
        user_input = input().strip()

    except (KeyboardInterrupt, EOFError):
        local_clear()
        menu_callback()
        return

    if not user_input:
        local_clear()

        draw_local_box(
            "ERROR - VALIDATION FAILURE"
        )

        print(
            "\n  [FATAL] Target URL cannot be empty."
        )

        fail_safe_exit_prompt()
        return

    target_url = user_input

    execute_analysis()


def run_login_analyzer(return_to_menu):
    global menu_callback, target_url

    menu_callback = return_to_menu
    target_url = ""

    reset_results()

    prompt_target()
