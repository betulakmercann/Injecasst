import sys
import os
import time
import json
import hashlib
from urllib.parse import urlparse, urljoin

import requests


mapper_results = {
    "url": "",
    "scan_date": "",
    "checked_count": 0,
    "discovered_count": 0,
    "confirmed_count": 0,
    "restricted_count": 0,
    "redirect_count": 0,
    "not_found_count": 0,
    "error_count": 0,
    "baseline": {},
    "found_endpoints": [],
    "risk_level": "INFORMATIONAL",
    "ans_tested": "",
    "ans_found": "",
    "ans_decided": "",
    "ans_todo": ""
}

target_url = ""
menu_callback = None


# ---------------------------------------------------------------------------
# Endpoint candidates
# ---------------------------------------------------------------------------

wordlist = [
    "admin",
    "administrator",
    "api",
    "api/v1",
    "api/v2",
    "v1",
    "v2",
    "login",
    "signin",
    "sign-in",
    "auth",
    "account",
    "dashboard",
    "panel",
    "manage",
    "management",
    "console",
    "user",
    "users",
    "profile",
    "config",
    "configs",
    "configuration",
    "backup",
    "backups",
    "db",
    "database",
    "debug",
    "dev",
    "development",
    "test",
    "staging",
    "internal",
    "private",
    "status",
    "health",
    "healthcheck",
    "metrics",
    "monitor",
    "server-status",
    "robots.txt",
    "sitemap.xml",
    ".well-known",
    ".well-known/security.txt",
    "wp-admin",
    "wp-login.php",
    "graphql",
    "swagger",
    "swagger-ui",
    "swagger.json",
    "openapi.json"
]


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def local_clear():
    os.system("clear")
    print("\x1b[0m", end="")


def draw_local_box(title):
    width = 68

    print(
        "\x1b[38;2;147;51;234m"
        "╔══════════════════════════════════════════════════════════════════════╗"
        "\x1b[0m"
    )

    padding_total = max(0, width - len(title))
    pad_left = padding_total // 2
    pad_right = padding_total - pad_left

    print(
        "\x1b[38;2;147;51;234m║\x1b[0m"
        + " " * pad_left
        + f"\x1b[38;2;59;130;246m\x1b[1m{title}\x1b[0m"
        + " " * pad_right
        + "\x1b[38;2;147;51;234m║\x1b[0m"
    )

    print(
        "\x1b[38;2;147;51;234m"
        "╚══════════════════════════════════════════════════════════════════════╝"
        "\x1b[0m"
    )


def back_to_menu_prompt():
    print("  Select Next Action Plan:")
    print("   1. Return to Main Management Console")
    print("   2. Export Structural Telemetry Matrix to Desktop (.json)")

    sys.stdout.write(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "\n  Specify Option (1 or 2): "
        "\x1b[0m"
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

            file_name = (
                f"InjecAsst_PathAuditReport_{int(time.time())}.json"
            )

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
                    mapper_results,
                    f,
                    ensure_ascii=False,
                    indent=4
                )

            print(
                f"\n\x1b[32m"
                f"  [SUCCESS] Telemetry payload saved securely to: "
                f"{file_name}"
                f"\x1b[0m"
            )

        except Exception as error:
            print(
                f"\n\x1b[31m"
                f"  [ERROR] IO write operation failed: {str(error)}"
                f"\x1b[0m"
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


# ---------------------------------------------------------------------------
# URL / response helpers
# ---------------------------------------------------------------------------

def normalize_base_url(value):
    value = value.strip()

    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        return ""

    if not parsed.netloc:
        return ""

    return value.rstrip("/")


def build_endpoint(base_url, path):
    return urljoin(
        base_url.rstrip("/") + "/",
        path.lstrip("/")
    )


def response_fingerprint(response):
    body = response.content or b""

    sample = body[:4096]

    return {
        "status": response.status_code,
        "length": len(body),
        "sha256_sample": hashlib.sha256(sample).hexdigest(),
        "content_type": response.headers.get(
            "Content-Type",
            ""
        ).split(";")[0].strip().lower(),
        "location": response.headers.get(
            "Location",
            ""
        )
    }


def is_html_response(response):
    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
    )


def response_similarity(response, baseline):
    if not baseline:
        return 0.0

    body = response.content or b""

    current_length = len(body)
    baseline_length = baseline.get("length", 0)

    if baseline_length == 0 and current_length == 0:
        return 1.0

    if baseline_length == 0 or current_length == 0:
        return 0.0

    length_similarity = (
        min(current_length, baseline_length)
        / max(current_length, baseline_length)
    )

    current_hash = hashlib.sha256(
        body[:4096]
    ).hexdigest()

    if current_hash == baseline.get("sha256_sample"):
        return 1.0

    return round(length_similarity, 4)


# ---------------------------------------------------------------------------
# Baseline analysis
# ---------------------------------------------------------------------------

def create_not_found_baseline(session, base_url, headers):
    random_path = (
        "__injecasst_nonexistent_"
        f"{int(time.time() * 1000000)}"
    )

    url = build_endpoint(
        base_url,
        random_path
    )

    try:
        response = session.get(
            url,
            headers=headers,
            timeout=8,
            allow_redirects=False
        )

        fingerprint = response_fingerprint(response)

        mapper_results["baseline"] = {
            "url": url,
            "status": response.status_code,
            "length": fingerprint["length"],
            "sha256_sample": fingerprint["sha256_sample"],
            "content_type": fingerprint["content_type"],
            "location": fingerprint["location"]
        }

        return response

    except requests.RequestException:
        mapper_results["baseline"] = {
            "url": url,
            "status": None,
            "length": 0,
            "sha256_sample": "",
            "content_type": "",
            "location": ""
        }

        return None


def create_root_baseline(session, base_url, headers):
    try:
        response = session.get(
            base_url,
            headers=headers,
            timeout=8,
            allow_redirects=True
        )

        return response

    except requests.RequestException:
        return None


def looks_like_custom_not_found(response, baseline):
    if not baseline:
        return False

    baseline_status = baseline.get("status")

    if baseline_status is None:
        return False

    if response.status_code != baseline_status:
        return False

    similarity = response_similarity(
        response,
        baseline
    )

    return similarity >= 0.92


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

def classify_response(
    response,
    baseline,
    root_response
):
    status = response.status_code

    if status in {401, 403}:
        return "RESTRICTED"

    if status in {301, 302, 303, 307, 308}:
        location = response.headers.get(
            "Location",
            ""
        )

        if location:
            return "REDIRECT"

        return "OBSERVED"

    if status in {404, 410}:
        return "NOT_FOUND"

    if looks_like_custom_not_found(
        response,
        baseline
    ):
        return "NOT_FOUND"

    if 200 <= status < 300:
        return "CONFIRMED"

    if status in {405, 406, 429}:
        return "OBSERVED"

    if 500 <= status <= 599:
        return "SERVER_ERROR"

    return "OBSERVED"


def endpoint_record(
    path,
    response,
    classification,
    elapsed_ms
):
    body = response.content or b""

    return {
        "path": "/" + path.lstrip("/"),
        "url": response.url,
        "status": response.status_code,
        "classification": classification,
        "length": len(body),
        "content_type": response.headers.get(
            "Content-Type",
            ""
        ),
        "response_time_ms": round(
            elapsed_ms,
            2
        ),
        "location": response.headers.get(
            "Location",
            ""
        ),
        "server": response.headers.get(
            "Server",
            ""
        ),
        "sha256_sample": hashlib.sha256(
            body[:4096]
        ).hexdigest()
    }


def add_endpoint(record):
    existing = {
        item["url"]
        for item in mapper_results["found_endpoints"]
    }

    if record["url"] not in existing:
        mapper_results["found_endpoints"].append(
            record
        )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def render_report_screen():
    local_clear()

    draw_local_box(
        "ENDPOINT DIRECTORY MAPPER RESULTS"
    )

    print(
        f"  Target Context  : "
        f"{mapper_results['url']}"
    )

    print(
        f"  Execution Date  : "
        f"{mapper_results['scan_date']}"
    )

    print(
        f"  Target Vectors  : "
        f"{mapper_results['checked_count']}"
    )

    print(
        f"  Confirmed       : "
        f"{mapper_results['confirmed_count']}"
    )

    print(
        f"  Restricted      : "
        f"{mapper_results['restricted_count']}"
    )

    print(
        f"  Redirects       : "
        f"{mapper_results['redirect_count']}"
    )

    print(
        f"  Not Found       : "
        f"{mapper_results['not_found_count']}"
    )

    print(
        f"  Request Errors  : "
        f"{mapper_results['error_count']}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  RESPONSE BASELINE"
    )

    baseline = mapper_results["baseline"]

    if baseline:
        print(
            f"   ├── Baseline Status       : "
            f"{baseline.get('status')}"
        )

        print(
            f"   ├── Baseline Length       : "
            f"{baseline.get('length')} Bytes"
        )

        print(
            f"   └── Baseline Fingerprint : "
            f"{baseline.get('sha256_sample', '')[:16]}..."
        )
    else:
        print(
            "   └── Baseline could not be established."
        )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  MAPPED STRUCTURAL INFRASTRUCTURE ELEMENTS"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  ROUTE                  │ STATUS │ CLASSIFICATION │ SIZE"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    if mapper_results["found_endpoints"]:

        for ep in mapper_results["found_endpoints"]:

            path_str = ep["path"][:22].ljust(22)
            status_str = str(
                ep["status"]
            ).ljust(6)

            classification = ep[
                "classification"
            ][:14].ljust(14)

            size_str = (
                f"{ep['length']} B"
            )

            print(
                f"  {path_str} │ "
                f"{status_str} │ "
                f"{classification} │ "
                f"{size_str}"
            )

    else:
        print(
            "  [-] No distinct endpoint responses identified."
        )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  ASSESSMENT & ACTION MATRIX"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        f"  [+] {mapper_results['ans_tested']}"
    )

    print(
        f"  [+] {mapper_results['ans_found']}"
    )

    print(
        f"  [+] {mapper_results['ans_decided']}"
    )

    print(
        f"  [+] {mapper_results['ans_todo']}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────\n"
    )

    back_to_menu_prompt()


# ---------------------------------------------------------------------------
# Main mapping engine
# ---------------------------------------------------------------------------

def execute_mapping():
    local_clear()

    draw_local_box(
        "ACTIVE ENUMERATION - PATH FUZZING"
    )

    print(
        f"\n  Target Base URL: {target_url}"
    )

    print(
        "  [*] Establishing response baseline..."
    )

    print(
        "  [*] Testing candidate routes against live HTTP responses..."
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

    base_url = normalize_base_url(
        target_url
    )

    if not base_url:
        local_clear()

        draw_local_box(
            "ERROR - VALIDATION FAILURE"
        )

        print(
            "\n  [FATAL] Invalid target URL."
        )

        fail_safe_exit_prompt()
        return

    mapper_results["url"] = base_url

    mapper_results["scan_date"] = (
        time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    mapper_results["checked_count"] = len(
        wordlist
    )

    mapper_results["ans_tested"] = (
        f"LIVE HTTP ENUMERATION: "
        f"{len(wordlist)} candidate routes tested "
        f"against the target using response-status, "
        f"body-length and content fingerprint comparison."
    )

    session = requests.Session()

    headers = {
        "User-Agent": (
            "InjecAsst-EndpointMapper/5.0"
        ),
        "Accept": (
            "text/html,"
            "application/xhtml+xml,"
            "application/json,"
            "text/plain,"
            "*/*"
        ),
        "Accept-Language": (
            "en-US,en;q=0.8"
        ),
        "Connection": "close"
    }

    try:
        root_response = create_root_baseline(
            session,
            base_url,
            headers
        )

        baseline_response = create_not_found_baseline(
            session,
            base_url,
            headers
        )

        baseline = mapper_results[
            "baseline"
        ]

        for index, path in enumerate(
            wordlist,
            1
        ):
            full_url = build_endpoint(
                base_url,
                path
            )

            try:
                start = time.perf_counter()

                response = session.get(
                    full_url,
                    headers=headers,
                    timeout=8,
                    allow_redirects=False
                )

                elapsed_ms = (
                    time.perf_counter()
                    - start
                ) * 1000

                classification = classify_response(
                    response,
                    baseline,
                    root_response
                )

                if classification == "NOT_FOUND":
                    mapper_results[
                        "not_found_count"
                    ] += 1

                    continue

                record = endpoint_record(
                    path,
                    response,
                    classification,
                    elapsed_ms
                )

                if classification == "CONFIRMED":
                    mapper_results[
                        "confirmed_count"
                    ] += 1

                    add_endpoint(record)

                elif classification == "RESTRICTED":
                    mapper_results[
                        "restricted_count"
                    ] += 1

                    add_endpoint(record)

                elif classification == "REDIRECT":
                    mapper_results[
                        "redirect_count"
                    ] += 1

                    add_endpoint(record)

                elif classification in {
                    "OBSERVED",
                    "SERVER_ERROR"
                }:
                    add_endpoint(record)

            except requests.exceptions.Timeout:
                mapper_results[
                    "error_count"
                ] += 1

            except requests.exceptions.RequestException:
                mapper_results[
                    "error_count"
                ] += 1

        mapper_results[
            "discovered_count"
        ] = len(
            mapper_results[
                "found_endpoints"
            ]
        )

        confirmed = mapper_results[
            "confirmed_count"
        ]

        restricted = mapper_results[
            "restricted_count"
        ]

        redirects = mapper_results[
            "redirect_count"
        ]

        observed = mapper_results[
            "discovered_count"
        ]

        if confirmed > 0:
            mapper_results[
                "risk_level"
            ] = "INFORMATIONAL"

            mapper_results[
                "ans_found"
            ] = (
                f"DISCOVERY RESULTS: "
                f"{confirmed} route(s) returned "
                f"responses distinct from the measured "
                f"not-found baseline and were classified "
                f"as reachable."
            )

        elif restricted > 0:
            mapper_results[
                "risk_level"
            ] = "INFORMATIONAL"

            mapper_results[
                "ans_found"
            ] = (
                f"DISCOVERY RESULTS: "
                f"{restricted} route(s) returned "
                f"authentication or access-control "
                f"responses and were classified as "
                f"restricted rather than confirmed accessible."
            )

        elif redirects > 0:
            mapper_results[
                "risk_level"
            ] = "INFORMATIONAL"

            mapper_results[
                "ans_found"
            ] = (
                f"DISCOVERY RESULTS: "
                f"{redirects} route(s) produced explicit "
                f"redirect responses."
            )

        elif observed > 0:
            mapper_results[
                "risk_level"
            ] = "INFORMATIONAL"

            mapper_results[
                "ans_found"
            ] = (
                f"DISCOVERY RESULTS: "
                f"{observed} distinct route response(s) "
                f"were observed and retained for review."
            )

        else:
            mapper_results[
                "risk_level"
            ] = "INFORMATIONAL"

            mapper_results[
                "ans_found"
            ] = (
                "DISCOVERY RESULTS: "
                "No route produced a response sufficiently "
                "distinct from the measured not-found "
                "baseline to be classified as discovered."
            )

        mapper_results[
            "ans_decided"
        ] = (
            "DETECTION LOGIC: HTTP status alone was not "
            "treated as endpoint proof. Candidate routes "
            "were compared against a live randomized "
            "not-found baseline using status, body length "
            "and content fingerprint characteristics."
        )

        mapper_results[
            "ans_todo"
        ] = (
            "ACTION REQUIRED: Review confirmed and "
            "restricted routes during an authorized "
            "assessment. Endpoint discovery alone does "
            "not establish a security vulnerability."
        )

        render_report_screen()

    except requests.exceptions.Timeout:
        print(
            "\n  [FATAL] Target baseline request timed out."
        )

        fail_safe_exit_prompt()

    except requests.exceptions.RequestException as error:
        print(
            f"\n  [FATAL] HTTP discovery operation failed: "
            f"{str(error)}"
        )

        fail_safe_exit_prompt()

    except Exception as error:
        print(
            f"\n  [FATAL] Endpoint mapping operation aborted: "
            f"{str(error)}"
        )

        fail_safe_exit_prompt()

    finally:
        try:
            session.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

def prompt_target():
    global target_url

    local_clear()

    draw_local_box(
        "ENDPOINT DIRECTORY ENUMERATOR - TARGET SPECIFICATION"
    )

    sys.stdout.write(
        "\n  Enter Target Infrastructure Base URL: "
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

    execute_mapping()


def reset_mapper_results():
    mapper_results.clear()

    mapper_results.update({
        "url": "",
        "scan_date": "",
        "checked_count": 0,
        "discovered_count": 0,
        "confirmed_count": 0,
        "restricted_count": 0,
        "redirect_count": 0,
        "not_found_count": 0,
        "error_count": 0,
        "baseline": {},
        "found_endpoints": [],
        "risk_level": "INFORMATIONAL",
        "ans_tested": "",
        "ans_found": "",
        "ans_decided": "",
        "ans_todo": ""
    })


def run_endpoint_mapper(return_to_menu):
    global menu_callback, target_url

    menu_callback = return_to_menu
    target_url = ""

    reset_mapper_results()

    prompt_target()
