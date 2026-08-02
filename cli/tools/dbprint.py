import sys
import os
import time
import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests


fp_results = {
    "endpoint": "",
    "scan_date": "",
    "status": 0,
    "detected_db": "Unknown / Unidentified",
    "confidence": "LOW",
    "tech_stack": "Unidentified Backend",
    "evidence": "No database-specific evidence observed.",
    "assessment": "NOT_IDENTIFIED",
    "stats": {
        "checked_headers": 0,
        "checked_payloads": 0,
        "signatures_matched": 0,
        "parameters_found": 0,
        "request_errors": 0
    },
    "ans_tested": "",
    "ans_found": "",
    "ans_decided": "",
    "ans_todo": ""
}

target_url = ""
menu_callback = None


DB_SIGNATURES = [
    {
        "name": "MySQL / MariaDB",
        "patterns": [
            r"you have an error in your sql syntax",
            r"mysql_fetch_",
            r"mysqli?_",
            r"com\.mysql\.jdbc",
            r"illegal mix of collations",
            r"supplied argument is not a valid mysql",
            r"on duplicate key update"
        ]
    },
    {
        "name": "PostgreSQL",
        "patterns": [
            r"postgresql query failed",
            r"pg_query\(",
            r"pg_exec\(",
            r"pgsql",
            r"invalid input syntax for (?:integer|numeric|uuid)",
            r"postgres.*error"
        ]
    },
    {
        "name": "Microsoft SQL Server",
        "patterns": [
            r"microsoft ole db provider",
            r"sql server.*driver",
            r"sqlserver.*error",
            r"unclosed quotation mark after the character string",
            r"microsoft odbc sql server driver",
            r"conversion failed when converting"
        ]
    },
    {
        "name": "Oracle Database",
        "patterns": [
            r"ora-\d{5}",
            r"oracle error",
            r"oracle.*driver",
            r"quoted string not properly terminated",
            r"sql command not properly ended"
        ]
    },
    {
        "name": "SQLite",
        "patterns": [
            r"sqlite3::",
            r"sqlite_error",
            r"unable to open database file",
            r"sqlite.*syntax error",
            r"near [\"'].*[\"']: syntax error"
        ]
    }
]


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

    title = title[:width]
    padding_total = width - len(title)
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


def reset_results():
    fp_results["endpoint"] = ""
    fp_results["scan_date"] = ""
    fp_results["status"] = 0
    fp_results["detected_db"] = "Unknown / Unidentified"
    fp_results["confidence"] = "LOW"
    fp_results["tech_stack"] = "Unidentified Backend"
    fp_results["evidence"] = "No database-specific evidence observed."
    fp_results["assessment"] = "NOT_IDENTIFIED"

    fp_results["stats"] = {
        "checked_headers": 0,
        "checked_payloads": 0,
        "signatures_matched": 0,
        "parameters_found": 0,
        "request_errors": 0
    }

    fp_results["ans_tested"] = ""
    fp_results["ans_found"] = ""
    fp_results["ans_decided"] = ""
    fp_results["ans_todo"] = ""


def fail_safe_exit_prompt():
    time.sleep(0.02)

    print(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "\n  Press Enter to return to main management console..."
        "\x1b[0m"
    )

    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass

    local_clear()
    menu_callback()


def extract_parameters(url):
    try:
        parsed = urlsplit(url)
        return parse_qsl(parsed.query, keep_blank_values=True)
    except Exception:
        return []


def build_parameter_url(url, parameter_name, new_value):
    parsed = urlsplit(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)

    replaced = False
    rebuilt = []

    for key, value in params:
        if key == parameter_name and not replaced:
            rebuilt.append((key, new_value))
            replaced = True
        else:
            rebuilt.append((key, value))

    new_query = urlencode(rebuilt, doseq=True)

    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        new_query,
        parsed.fragment
    ))


def fingerprint_response(response):
    """
    Search only for explicit DBMS exception signatures.
    This function does NOT infer a DBMS from framework/server headers.
    """

    combined = (
        response.text
        + "\n"
        + "\n".join(
            f"{k}: {v}" for k, v in response.headers.items()
        )
    )

    combined_lower = combined.lower()

    matches = []

    for signature in DB_SIGNATURES:
        for pattern in signature["patterns"]:
            try:
                if re.search(pattern, combined_lower, re.I):
                    matches.append(signature["name"])
                    break
            except re.error:
                continue

    return list(dict.fromkeys(matches))


def identify_technology(response):
    headers = {
        str(k).lower(): str(v).lower()
        for k, v in response.headers.items()
    }

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    via = headers.get("via", "")

    technologies = []

    if "cloudflare" in server or "cloudflare" in via:
        technologies.append("Cloudflare Edge")

    if "nginx" in server:
        technologies.append("Nginx")

    if "apache" in server:
        technologies.append("Apache")

    if "microsoft-iis" in server:
        technologies.append("Microsoft IIS")

    if "php" in powered:
        technologies.append("PHP")

    if "asp.net" in powered:
        technologies.append("ASP.NET")

    if technologies:
        return " / ".join(dict.fromkeys(technologies))

    if server:
        return f"Server: {server}"

    return "Application / Server identity not disclosed"


def render_report_screen():
    local_clear()
    draw_local_box("DBMS INFRASTRUCTURE FINGERPRINTING MATRIX")

    sys.stdout.write("\x1b[0m\x1b[22m\x1b[38;5;16m")

    print(f"  Target Endpoint : {fp_results['endpoint']}")
    print(
        f"  Execution Date  : {fp_results['scan_date']} "
        f"│ HTTP Status: {fp_results['status']}"
    )

    print(" ────────────────────────────────────────────────────────────────────────")

    print("  TELEMETRY RECONNAISSANCE")
    print(
        f"   ├── Headers Evaluated       : "
        f"{fp_results['stats']['checked_headers']}"
    )
    print(
        f"   ├── Active Requests         : "
        f"{fp_results['stats']['checked_payloads']}"
    )
    print(
        f"   ├── Query Parameters        : "
        f"{fp_results['stats']['parameters_found']}"
    )
    print(
        f"   ├── Signature Matches       : "
        f"{fp_results['stats']['signatures_matched']}"
    )
    print(
        f"   └── Request Errors          : "
        f"{fp_results['stats']['request_errors']}"
    )

    print()
    print("  IDENTIFIED DATA ARCHITECTURE METRICS")

    print(
        f"   ├── Target Infrastructure   : "
        f"{fp_results['detected_db']}"
    )

    print(
        f"   ├── Identification Confidence: "
        f"{fp_results['confidence']}"
    )

    print(
        f"   ├── Mapped Stack / Engine   : "
        f"{fp_results['tech_stack']}"
    )

    print(
        f"   ├── Assessment State        : "
        f"{fp_results['assessment']}"
    )

    print(
        f"   └── Evidence                : "
        f"{fp_results['evidence']}"
    )

    print(" ────────────────────────────────────────────────────────────────────────")

    print("  ASSESSMENT & ACTION MATRIX")
    print(" ────────────────────────────────────────────────────────────────────────")

    print(f"  [+] {fp_results['ans_tested']}")
    print(f"  [+] {fp_results['ans_found']}")
    print(f"  [+] {fp_results['ans_decided']}")
    print(f"  [+] {fp_results['ans_todo']}")

    print(" ────────────────────────────────────────────────────────────────────────\n")

    back_to_menu_prompt()


def back_to_menu_prompt():
    time.sleep(0.02)

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

            os.makedirs(desktop_path, exist_ok=True)

            file_name = (
                f"InjecAsst_DbAuditReport_{int(time.time())}.json"
            )

            full_path = os.path.join(desktop_path, file_name)

            with open(full_path, "w", encoding="utf-8") as f:
                json.dump(
                    fp_results,
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

        except Exception as e:
            print(
                f"\n\x1b[31m"
                f"  [ERROR] IO write operation constraint failure: "
                f"{str(e)}"
                f"\x1b[0m"
            )

        time.sleep(0.02)

        print(
            "\x1b[0m\x1b[22m\x1b[38;5;16m"
            "\n  Press Enter to resume main session loop..."
            "\x1b[0m"
        )

        try:
            input()
        except (KeyboardInterrupt, EOFError):
            pass

    local_clear()
    menu_callback()


def execute_fingerprint():
    local_clear()
    draw_local_box("DBMS FINGERPRINT - ACTIVE DIAGNOSTIC ANALYSIS")

    print(
        f"\x1b[0m\x1b[22m\x1b[38;5;16m"
        f"\n  Target URL: {target_url}"
        f"\x1b[0m"
    )

    print(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "  [*] Measuring response metadata and explicit DBMS evidence..."
        "\n\x1b[0m"
    )

    if not target_url.startswith(("http://", "https://")):
        local_clear()
        draw_local_box("ERROR - VALIDATION FAILURE")

        print(
            "\n\x1b[0m\x1b[22m\x1b[31m"
            "  [FATAL] Invalid URI schema. "
            "Absolute HTTP or HTTPS path mandatory."
            "\x1b[0m"
        )

        fail_safe_exit_prompt()
        return

    try:
        session = requests.Session()

        headers = {
            "User-Agent": "InjecAsst-DBPrint/4.0"
        }

        base_res = session.get(
            target_url,
            headers=headers,
            timeout=8,
            allow_redirects=True
        )

        fp_results["endpoint"] = target_url
        fp_results["scan_date"] = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        fp_results["status"] = base_res.status_code
        fp_results["stats"]["checked_headers"] = len(
            base_res.headers
        )

        fp_results["tech_stack"] = identify_technology(
            base_res
        )

        parameters = extract_parameters(target_url)

        fp_results["stats"]["parameters_found"] = len(
            parameters
        )

        fp_results["ans_tested"] = (
            "ANALYSIS SCOPE: Live HTTP response, response headers, "
            "technology fingerprints and explicit database exception "
            "signatures were evaluated. Active diagnostic checks are "
            "performed only when an existing query parameter is present."
        )

        base_matches = fingerprint_response(base_res)

        if base_matches:
            fp_results["detected_db"] = base_matches[0]
            fp_results["confidence"] = "HIGH"
            fp_results["assessment"] = "EXPLICIT_DB_ERROR_OBSERVED"
            fp_results["stats"]["signatures_matched"] = len(
                base_matches
            )
            fp_results["evidence"] = (
                "Explicit database-specific error signature observed "
                f"in baseline response: {', '.join(base_matches)}."
            )

        active_results = []

        if parameters:
            parameter_name = parameters[0][0]

            diagnostic_values = [
                "'",
                "1' AND '1'='2"
            ]

            for diagnostic_value in diagnostic_values:
                try:
                    test_url = build_parameter_url(
                        target_url,
                        parameter_name,
                        diagnostic_value
                    )

                    test_res = session.get(
                        test_url,
                        headers={
                            "User-Agent": "InjecAsst-DBPrint/4.0"
                        },
                        timeout=8,
                        allow_redirects=True
                    )

                    fp_results["stats"]["checked_payloads"] += 1

                    matches = fingerprint_response(
                        test_res
                    )

                    if matches:
                        active_results.extend(matches)

                except requests.RequestException:
                    fp_results["stats"]["request_errors"] += 1

                except Exception:
                    fp_results["stats"]["request_errors"] += 1

        active_results = list(
            dict.fromkeys(active_results)
        )

        if active_results:
            fp_results["detected_db"] = active_results[0]
            fp_results["confidence"] = "HIGH"
            fp_results["assessment"] = (
                "EXPLICIT_DB_ERROR_OBSERVED"
            )

            fp_results["stats"]["signatures_matched"] = len(
                active_results
            )

            fp_results["evidence"] = (
                "A database-specific diagnostic error signature "
                "was observed after testing an existing query "
                f"parameter. Candidate DBMS: "
                f"{', '.join(active_results)}."
            )

            fp_results["ans_found"] = (
                "FINDINGS: Explicit DBMS error signatures were "
                "observed in the live HTTP response path."
            )

            fp_results["ans_decided"] = (
                "DEDUCTION: The DBMS identification is based on "
                "database-specific response signatures rather than "
                "framework or server-header assumptions."
            )

            fp_results["ans_todo"] = (
                "ACTION: Treat the DBMS identification as a strong "
                "fingerprint, not as standalone proof of SQL injection. "
                "Validate the input behavior separately in an authorized lab."
            )

        elif base_matches:
            fp_results["ans_found"] = (
                "FINDINGS: Database-specific error evidence was "
                "present in the baseline response."
            )

            fp_results["ans_decided"] = (
                "DEDUCTION: The database fingerprint is based on "
                "an explicit DBMS exception signature."
            )

            fp_results["ans_todo"] = (
                "ACTION: Review error handling and verify whether "
                "the exposed database error is reproducible and "
                "security-relevant."
            )

        elif not parameters:
            fp_results["confidence"] = "LOW"
            fp_results["assessment"] = (
                "NOT_IDENTIFIED_NO_PARAMETER"
            )

            fp_results["evidence"] = (
                "No explicit DBMS signature observed. "
                "No existing query parameter was available for "
                "active diagnostic comparison."
            )

            fp_results["ans_found"] = (
                "FINDINGS: No database-specific exception signature "
                "was observed in the baseline response."
            )

            fp_results["ans_decided"] = (
                "DEDUCTION: DBMS cannot be reliably identified from "
                "the available passive evidence."
            )

            fp_results["ans_todo"] = (
                "ACTION: Use an authorized parameterized endpoint "
                "if active diagnostic testing is required. "
                "No parameter was invented automatically."
            )

        else:
            fp_results["confidence"] = "LOW"
            fp_results["assessment"] = (
                "NOT_IDENTIFIED"
            )

            fp_results["evidence"] = (
                "No explicit database-specific exception signature "
                "was observed in baseline or diagnostic responses."
            )

            fp_results["ans_found"] = (
                "FINDINGS: No explicit DBMS error signature was "
                "detected during the live response assessment."
            )

            fp_results["ans_decided"] = (
                "DEDUCTION: Server/framework fingerprints alone are "
                "insufficient to identify the underlying database."
            )

            fp_results["ans_todo"] = (
                "ACTION: Keep DBMS classification unidentified unless "
                "additional authorized evidence becomes available."
            )

        render_report_screen()

    except requests.RequestException as err:
        fp_results["assessment"] = "REQUEST_ERROR"
        fp_results["stats"]["request_errors"] += 1

        print(
            f"\n\x1b[31m"
            f"  [ERROR] HTTP request failed: {str(err)}"
            f"\x1b[0m"
        )

        fail_safe_exit_prompt()

    except Exception as err:
        print(
            f"\n\x1b[31m"
            f"  [FATAL] Infrastructure tracking loop aborted: "
            f"{str(err)}"
            f"\x1b[0m"
        )

        fail_safe_exit_prompt()


def prompt_target():
    global target_url

    local_clear()
    draw_local_box(
        "DBMS FINGERPRINT ANALYZER - TARGET SPECIFICATION"
    )

    time.sleep(0.02)

    sys.stdout.write(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "\n  Enter Target URL "
        "(parameterized URL recommended for active diagnostics): "
        "\x1b[0m"
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
        draw_local_box("ERROR - VALIDATION FAILURE")

        print(
            "\n\x1b[0m\x1b[22m\x1b[31m"
            "  [FATAL] Target URL input constraint violation. "
            "Field cannot be empty."
            "\x1b[0m"
        )

        fail_safe_exit_prompt()
        return

    target_url = user_input

    execute_fingerprint()


def run_db_print(return_to_menu):
    global menu_callback, target_url

    menu_callback = return_to_menu
    target_url = ""

    reset_results()

    prompt_target()
