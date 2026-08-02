import sys
import os
import time
import json
import hashlib
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests

param_results = {
    "url": "",
    "scan_date": "",
    "checked_count": 0,
    "discovered_count": 0,
    "confirmed_count": 0,
    "redirect_count": 0,
    "not_found_count": 0,
    "request_errors": 0,
    "found_params": [],
    "risk_level": "UNDETERMINED",
    "ans_tested": "",
    "ans_found": "",
    "ans_decided": "",
    "ans_todo": ""
}

target_url = ""
menu_callback = None

param_wordlist = [
    "id", "page", "cat", "category", "user",
    "file", "action", "search", "query",
    "token", "dir", "item", "product",
    "product_id", "user_id", "sort"
]

REQUEST_TIMEOUT = 6
USER_AGENT = "InjecAsst-ParameterDiscovery/4.0"


def local_clear():
    os.system("clear")
    print("\x1b[0m", end="")


def draw_local_box(title):
    print(
        "\x1b[38;2;147;51;234m"
        "╔══════════════════════════════════════════════════════════════════════╗"
        "\x1b[0m"
    )

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

    print(
        "\x1b[38;2;147;51;234m"
        "╚══════════════════════════════════════════════════════════════════════╝"
        "\x1b[0m"
    )


def reset_mapper_results():
    param_results["url"] = ""
    param_results["scan_date"] = ""
    param_results["checked_count"] = 0
    param_results["discovered_count"] = 0
    param_results["confirmed_count"] = 0
    param_results["redirect_count"] = 0
    param_results["not_found_count"] = 0
    param_results["request_errors"] = 0
    param_results["found_params"] = []
    param_results["risk_level"] = "UNDETERMINED"
    param_results["ans_tested"] = ""
    param_results["ans_found"] = ""
    param_results["ans_decided"] = ""
    param_results["ans_todo"] = ""


def response_fingerprint(response):
    body = response.text or ""
    normalized = body[:200000]

    return hashlib.sha256(
        normalized.encode("utf-8", errors="ignore")
    ).hexdigest()[:16]


def response_signature(response):
    return {
        "status": response.status_code,
        "length": len(response.content),
        "fingerprint": response_fingerprint(response)
    }


def build_parameter_url(url, parameter, value="1"):
    parts = urlsplit(url)

    existing = parse_qsl(
        parts.query,
        keep_blank_values=True
    )

    existing.append((parameter, value))

    query = urlencode(existing, doseq=True)

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        query,
        parts.fragment
    ))


def classify_response(baseline, candidate):
    status = candidate.get("status_code", 0)

    if status in {301, 302, 303, 307, 308}:
        return "REDIRECT"

    if status == 404:
        return "NOT FOUND"

    if status in {401, 403}:
        return "RESTRICTED"

    if status < 200 or status >= 500:
        return "OTHER"

    length_delta = abs(
        candidate["length"] - baseline["length"]
    )

    fingerprint_changed = (
        candidate["fingerprint"] != baseline["fingerprint"]
    )

    status_changed = (
        candidate["status"] != baseline["status"]
    )

    if status_changed or fingerprint_changed or length_delta > 32:
        return "RESPONSE DEVIATION"

    return "BASELINE MATCH"


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
                f"InjecAsst_ParamAuditReport_"
                f"{int(time.time())}.json"
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
                    param_results,
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
                f"  [ERROR] IO write operation failure: {str(e)}"
                f"\x1b[0m"
            )

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


def render_report_screen():
    local_clear()
    draw_local_box("INPUT VECTOR ENUMERATION MATRIX")

    sys.stdout.write(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
    )

    print(f"  Target Context  : {param_results['url']}")
    print(
        f"  Execution Date  : {param_results['scan_date']} "
        f"│ Target Vectors: {param_results['checked_count']}"
    )

    print(" ────────────────────────────────────────────────────────────────────────")

    print("  ENUMERATION SUMMARY")
    print(
        f"   ├── Confirmed Response Deviations : "
        f"{param_results['confirmed_count']}"
    )
    print(
        f"   ├── Restricted Responses          : "
        f"{param_results['discovered_count'] - param_results['confirmed_count']}"
    )
    print(
        f"   ├── Redirect Responses             : "
        f"{param_results['redirect_count']}"
    )
    print(
        f"   ├── Baseline-Matched / Not Found   : "
        f"{param_results['not_found_count']}"
    )
    print(
        f"   └── Request Errors                 : "
        f"{param_results['request_errors']}"
    )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  IDENTIFIED SYSTEM INPUT VECTOR ARRAYS")
    print(" ────────────────────────────────────────────────────────────────────────")
    print(
        "  INPUT FIELD           │ CLASSIFICATION        │ STATUS │ SIZE DELTA"
    )
    print(" ────────────────────────────────────────────────────────────────────────")

    if param_results["found_params"]:
        for item in param_results["found_params"]:
            parameter = item["parameter"].ljust(21)
            classification = item["classification"].ljust(21)
            status = str(item["status"]).ljust(6)
            delta = f"{item['length_delta']} B"

            print(
                f"  {parameter} │ "
                f"{classification} │ "
                f"{status} │ "
                f"{delta}"
            )
    else:
        print(
            "  [-] No parameter response deviations were confirmed "
            "against the measured baseline."
        )

    print(" ────────────────────────────────────────────────────────────────────────")
    print("  ASSESSMENT & ACTION MATRIX")
    print(" ────────────────────────────────────────────────────────────────────────")

    print(f"  [+] {param_results['ans_tested']}")
    print(f"  [+] {param_results['ans_found']}")
    print(f"  [+] {param_results['ans_decided']}")
    print(f"  [+] {param_results['ans_todo']}")

    print(" ────────────────────────────────────────────────────────────────────────\n")

    back_to_menu_prompt()


def execute_param_mapping():
    local_clear()

    draw_local_box(
        "ACTIVE INTERACTION - PARAMETER ASSESSMENT"
    )

    print(
        f"\x1b[0m\x1b[22m\x1b[38;5;16m"
        f"\n  Target URL: {target_url}"
        f"\x1b[0m"
    )

    print(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "  [*] Measuring baseline and testing candidate query parameters...\n"
        "\x1b[0m"
    )

    if not (
        target_url.startswith("http://")
        or target_url.startswith("https://")
    ):
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

    param_results["url"] = target_url
    param_results["scan_date"] = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    param_results["checked_count"] = len(param_wordlist)

    session = requests.Session()

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml"
    }

    param_results["ans_tested"] = (
        f"LIVE HTTP ENUMERATION: "
        f"{len(param_wordlist)} candidate query parameters were tested "
        f"against a measured target response baseline. "
        f"HTTP status, body size and content fingerprint were compared."
    )

    try:
        baseline_res = session.get(
            target_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        baseline = response_signature(baseline_res)

        print(
            f"  [*] Baseline: "
            f"HTTP {baseline['status']} │ "
            f"{baseline['length']} bytes │ "
            f"{baseline['fingerprint']}..."
        )

        seen = set()

        for parameter in param_wordlist:
            if parameter in seen:
                continue

            seen.add(parameter)

            candidate_url = build_parameter_url(
                target_url,
                parameter,
                "1"
            )

            try:
                response = session.get(
                    candidate_url,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False
                )

                signature = response_signature(response)

                classification = classify_response(
                    baseline,
                    signature
                )

                if classification == "RESPONSE DEVIATION":
                    param_results["confirmed_count"] += 1

                    param_results["found_params"].append({
                        "parameter": parameter,
                        "classification": "RESPONSE DEVIATION",
                        "status": response.status_code,
                        "length": signature["length"],
                        "length_delta": abs(
                            signature["length"]
                            - baseline["length"]
                        ),
                        "baseline_fingerprint": baseline["fingerprint"],
                        "response_fingerprint": signature["fingerprint"]
                    })

                elif classification == "RESTRICTED":
                    param_results["discovered_count"] += 1

                    param_results["found_params"].append({
                        "parameter": parameter,
                        "classification": "RESTRICTED",
                        "status": response.status_code,
                        "length": signature["length"],
                        "length_delta": abs(
                            signature["length"]
                            - baseline["length"]
                        ),
                        "baseline_fingerprint": baseline["fingerprint"],
                        "response_fingerprint": signature["fingerprint"]
                    })

                elif classification == "REDIRECT":
                    param_results["redirect_count"] += 1

                elif classification in {
                    "NOT FOUND",
                    "BASELINE MATCH"
                }:
                    param_results["not_found_count"] += 1

                else:
                    param_results["not_found_count"] += 1

            except requests.RequestException:
                param_results["request_errors"] += 1

        param_results["discovered_count"] = (
            len(param_results["found_params"])
        )

        confirmed = param_results["confirmed_count"]

        restricted = sum(
            1
            for item in param_results["found_params"]
            if item["classification"] == "RESTRICTED"
        )

        if confirmed > 0:
            param_results["risk_level"] = "OBSERVED DEVIATION"

            param_results["ans_found"] = (
                f"DISCOVERY RESULTS: "
                f"{confirmed} candidate parameter(s) produced "
                f"a response deviation from the measured baseline."
            )

            param_results["ans_decided"] = (
                "DETECTION LOGIC: "
                "HTTP status alone was not treated as parameter proof. "
                "Candidate responses were compared using status, "
                "body length and content fingerprint."
            )

            param_results["ans_todo"] = (
                "ACTION REQUIRED: "
                "Review the identified parameters during an authorized "
                "assessment. A response deviation alone does not establish "
                "SQL injection or another vulnerability."
            )

        elif restricted > 0:
            param_results["risk_level"] = "RESTRICTED SURFACE"

            param_results["ans_found"] = (
                f"DISCOVERY RESULTS: "
                f"{restricted} candidate parameter(s) returned "
                "access-control responses."
            )

            param_results["ans_decided"] = (
                "DETECTION LOGIC: "
                "Restricted responses were separated from confirmed "
                "application response deviations."
            )

            param_results["ans_todo"] = (
                "ACTION REQUIRED: "
                "Review restricted routes only within an authorized "
                "assessment context."
            )

        else:
            param_results["risk_level"] = "NO DEVIATION OBSERVED"

            param_results["ans_found"] = (
                "DISCOVERY RESULTS: "
                "No candidate parameter produced a confirmed response "
                "deviation against the measured baseline."
            )

            param_results["ans_decided"] = (
                "DETECTION LOGIC: "
                "Candidate query parameters were evaluated against "
                "baseline status, response size and content fingerprint."
            )

            param_results["ans_todo"] = (
                "ACTION REQUIRED: "
                "No parameter was confirmed by this passive differential "
                "logic. Use broader authorized application mapping if needed."
            )

        render_report_screen()

    except requests.RequestException as err:
        print(
            f"\n\x1b[31m"
            f"  [ERROR] HTTP request failed: {str(err)}"
            f"\x1b[0m"
        )

        fail_safe_exit_prompt()

    except Exception as err:
        print(
            f"\n\x1b[31m"
            f"  [FATAL] Parameter assessment aborted: {str(err)}"
            f"\x1b[0m"
        )

        fail_safe_exit_prompt()


def prompt_target():
    global target_url

    local_clear()

    draw_local_box(
        "INPUT VECTOR ENUMERATOR - TARGET SPECIFICATION"
    )

    time.sleep(0.02)

    sys.stdout.write(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "\n  Enter Target Infrastructure URL to Map: "
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

        draw_local_box(
            "ERROR - VALIDATION FAILURE"
        )

        print(
            "\n\x1b[0m\x1b[22m\x1b[31m"
            "  [FATAL] Target URL input constraint violation. "
            "Field cannot be empty."
            "\x1b[0m"
        )

        fail_safe_exit_prompt()
        return

    target_url = user_input

    execute_param_mapping()


def run_parameter_mapper(return_to_menu):
    global menu_callback, target_url

    menu_callback = return_to_menu
    target_url = ""

    reset_mapper_results()

    prompt_target()
