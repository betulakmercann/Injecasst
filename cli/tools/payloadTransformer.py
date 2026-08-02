import os
import time
import json
import hashlib
import urllib.parse

import requests
from bs4 import BeautifulSoup


target_url = ""
menu_callback = None

results = {
    "target": "",
    "scan_date": "",
    "baseline": {},
    "parameters": [],
    "tested": [],
    "confirmed_differences": 0,
    "errors": 0,
    "ans_tested": "",
    "ans_found": "",
    "ans_decided": "",
    "ans_todo": ""
}


HEADERS = {
    "User-Agent": "InjecAsst-AuthorizedAssessment/1.0"
}


def reset_results():
    global results

    results = {
        "target": "",
        "scan_date": "",
        "baseline": {},
        "parameters": [],
        "tested": [],
        "confirmed_differences": 0,
        "errors": 0,
        "ans_tested": "",
        "ans_found": "",
        "ans_decided": "",
        "ans_todo": ""
    }


def local_clear():
    os.system("clear")
    print("\x1b[0m", end="")


def draw_local_box(title):
    print(
        "\x1b[38;2;147;51;234m"
        "╔══════════════════════════════════════════════════════════════════════╗"
        "\x1b[0m"
    )

    padding = max(0, 68 - len(title))
    left = padding // 2
    right = padding - left

    print(
        "\x1b[38;2;147;51;234m║\x1b[0m"
        + " " * left
        + f"\x1b[38;2;59;130;246m\x1b[1m{title}\x1b[0m"
        + " " * right
        + "\x1b[38;2;147;51;234m║\x1b[0m"
    )

    print(
        "\x1b[38;2;147;51;234m"
        "╚══════════════════════════════════════════════════════════════════════╝"
        "\x1b[0m"
    )


def normalize_target(value):
    value = value.strip()

    if not value:
        return None

    parsed = urllib.parse.urlparse(value)

    if parsed.scheme not in ("http", "https"):
        return None

    if not parsed.netloc:
        return None

    return value


def response_fingerprint(response):
    body = response.text

    return {
        "status": response.status_code,
        "length": len(body),
        "sha256": hashlib.sha256(
            body.encode("utf-8", errors="ignore")
        ).hexdigest()[:16]
    }


def discover_parameters(url, response):
    found = set()

    parsed = urllib.parse.urlparse(url)

    for key in urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    ):
        found.add(key)

    try:
        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        for form in soup.find_all("form"):

            for element in form.find_all(
                ["input", "textarea", "select"]
            ):
                name = element.get("name")

                if name:
                    found.add(name)

        for link in soup.find_all(
            "a",
            href=True
        ):

            absolute = urllib.parse.urljoin(
                url,
                link["href"]
            )

            parsed_link = urllib.parse.urlparse(
                absolute
            )

            for key in urllib.parse.parse_qs(
                parsed_link.query,
                keep_blank_values=True
            ):
                found.add(key)

    except Exception:
        pass

    return sorted(found)


def build_test_url(url, parameter, value):
    parsed = urllib.parse.urlparse(url)

    query = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    query[parameter] = [value]

    new_query = urllib.parse.urlencode(
        query,
        doseq=True
    )

    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        )
    )


def compare_response(baseline, current):
    differences = []

    if current["status"] != baseline["status"]:
        differences.append("HTTP status")

    if current["length"] != baseline["length"]:
        differences.append("body length")

    if current["sha256"] != baseline["sha256"]:
        differences.append("content fingerprint")

    return differences


def execute_assessment():

    results["target"] = target_url
    results["scan_date"] = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    local_clear()

    draw_local_box(
        "PARAMETER & RESPONSE DIFFERENTIAL ASSESSMENT"
    )

    print(
        f"\n  Target: {target_url}"
    )

    print(
        "  [*] Measuring baseline response..."
    )

    try:

        baseline_response = requests.get(
            target_url,
            headers=HEADERS,
            timeout=8,
            allow_redirects=True
        )

        baseline = response_fingerprint(
            baseline_response
        )

        results["baseline"] = baseline

        print(
            f"  [+] Baseline: "
            f"HTTP {baseline['status']} │ "
            f"{baseline['length']} bytes │ "
            f"{baseline['sha256']}"
        )

        print(
            "\n  [*] Discovering real application parameters..."
        )

        discovered = discover_parameters(
            target_url,
            baseline_response
        )

        results["parameters"] = discovered

        print(
            f"  [+] Parameters discovered: "
            f"{len(discovered)}"
        )

        if not discovered:

            results["ans_tested"] = (
                "LIVE PARAMETER DISCOVERY: "
                "The target was crawled and no query-string "
                "or HTML form parameters were discovered."
            )

            results["ans_found"] = (
                "DISCOVERY RESULTS: "
                "No real input parameter was identified "
                "from the supplied target page."
            )

            results["ans_decided"] = (
                "DETECTION LOGIC: "
                "No parameter was invented or added from a "
                "predefined candidate list."
            )

            results["ans_todo"] = (
                "ACTION REQUIRED: "
                "Expand authorized application mapping or "
                "navigate to pages containing user-controlled inputs."
            )

            render_report()
            return

        print(
            "\n  [*] Testing discovered parameters "
            "with harmless canary values..."
        )

        test_value = "injecasst_canary_7"

        for parameter in discovered:

            test_url = build_test_url(
                target_url,
                parameter,
                test_value
            )

            try:

                response = requests.get(
                    test_url,
                    headers=HEADERS,
                    timeout=8,
                    allow_redirects=True
                )

                current = response_fingerprint(
                    response
                )

                differences = compare_response(
                    baseline,
                    current
                )

                result = {
                    "parameter": parameter,
                    "test_value": test_value,
                    "status": current["status"],
                    "length": current["length"],
                    "fingerprint": current["sha256"],
                    "differences": differences,
                    "test_url": test_url
                }

                results["tested"].append(
                    result
                )

                if differences:
                    results["confirmed_differences"] += 1

            except requests.RequestException as exc:

                results["errors"] += 1

                results["tested"].append({
                    "parameter": parameter,
                    "test_value": test_value,
                    "error": str(exc)
                })

        prepare_report_text()

        render_report()

    except requests.RequestException as exc:

        local_clear()

        draw_local_box(
            "REQUEST ERROR"
        )

        print(
            f"\n  [ERROR] Baseline request failed:"
            f"\n  {exc}"
        )

        fail_safe_exit_prompt()


def prepare_report_text():

    results["ans_tested"] = (
        f"LIVE DIFFERENTIAL ASSESSMENT: "
        f"{len(results['parameters'])} real application "
        f"parameter(s) were discovered and tested using "
        f"a measured HTTP baseline and harmless canary values."
    )

    if results["confirmed_differences"]:

        results["ans_found"] = (
            f"DISCOVERY RESULTS: "
            f"{results['confirmed_differences']} parameter(s) "
            f"produced measurable response differences."
        )

        results["ans_decided"] = (
            "DETECTION LOGIC: "
            "Differences were identified by comparing HTTP "
            "status, response body size and content fingerprint "
            "against the baseline."
        )

        results["ans_todo"] = (
            "ACTION REQUIRED: "
            "Review differing parameters manually in an "
            "authorized environment. A response difference "
            "does not by itself prove SQL injection."
        )

    else:

        results["ans_found"] = (
            "DISCOVERY RESULTS: "
            "No discovered parameter produced a measurable "
            "difference from the baseline."
        )

        results["ans_decided"] = (
            "DETECTION LOGIC: "
            "Test responses matched the measured baseline "
            "across HTTP status, body size and content fingerprint."
        )

        results["ans_todo"] = (
            "ACTION REQUIRED: "
            "No parameter was confirmed by this differential "
            "test. Broader authorized application mapping "
            "may be required."
        )


def render_report():

    local_clear()

    draw_local_box(
        "PARAMETER DISCOVERY & RESPONSE DIFFERENTIAL MATRIX"
    )

    baseline = results["baseline"]

    print(
        f"\n  Target Context : {results['target']}"
    )

    print(
        f"  Execution Date : {results['scan_date']}"
    )

    print(
        f"  Baseline       : "
        f"HTTP {baseline.get('status', '-')}"
        f" │ {baseline.get('length', 0)} bytes"
        f" │ {baseline.get('sha256', '-')}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  DISCOVERED / TESTED PARAMETERS"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  PARAMETER              │ STATUS │ SIZE    │ DIFFERENCE"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    if not results["tested"]:

        print(
            "  [-] No parameters were tested."
        )

    for item in results["tested"]:

        parameter = item["parameter"]

        if "error" in item:

            print(
                f"  {parameter.ljust(22)} │ "
                f"ERROR  │ -       │ request failed"
            )

            continue

        differences = item["differences"]

        if differences:

            diff_text = ", ".join(
                differences
            )

        else:

            diff_text = "baseline matched"

        print(
            f"  {parameter.ljust(22)} │ "
            f"{str(item['status']).ljust(6)} │ "
            f"{str(item['length']).ljust(7)} │ "
            f"{diff_text}"
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
        f"  [+] {results['ans_tested']}"
    )

    print(
        f"  [+] {results['ans_found']}"
    )

    print(
        f"  [+] {results['ans_decided']}"
    )

    print(
        f"  [+] {results['ans_todo']}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────\n"
    )

    back_to_menu_prompt()


def back_to_menu_prompt():

    print(
        "  Select Next Action Plan:"
    )

    print(
        "   1. Return to Main Management Console"
    )

    print(
        "   2. Export Assessment Matrix to Desktop (.json)"
    )

    try:

        choice = input(
            "\n  Specify Option (1 or 2): "
        ).strip()

    except (KeyboardInterrupt, EOFError):

        choice = "1"

    if choice == "2":

        try:

            desktop = os.path.join(
                os.path.expanduser("~"),
                "Desktop"
            )

            os.makedirs(
                desktop,
                exist_ok=True
            )

            filename = (
                f"InjecAsst_ParamAssessment_"
                f"{int(time.time())}.json"
            )

            path = os.path.join(
                desktop,
                filename
            )

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    results,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

            print(
                f"\n  [SUCCESS] Report exported: {filename}"
            )

            input(
                "\n  Press Enter to continue..."
            )

        except Exception as exc:

            print(
                f"\n  [ERROR] Export failed: {exc}"
            )

            input(
                "\n  Press Enter to continue..."
            )

    local_clear()

    menu_callback()


def fail_safe_exit_prompt():

    try:

        input(
            "\n  Press Enter to return to main management console..."
        )

    except (KeyboardInterrupt, EOFError):

        pass

    local_clear()

    menu_callback()


def prompt_target():

    global target_url

    local_clear()

    draw_local_box(
        "SQLi SURFACE ASSESSMENT - TARGET SPECIFICATION"
    )

    print(
        "\n  Enter normal authorized target URL."
    )

    print(
        "  Example: https://example.com"
    )

    print(
        "  The tool will discover available input parameters."
    )

    try:

        user_input = input(
            "\n  Target URL: "
        ).strip()

    except (KeyboardInterrupt, EOFError):

        local_clear()
        menu_callback()
        return

    normalized = normalize_target(
        user_input
    )

    if not normalized:

        local_clear()

        draw_local_box(
            "ERROR - INVALID TARGET"
        )

        print(
            "\n  [FATAL] A valid HTTP/HTTPS target is required."
        )

        fail_safe_exit_prompt()
        return

    target_url = normalized

    execute_assessment()


def run_waf_bypass(return_to_menu):

    global menu_callback
    global target_url

    menu_callback = return_to_menu

    target_url = ""

    reset_results()

    prompt_target()
