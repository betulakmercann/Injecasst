import sys
import os
import time
import json
import hashlib
import urllib.parse
import requests
from bs4 import BeautifulSoup


target_url = ""
menu_callback = None

extractor_results = {
    "url": "",
    "method_used": "Baseline / Parameter Validation",
    "status_text": "Awaiting authorized assessment.",
    "baseline": {},
    "parameters": [],
    "tested": [],
    "differences": 0,
    "errors": 0,
    "ans_tested": "",
    "ans_found": "",
    "ans_decided": "",
    "ans_todo": ""
}

HEADERS = {
    "User-Agent": "InjecAsst-AuthorizedValidation/1.0"
}


def reset_results():
    global extractor_results

    extractor_results = {
        "url": "",
        "method_used": "Baseline / Parameter Validation",
        "status_text": "Awaiting authorized assessment.",
        "baseline": {},
        "parameters": [],
        "tested": [],
        "differences": 0,
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


def response_fingerprint(response):
    body = response.text

    return {
        "status": response.status_code,
        "length": len(body),
        "sha256": hashlib.sha256(
            body.encode("utf-8", errors="ignore")
        ).hexdigest()[:16]
    }


def compare_response(baseline, current):
    differences = []

    if current["status"] != baseline["status"]:
        differences.append("HTTP status")

    if current["length"] != baseline["length"]:
        differences.append("body length")

    if current["sha256"] != baseline["sha256"]:
        differences.append("content fingerprint")

    return differences


def discover_parameters(url, response):
    discovered = {}

    parsed = urllib.parse.urlparse(response.url)

    for name, value in urllib.parse.parse_qsl(
        parsed.query,
        keep_blank_values=True
    ):
        discovered.setdefault(
            name,
            {
                "name": name,
                "value": value,
                "source": "query",
                "method": "GET",
                "url": response.url
            }
        )

    try:
        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        for form_index, form in enumerate(
            soup.find_all("form"),
            start=1
        ):
            method = (
                form.get("method", "GET")
                .strip()
                .upper()
            )

            if method not in ("GET", "POST"):
                method = "GET"

            action = form.get("action", "")

            form_url = urllib.parse.urljoin(
                response.url,
                action
            )

            for element in form.find_all(
                ["input", "textarea", "select"]
            ):
                name = element.get("name")

                if not name:
                    continue

                key = f"form:{method}:{form_index}:{name}"

                value = element.get("value", "")

                if element.name == "textarea":
                    value = element.text or value

                discovered.setdefault(
                    key,
                    {
                        "name": name,
                        "value": value,
                        "source": "form",
                        "method": method,
                        "url": form_url,
                        "form_index": form_index
                    }
                )

        for link in soup.find_all(
            "a",
            href=True
        ):
            link_url = urllib.parse.urljoin(
                response.url,
                link["href"]
            )

            parsed_link = urllib.parse.urlparse(
                link_url
            )

            for name, value in urllib.parse.parse_qsl(
                parsed_link.query,
                keep_blank_values=True
            ):
                key = f"link:{name}"

                discovered.setdefault(
                    key,
                    {
                        "name": name,
                        "value": value,
                        "source": "link",
                        "method": "GET",
                        "url": link_url
                    }
                )

    except Exception:
        pass

    return list(discovered.values())


def build_query_test_url(url, parameter, value):
    parsed = urllib.parse.urlparse(url)

    query = urllib.parse.parse_qsl(
        parsed.query,
        keep_blank_values=True
    )

    replaced = False
    new_query = []

    for name, old_value in query:
        if name == parameter:
            new_query.append(
                (name, value)
            )
            replaced = True
        else:
            new_query.append(
                (name, old_value)
            )

    if not replaced:
        new_query.append(
            (parameter, value)
        )

    encoded = urllib.parse.urlencode(
        new_query
    )

    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            encoded,
            parsed.fragment
        )
    )


def prepare_report_text():
    tested = len(extractor_results["tested"])
    differences = extractor_results["differences"]

    extractor_results["status_text"] = (
        "Assessment completed."
    )

    extractor_results["ans_tested"] = (
        f"LIVE VALIDATION: {tested} discovered input surface(s) "
        f"were evaluated using a measured HTTP baseline and "
        f"harmless canary values."
    )

    if tested == 0:
        extractor_results["ans_found"] = (
            "FINDINGS: No testable query or HTML form parameters "
            "were discovered."
        )

        extractor_results["ans_decided"] = (
            "DECISION: SQL injection cannot be assessed from "
            "the discovered input surface."
        )

        extractor_results["ans_todo"] = (
            "ACTION REQUIRED: Provide an authorized parameterized "
            "URL or expand application surface mapping."
        )

        return

    if differences:
        extractor_results["ans_found"] = (
            f"FINDINGS: {differences} input surface(s) produced "
            f"measurable response differences."
        )

        extractor_results["ans_decided"] = (
            "DECISION: A response difference is an observation, "
            "not proof of SQL injection. Additional controlled "
            "validation is required."
        )

        extractor_results["ans_todo"] = (
            "ACTION REQUIRED: Review differing inputs manually "
            "within the authorized assessment scope."
        )

    else:
        extractor_results["ans_found"] = (
            "FINDINGS: No measurable response differences were "
            "observed against the baseline."
        )

        extractor_results["ans_decided"] = (
            "DECISION: No SQL injection condition was confirmed "
            "by this differential validation."
        )

        extractor_results["ans_todo"] = (
            "ACTION REQUIRED: No confirmed finding from the "
            "current validation surface."
        )


def execute_extraction():
    extractor_results["url"] = target_url

    local_clear()

    draw_local_box(
        "SQLi VALIDATION & EVIDENCE ANALYZER"
    )

    extractor_results["url"] = target_url

    print(
        f"\n  Target Context : {target_url}"
    )

    print(
        f"  Execution Date : "
        f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        "  Method         : "
        "Baseline / Parameter Validation"
    )

    print(
        "  Assessment     : "
        "Measuring authorized input surfaces..."
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    try:
        session = requests.Session()

        baseline_response = session.get(
            target_url,
            headers=HEADERS,
            timeout=8,
            allow_redirects=True
        )

        baseline = response_fingerprint(
            baseline_response
        )

        extractor_results["baseline"] = baseline

        print(
            "\n  BASELINE"
        )

        print(
            f"  HTTP {baseline['status']} │ "
            f"{baseline['length']} bytes │ "
            f"{baseline['sha256']}"
        )

        print(
            " ────────────────────────────────────────────────────────────────────────"
        )

        print(
            "  DISCOVERING INPUT SURFACES"
        )

        discovered = discover_parameters(
            target_url,
            baseline_response
        )

        extractor_results["parameters"] = discovered

        if not discovered:
            prepare_report_text()
            render_extractor_screen()
            return

        print(
            f"  [+] Discovered {len(discovered)} "
            f"input surface(s)."
        )

        print(
            "\n  PARAMETER VALIDATION"
        )

        print(
            " ────────────────────────────────────────────────────────────────────────"
        )

        print(
            "  PARAMETER              │ METHOD │ SOURCE │ STATUS │ DIFFERENCE"
        )

        print(
            " ────────────────────────────────────────────────────────────────────────"
        )

        canary = "injecasst_canary_7"

        for item in discovered:

            name = item["name"]
            method = item["method"]
            source = item["source"]

            if source == "query":
                test_url = build_query_test_url(
                    target_url,
                    name,
                    canary
                )

                request_method = "GET"

            elif source == "link":
                test_url = build_query_test_url(
                    item["url"],
                    name,
                    canary
                )

                request_method = "GET"

            else:
                test_url = item["url"]
                request_method = method

            try:

                if request_method == "POST":

                    response = session.post(
                        test_url,
                        headers=HEADERS,
                        data={
                            name: canary
                        },
                        timeout=8,
                        allow_redirects=True
                    )

                else:

                    response = session.get(
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

                if differences:
                    extractor_results["differences"] += 1

                result = {
                    "parameter": name,
                    "method": request_method,
                    "source": source,
                    "status": current["status"],
                    "length": current["length"],
                    "fingerprint": current["sha256"],
                    "differences": differences
                }

                extractor_results["tested"].append(
                    result
                )

                diff_text = (
                    ", ".join(differences)
                    if differences
                    else "baseline matched"
                )

                print(
                    f"  {name[:22].ljust(22)} │ "
                    f"{request_method.ljust(6)} │ "
                    f"{source.ljust(6)} │ "
                    f"{str(current['status']).ljust(6)} │ "
                    f"{diff_text}"
                )

            except requests.RequestException as exc:

                extractor_results["errors"] += 1

                extractor_results["tested"].append({
                    "parameter": name,
                    "method": request_method,
                    "source": source,
                    "error": str(exc)
                })

                print(
                    f"  {name[:22].ljust(22)} │ "
                    f"{request_method.ljust(6)} │ "
                    f"{source.ljust(6)} │ "
                    f"ERROR  │ request failed"
                )

        prepare_report_text()

        render_extractor_screen()

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


def render_extractor_screen():
    local_clear()

    draw_local_box(
        "SQLi VALIDATION & EVIDENCE MATRIX"
    )

    print(
        f"  Target Context : "
        f"{extractor_results['url']}"
    )

    print(
        f"  Execution Date : "
        f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        f"  Method         : "
        f"{extractor_results['method_used']}"
    )

    print(
        f"  Assessment     : "
        f"{extractor_results['status_text']}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    baseline = extractor_results["baseline"]

    print(
        "  BASELINE"
    )

    print(
        f"  HTTP {baseline.get('status', '-')}"
        f" │ {baseline.get('length', 0)} bytes"
        f" │ {baseline.get('sha256', '-')}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  PARAMETER VALIDATION"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  PARAMETER              │ METHOD │ SOURCE │ STATUS │ DIFFERENCE"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    for item in extractor_results["tested"]:

        parameter = item["parameter"]

        if "error" in item:

            print(
                f"  {parameter[:22].ljust(22)} │ "
                f"{item['method'].ljust(6)} │ "
                f"{item['source'].ljust(6)} │ "
                f"ERROR  │ request failed"
            )

            continue

        differences = item["differences"]

        diff_text = (
            ", ".join(differences)
            if differences
            else "baseline matched"
        )

        print(
            f"  {parameter[:22].ljust(22)} │ "
            f"{item['method'].ljust(6)} │ "
            f"{item['source'].ljust(6)} │ "
            f"{str(item['status']).ljust(6)} │ "
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
        f"  [+] {extractor_results['ans_tested']}"
    )

    print(
        f"  [+] {extractor_results['ans_found']}"
    )

    print(
        f"  [+] {extractor_results['ans_decided']}"
    )

    print(
        f"  [+] {extractor_results['ans_todo']}"
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
        "   2. Export Validation Evidence to Desktop (.json)"
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
                "InjecAsst_SQLiValidation_"
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
                    extractor_results,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

            print(
                f"\n  [SUCCESS] "
                f"Validation evidence exported: {filename}"
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
        "SQLi VALIDATION & EVIDENCE - TARGET SPECIFICATION"
    )

    print(
        "\n  Enter an authorized HTTP/HTTPS target."
    )

    print(
        "  Query parameters and HTML forms will be inspected."
    )

    try:

        user_input = input(
            "\n  Target URL: "
        ).strip()

    except (KeyboardInterrupt, EOFError):

        local_clear()
        menu_callback()
        return

    parsed = urllib.parse.urlparse(
        user_input
    )

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
    ):

        local_clear()

        draw_local_box(
            "ERROR - INVALID TARGET"
        )

        print(
            "\n  [FATAL] A valid HTTP/HTTPS target is required."
        )

        fail_safe_exit_prompt()
        return

    target_url = user_input

    execute_extraction()


def run_sql_extractor(return_to_menu):

    global menu_callback

    menu_callback = return_to_menu

    reset_results()

    prompt_target()
