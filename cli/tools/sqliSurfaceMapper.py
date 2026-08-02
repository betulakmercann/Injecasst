import sys
import os
import time
import json
import requests
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode


results = {
    "target": "",
    "scan_date": "",
    "status": 0,
    "pages_checked": 0,
    "links_checked": 0,
    "parameters_found": 0,
    "parameters": [],
    "forms": [],
    "errors": 0,
    "ans_tested": "",
    "ans_found": "",
    "ans_decided": "",
    "ans_todo": ""
}

target_url = ""
menu_callback = None


def reset_results():
    global results

    results = {
        "target": "",
        "scan_date": "",
        "status": 0,
        "pages_checked": 0,
        "links_checked": 0,
        "parameters_found": 0,
        "parameters": [],
        "forms": [],
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

    padding_total = max(0, 68 - len(title))
    left = padding_total // 2
    right = padding_total - left

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


def fail_safe_exit_prompt():
    print(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "\n  Press Enter to return to main management console...\x1b[0m"
    )

    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass

    local_clear()
    menu_callback()


def normalize_target(value):
    value = value.strip()

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)

    if not parsed.netloc:
        return None

    return value


def same_origin(base_url, candidate):
    base = urlparse(base_url)
    target = urlparse(candidate)

    return target.scheme in ("http", "https") and target.netloc == base.netloc


def extract_parameter(url):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)

    if not params:
        return []

    return [
        {
            "name": name,
            "value": value,
            "url": url
        }
        for name, value in params
    ]


def extract_forms(html, page_url):
    forms = []

    marker = "<form"
    lower = html.lower()

    position = 0

    while True:
        start = lower.find(marker, position)

        if start == -1:
            break

        end = lower.find(">", start)

        if end == -1:
            break

        opening = html[start:end + 1]

        action = ""
        method = "GET"

        action_marker = 'action="'
        action_pos = opening.lower().find(action_marker)

        if action_pos != -1:
            action_start = action_pos + len(action_marker)
            action_end = opening.find('"', action_start)

            if action_end != -1:
                action = opening[action_start:action_end]

        method_marker = 'method="'
        method_pos = opening.lower().find(method_marker)

        if method_pos != -1:
            method_start = method_pos + len(method_marker)
            method_end = opening.find('"', method_start)

            if method_end != -1:
                method = opening[method_start:method_end].upper()

        form_end = lower.find("</form>", end)

        if form_end == -1:
            form_end = min(len(html), end + 5000)

        form_body = html[end + 1:form_end]

        inputs = []
        search_pos = 0

        while True:
            input_pos = form_body.lower().find("<input", search_pos)

            if input_pos == -1:
                break

            input_end = form_body.find(">", input_pos)

            if input_end == -1:
                break

            tag = form_body[input_pos:input_end + 1]

            name = ""
            input_name_marker = 'name="'
            name_pos = tag.lower().find(input_name_marker)

            if name_pos != -1:
                name_start = name_pos + len(input_name_marker)
                name_end = tag.find('"', name_start)

                if name_end != -1:
                    name = tag[name_start:name_end]

            if name:
                inputs.append(name)

            search_pos = input_end + 1

        forms.append({
            "action": urljoin(page_url, action) if action else page_url,
            "method": method,
            "inputs": inputs
        })

        position = form_end + 7

    return forms


def extract_links(html, page_url):
    links = []
    lower = html.lower()
    position = 0

    while True:
        pos = lower.find('href="', position)

        if pos == -1:
            break

        start = pos + 6
        end = html.find('"', start)

        if end == -1:
            break

        href = html[start:end].strip()

        if href:
            absolute = urljoin(page_url, href)

            if same_origin(page_url, absolute):
                links.append(absolute)

        position = end + 1

    return list(dict.fromkeys(links))


def register_parameter(url, parameter):
    parsed = urlparse(url)

    existing = [
        item["name"]
        for item in results["parameters"]
        if item["url"] == url
    ]

    if parameter["name"] in existing:
        return

    results["parameters"].append({
        "url": url,
        "parameter": parameter["name"],
        "value": parameter["value"],
        "location": "QUERY"
    })


def crawl_target():
    global results

    headers = {
        "User-Agent": "InjecAsst-SQLiSurfaceMapper/1.0"
    }

    queue = [target_url]
    visited = set()

    session = requests.Session()

    while queue and len(visited) < 10:
        current = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)

        try:
            response = session.get(
                current,
                headers=headers,
                timeout=7,
                allow_redirects=True
            )

            results["pages_checked"] += 1

            if results["pages_checked"] == 1:
                results["status"] = response.status_code

            for parameter in extract_parameter(response.url):
                register_parameter(response.url, parameter)

            forms = extract_forms(response.text, response.url)

            for form in forms:
                if form["inputs"]:
                    results["forms"].append(form)

            links = extract_links(response.text, response.url)

            for link in links:
                results["links_checked"] += 1

                for parameter in extract_parameter(link):
                    register_parameter(link, parameter)

                parsed = urlparse(link)

                clean_url = parsed._replace(
                    fragment=""
                ).geturl()

                if clean_url not in visited and clean_url not in queue:
                    queue.append(clean_url)

        except requests.RequestException:
            results["errors"] += 1

    results["parameters_found"] = len(results["parameters"])


def render_report():
    local_clear()

    draw_local_box("SQL INJECTION TEST SURFACE MAPPER")

    print(
        f"  Target Context  : {results['target']}"
    )

    print(
        f"  Execution Date  : {results['scan_date']}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print("  ENUMERATION SUMMARY")

    print(
        f"   ├── Pages Checked              : {results['pages_checked']}"
    )

    print(
        f"   ├── Links Checked              : {results['links_checked']}"
    )

    print(
        f"   ├── Query Parameters Found     : {results['parameters_found']}"
    )

    print(
        f"   ├── Forms Identified           : {len(results['forms'])}"
    )

    print(
        f"   └── Request Errors             : {results['errors']}"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print("  DISCOVERED SQLi TEST SURFACES")

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(
        "  PARAMETER              │ LOCATION │ SOURCE"
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    if results["parameters"]:

        for item in results["parameters"][:30]:

            print(
                f"  {item['parameter'].ljust(22)} │ "
                f"{item['location'].ljust(8)} │ "
                f"{item['url']}"
            )

    else:

        print(
            "  [-] No query parameters discovered during the current crawl."
        )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print("  FORM INPUT SURFACES")

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    if results["forms"]:

        for form in results["forms"][:20]:

            print(
                f"  {form['method'].ljust(6)} │ "
                f"{form['action']} │ "
                f"Inputs: {', '.join(form['inputs'])}"
            )

    else:

        print(
            "  [-] No HTML forms identified."
        )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print("  ASSESSMENT & ACTION MATRIX")

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(f"  [+] {results['ans_tested']}")
    print(f"  [+] {results['ans_found']}")
    print(f"  [+] {results['ans_decided']}")
    print(f"  [+] {results['ans_todo']}")

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    back_to_menu_prompt()


def back_to_menu_prompt():
    print("  Select Next Action Plan:")
    print("   1. Return to Main Management Console")
    print("   2. Export SQLi Surface Matrix to Desktop (.json)")

    sys.stdout.write(
        "\n  Specify Option (1 or 2): "
    )

    try:
        choice = input().strip()
    except (KeyboardInterrupt, EOFError):
        local_clear()
        menu_callback()
        return

    if choice == "2":

        try:
            desktop = os.path.join(
                os.path.expanduser("~"),
                "Desktop"
            )

            os.makedirs(desktop, exist_ok=True)

            filename = (
                f"InjecAsst_SQLiSurfaceReport_{int(time.time())}.json"
            )

            path = os.path.join(desktop, filename)

            with open(path, "w", encoding="utf-8") as file:
                json.dump(
                    results,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

            print(
                f"\n\x1b[32m  [SUCCESS] "
                f"SQLi surface report saved: {filename}\x1b[0m"
            )

            input("\n  Press Enter to continue...")

        except Exception as error:

            print(
                f"\n\x1b[31m  [ERROR] "
                f"Export failed: {error}\x1b[0m"
            )

            input("\n  Press Enter to continue...")

    local_clear()
    menu_callback()


def execute_surface_mapping():

    local_clear()

    draw_local_box(
        "ACTIVE SQLi SURFACE DISCOVERY"
    )

    print(
        f"\n  Target URL: {target_url}"
    )

    print(
        "\n  [*] Measuring application structure..."
    )

    try:

        crawl_target()

        results["target"] = target_url
        results["scan_date"] = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        results["ans_tested"] = (
            f"LIVE HTTP ENUMERATION: "
            f"The authorized target was crawled across "
            f"{results['pages_checked']} page(s). "
            f"Links, query parameters and HTML form inputs were inspected."
        )

        if results["parameters_found"]:

            results["ans_found"] = (
                f"DISCOVERY RESULTS: "
                f"{results['parameters_found']} query parameter "
                f"candidate(s) were identified as potential SQLi test surfaces."
            )

            results["ans_decided"] = (
                "DETECTION LOGIC: "
                "Candidates were identified from actual target URLs "
                "and application-generated links rather than invented parameters."
            )

            results["ans_todo"] = (
                "ACTION REQUIRED: "
                "Review the discovered surfaces and perform SQLi validation "
                "only against systems you are authorized to test."
            )

        else:

            results["ans_found"] = (
                "DISCOVERY RESULTS: "
                "No query-string parameter was discovered during the limited crawl."
            )

            results["ans_decided"] = (
                "DETECTION LOGIC: "
                "The analyzer did not invent parameters when the application "
                "did not expose any during discovery."
            )

            results["ans_todo"] = (
                "ACTION REQUIRED: "
                "Review discovered forms or expand authorized application mapping."
            )

        render_report()

    except Exception as error:

        print(
            f"\n\x1b[31m  [FATAL] "
            f"Surface discovery aborted: {error}\x1b[0m"
        )

        fail_safe_exit_prompt()


def prompt_target():

    global target_url

    local_clear()

    draw_local_box(
        "SQLi SURFACE MAPPER - TARGET SPECIFICATION"
    )

    print(
        "\n  Enter normal target URL."
    )

    print(
        "  Example: https://example.com"
    )

    sys.stdout.write(
        "\n  Target URL: "
    )

    try:
        user_input = input().strip()

    except (KeyboardInterrupt, EOFError):

        local_clear()
        menu_callback()
        return

    normalized = normalize_target(user_input)

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

    execute_surface_mapping()


def run_sqli_surface_mapper(return_to_menu):

    global menu_callback, target_url

    menu_callback = return_to_menu

    target_url = ""

    reset_results()

    prompt_target()
