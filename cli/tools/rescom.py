import sys
import os
import time
import json
import hashlib
import statistics
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests


diff_results = {
    "url": "",
    "scan_date": "",
    "parameter": "",
    "baseline": {},
    "true_state": {},
    "false_state": {},
    "comparison": {},
    "risk_level": "UNDETERMINED",
    "ans_tested": "",
    "ans_found": "",
    "ans_decided": "",
    "ans_todo": "",
}

target_url = ""
menu_callback = None


REQUEST_TIMEOUT = 8
SAMPLES = 3

HEADERS = {
    "User-Agent": "InjecAsst-ResponseComparator/4.0",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Cache-Control": "no-cache",
}


def reset_diff_results():
    global diff_results

    diff_results = {
        "url": "",
        "scan_date": "",
        "parameter": "",
        "baseline": {},
        "true_state": {},
        "false_state": {},
        "comparison": {},
        "risk_level": "UNDETERMINED",
        "ans_tested": "",
        "ans_found": "",
        "ans_decided": "",
        "ans_todo": "",
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


def safe_fingerprint(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def response_metrics(response):
    body = response.text or ""

    return {
        "status": response.status_code,
        "length": len(body),
        "words": len(body.split()),
        "fingerprint": safe_fingerprint(body),
        "time_ms": round(response.elapsed.total_seconds() * 1000, 2),
        "content_type": response.headers.get("Content-Type", ""),
        "final_url": response.url,
    }


def median(values):
    if not values:
        return 0

    return round(statistics.median(values), 2)


def request_once(session, url):
    started = time.perf_counter()

    try:
        response = session.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        elapsed = (time.perf_counter() - started) * 1000

        metrics = response_metrics(response)
        metrics["wall_time_ms"] = round(elapsed, 2)
        metrics["error"] = ""

        return metrics

    except requests.RequestException as exc:
        elapsed = (time.perf_counter() - started) * 1000

        return {
            "status": None,
            "length": 0,
            "words": 0,
            "fingerprint": "",
            "time_ms": round(elapsed, 2),
            "wall_time_ms": round(elapsed, 2),
            "content_type": "",
            "final_url": "",
            "error": str(exc),
        }


def sample_request(session, url, count=SAMPLES):
    samples = []

    for _ in range(count):
        result = request_once(session, url)
        samples.append(result)

        if result.get("error"):
            break

    successful = [x for x in samples if not x.get("error")]

    if not successful:
        return {
            "samples": len(samples),
            "successful_samples": 0,
            "status": None,
            "length": 0,
            "words": 0,
            "fingerprint": "",
            "time_ms": 0,
            "statuses": [],
            "errors": [x.get("error", "") for x in samples],
        }

    statuses = [x["status"] for x in successful]
    lengths = [x["length"] for x in successful]
    words = [x["words"] for x in successful]
    times = [x["time_ms"] for x in successful]

    fingerprints = [x["fingerprint"] for x in successful]

    return {
        "samples": len(samples),
        "successful_samples": len(successful),
        "status": max(set(statuses), key=statuses.count),
        "length": int(median(lengths)),
        "words": int(median(words)),
        "fingerprint": fingerprints[0],
        "time_ms": median(times),
        "statuses": statuses,
        "errors": [x.get("error", "") for x in samples if x.get("error")],
    }


def parse_target(url):
    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Target must use HTTP or HTTPS.")

    if not parsed.netloc:
        raise ValueError("Target URL must contain a valid host.")

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    return parsed, parameters


def build_url(parsed, parameters):
    query = urlencode(parameters, doseq=True)

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            query,
            parsed.fragment,
        )
    )


def create_state_url(parsed, parameters, parameter_name, value):
    modified = []

    replaced = False

    for key, current_value in parameters:
        if key == parameter_name and not replaced:
            modified.append((key, value))
            replaced = True
        else:
            modified.append((key, current_value))

    return build_url(parsed, modified)


def render_metric_block(title, data):
    print(f"  {title}")
    print("   ├── Samples              :", data.get("samples", 0))
    print("   ├── Successful Samples   :", data.get("successful_samples", 0))
    print("   ├── HTTP Status          :", data.get("status", "N/A"))
    print("   ├── Response Length      :", data.get("length", 0), "Bytes")
    print("   ├── Word Count           :", data.get("words", 0))
    print("   ├── Median Latency       :", data.get("time_ms", 0), "ms")
    print("   └── Fingerprint          :", data.get("fingerprint", "N/A"))


def compare_states(baseline, true_state, false_state):
    length_delta = abs(
        true_state["length"] - false_state["length"]
    )

    word_delta = abs(
        true_state["words"] - false_state["words"]
    )

    time_delta = abs(
        true_state["time_ms"] - false_state["time_ms"]
    )

    status_changed = (
        true_state["status"] != false_state["status"]
    )

    fingerprint_changed = (
        true_state["fingerprint"] != false_state["fingerprint"]
    )

    baseline_true_distance = abs(
        true_state["length"] - baseline["length"]
    )

    baseline_false_distance = abs(
        false_state["length"] - baseline["length"]
    )

    errors = (
        baseline["successful_samples"] == 0
        or true_state["successful_samples"] == 0
        or false_state["successful_samples"] == 0
    )

    signal_score = 0

    if status_changed:
        signal_score += 2

    if fingerprint_changed:
        signal_score += 2

    if length_delta >= 50:
        signal_score += 2
    elif length_delta >= 20:
        signal_score += 1

    if word_delta >= 10:
        signal_score += 2
    elif word_delta >= 5:
        signal_score += 1

    if time_delta >= 1000:
        signal_score += 2
    elif time_delta >= 500:
        signal_score += 1

    if errors:
        signal_score = 0

    return {
        "length_delta": length_delta,
        "word_delta": word_delta,
        "time_delta_ms": time_delta,
        "status_changed": status_changed,
        "fingerprint_changed": fingerprint_changed,
        "baseline_true_length_distance": baseline_true_distance,
        "baseline_false_length_distance": baseline_false_distance,
        "signal_score": signal_score,
        "signal_detected": signal_score >= 3 and not errors,
        "measurement_error": errors,
    }


def back_to_menu_prompt():
    print("  Select Next Action Plan:")
    print("   1. Return to Main Management Console")
    print("   2. Export Structural Telemetry Matrix to Desktop (.json)")

    sys.stdout.write(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
        "\n  Specify Option (1 or 2): \x1b[0m"
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
                "Desktop",
            )

            os.makedirs(desktop_path, exist_ok=True)

            file_name = (
                f"InjecAsst_RescomAuditReport_"
                f"{int(time.time())}.json"
            )

            full_path = os.path.join(
                desktop_path,
                file_name,
            )

            with open(
                full_path,
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    diff_results,
                    file,
                    ensure_ascii=False,
                    indent=4,
                )

            print(
                f"\n\x1b[32m"
                f"  [SUCCESS] Telemetry payload saved: {file_name}"
                f"\x1b[0m"
            )

        except Exception as exc:
            print(
                f"\n\x1b[31m"
                f"  [ERROR] Export failed: {exc}"
                f"\x1b[0m"
            )

        print(
            "\n\x1b[0m\x1b[22m\x1b[38;5;16m"
            "  Press Enter to resume main session loop..."
            "\x1b[0m"
        )

        try:
            input()
        except (KeyboardInterrupt, EOFError):
            pass

    local_clear()
    menu_callback()


def fail_safe_exit_prompt():
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

    draw_local_box(
        "HTTP METRIC DIFFERENTIAL ANALYSIS RESULTS"
    )

    sys.stdout.write(
        "\x1b[0m\x1b[22m\x1b[38;5;16m"
    )

    print(f"  Target URI      : {diff_results['url']}")
    print(f"  Execution Date  : {diff_results['scan_date']}")
    print(f"  Tested Parameter: {diff_results['parameter']}")

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    render_metric_block(
        "BASELINE RESPONSE",
        diff_results["baseline"],
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    render_metric_block(
        "TRUE STATE RESPONSE",
        diff_results["true_state"],
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    render_metric_block(
        "FALSE STATE RESPONSE",
        diff_results["false_state"],
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    comparison = diff_results["comparison"]

    print("  DIFFERENTIAL ANALYSIS")
    print("   ├── Status Changed      :", comparison.get("status_changed"))
    print(
        "   ├── Fingerprint Changed :",
        comparison.get("fingerprint_changed"),
    )
    print(
        "   ├── Length Difference   :",
        comparison.get("length_delta"),
        "Bytes",
    )
    print(
        "   ├── Word Difference     :",
        comparison.get("word_delta"),
        "Words",
    )
    print(
        "   ├── Latency Difference  :",
        comparison.get("time_delta_ms"),
        "ms",
    )
    print(
        "   ├── Signal Score        :",
        comparison.get("signal_score"),
    )
    print(
        "   └── Differential Signal :",
        "OBSERVED"
        if comparison.get("signal_detected")
        else "NOT OBSERVED",
    )

    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print("  ASSESSMENT & ACTION MATRIX")
    print(
        " ────────────────────────────────────────────────────────────────────────"
    )

    print(f"  [+] {diff_results['ans_tested']}")
    print(f"  [+] {diff_results['ans_found']}")
    print(f"  [+] {diff_results['ans_decided']}")
    print(f"  [+] {diff_results['ans_todo']}")

    print(
        " ────────────────────────────────────────────────────────────────────────\n"
    )

    back_to_menu_prompt()


def execute_diff_engine():
    local_clear()

    draw_local_box(
        "LIVE HTTP RESPONSE DIFFERENTIAL ANALYZER"
    )

    print(
        f"\x1b[0m\x1b[22m\x1b[38;5;16m"
        f"\n  Target URL: {target_url}\x1b[0m"
    )

    if not (
        target_url.startswith("http://")
        or target_url.startswith("https://")
    ):
        local_clear()
        draw_local_box("ERROR - VALIDATION FAILURE")

        print(
            "\n\x1b[31m"
            "  [FATAL] Invalid URI schema."
            "\x1b[0m"
        )

        fail_safe_exit_prompt()
        return

    try:
        parsed, parameters = parse_target(target_url)

        if not parameters:
            local_clear()

            draw_local_box(
                "PARAMETER REQUIRED"
            )

            print(
                "\n\x1b[31m"
                "  [!] This analyzer requires an existing query parameter."
                "\x1b[0m"
            )

            print(
                "\n  Example:"
                "\n   https://example.test/item?id=1"
            )

            print(
                "\n  No automatic parameter was invented."
            )

            fail_safe_exit_prompt()
            return

        local_clear()

        draw_local_box(
            "LIVE HTTP RESPONSE DIFFERENTIAL ANALYZER"
        )

        print(
            f"\n  Target URL : {target_url}"
        )

        print(
            "\n  Available parameters:"
        )

        for index, (name, value) in enumerate(
            parameters,
            start=1,
        ):
            print(
                f"   {index}. {name}={value}"
            )

        print()

        try:
            selection = input(
                "  Select parameter number: "
            ).strip()

            parameter_index = int(selection) - 1

            if parameter_index < 0 or parameter_index >= len(parameters):
                raise ValueError

        except (ValueError, KeyboardInterrupt, EOFError):
            local_clear()
            fail_safe_exit_prompt()
            return

        parameter_name, original_value = parameters[
            parameter_index
        ]

        diff_results["url"] = target_url
        diff_results["scan_date"] = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        diff_results["parameter"] = parameter_name

        true_value = f"{original_value} AND 1=1"
        false_value = f"{original_value} AND 1=2"

        baseline_url = build_url(
            parsed,
            parameters,
        )

        true_url = create_state_url(
            parsed,
            parameters,
            parameter_name,
            true_value,
        )

        false_url = create_state_url(
            parsed,
            parameters,
            parameter_name,
            false_value,
        )

        print(
            "\n  [*] Establishing live baseline..."
        )

        session = requests.Session()

        baseline = sample_request(
            session,
            baseline_url,
        )

        print(
            "  [*] Testing TRUE-state differential..."
        )

        true_state = sample_request(
            session,
            true_url,
        )

        print(
            "  [*] Testing FALSE-state differential..."
        )

        false_state = sample_request(
            session,
            false_url,
        )

        comparison = compare_states(
            baseline,
            true_state,
            false_state,
        )

        diff_results["baseline"] = baseline
        diff_results["true_state"] = true_state
        diff_results["false_state"] = false_state
        diff_results["comparison"] = comparison

        diff_results["ans_tested"] = (
            f"LIVE HTTP DIFFERENTIAL TEST: "
            f"Baseline plus {SAMPLES} sample(s) per state were "
            f"measured for parameter '{parameter_name}' using "
            f"status, response size, word count, fingerprint "
            f"and latency characteristics."
        )

        if comparison["measurement_error"]:
            diff_results["risk_level"] = "UNDETERMINED"

            diff_results["ans_found"] = (
                "MEASUREMENT RESULT: One or more response states "
                "could not be measured reliably."
            )

            diff_results["ans_decided"] = (
                "DETECTION DECISION: No differential security "
                "conclusion was produced because the live response "
                "sample set was incomplete."
            )

            diff_results["ans_todo"] = (
                "ACTION REQUIRED: Re-run the assessment against an "
                "authorized target and verify network, authentication, "
                "rate-limit or edge-protection effects."
            )

        elif comparison["signal_detected"]:
            diff_results["risk_level"] = (
                "REVIEW REQUIRED"
            )

            diff_results["ans_found"] = (
                "DIFFERENTIAL SIGNAL: TRUE and FALSE states "
                "produced measurable response differences."
            )

            diff_results["ans_decided"] = (
                "DETECTION DECISION: The response differential is "
                "a live observation, not proof of SQL injection. "
                "Status, body characteristics and/or timing differed "
                "between the compared states."
            )

            diff_results["ans_todo"] = (
                "ACTION REQUIRED: Validate the signal manually "
                "during an authorized assessment and eliminate "
                "application-state, caching, authentication, "
                "random-content and edge-protection explanations "
                "before treating it as a vulnerability."
            )

        else:
            diff_results["risk_level"] = (
                "LOW / NO DIFFERENTIAL OBSERVED"
            )

            diff_results["ans_found"] = (
                "MEASUREMENT RESULT: No material TRUE/FALSE "
                "response differential was observed under the "
                "current test conditions."
            )

            diff_results["ans_decided"] = (
                "DETECTION DECISION: The measured response "
                "characteristics remained sufficiently similar "
                "to avoid flagging a differential signal."
            )

            diff_results["ans_todo"] = (
                "ACTION REQUIRED: No vulnerability is established. "
                "If authorized testing continues, investigate other "
                "parameters or application paths using controlled "
                "manual validation."
            )

        render_report_screen()

    except Exception as err:
        print(
            f"\n\x1b[31m"
            f"  [FATAL] Differential analysis aborted: {err}"
            f"\x1b[0m"
        )

        fail_safe_exit_prompt()


def prompt_target():
    global target_url

    local_clear()

    draw_local_box(
        "HTTP RESPONSE COMPARATOR - TARGET SPECIFICATION"
    )

    print(
        "\n  Enter Target Parameterized URL:"
    )

    try:
        user_input = input(
            "  > "
        ).strip()

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
            "\n\x1b[31m"
            "  [FATAL] Target URL cannot be empty."
            "\x1b[0m"
        )

        fail_safe_exit_prompt()
        return

    target_url = user_input

    execute_diff_engine()


def run_res_com(return_to_menu):
    global menu_callback, target_url

    menu_callback = return_to_menu
    target_url = ""

    reset_diff_results()

    prompt_target()
