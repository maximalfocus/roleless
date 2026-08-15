from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence

import httpx

from roleless.scenarios import Comparison, run_comparison, run_one


def wait_ready(base_url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{base_url}/health", timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"application did not become ready: {base_url}")


def render(comparison: Comparison, *, verbose: bool = False) -> None:
    print("BFLA comparison — role source: stored user record")
    print("rung  app         actor     role    function")
    print("      enforcement/status -> effect")
    for result in comparison.results:
        print(
            f"{result.rung:<5} {result.application:<11} {result.actor:<9} "
            f"{result.attributed_role:<7} {result.function:<33} "
            f"{result.enforcement}; {result.status} -> {result.effect} [{result.verdict}]"
        )
    if verbose:
        print("\nHTTP exchanges (fictional demo credentials only)")
        for exchange in comparison.exchanges:
            print(
                json.dumps(
                    {
                        "application": exchange.application,
                        "request": {
                            "method": exchange.method,
                            "path": exchange.path,
                            "headers": exchange.headers,
                            "body": exchange.body,
                        },
                        "response": {"status": exchange.status, "body": exchange.response},
                    },
                    sort_keys=True,
                )
            )


def compare(secure_url: str, vulnerable_url: str, *, verbose: bool = False) -> None:
    wait_ready(secure_url)
    wait_ready(vulnerable_url)
    with (
        httpx.Client(base_url=secure_url, timeout=10) as secure,
        httpx.Client(base_url=vulnerable_url, timeout=10) as vulnerable,
    ):
        render(run_comparison(secure, vulnerable), verbose=verbose)


def interactive(secure_url: str, vulnerable_url: str, *, verbose: bool = False) -> None:
    application = input("Application [secure/vulnerable]: ").strip().lower()
    if application not in {"secure", "vulnerable"}:
        raise SystemExit("choose secure or vulnerable")
    rung_text = input("Rung [1/2/3/4/5]: ").strip()
    if rung_text not in {"1", "2", "3", "4", "5"}:
        raise SystemExit("choose rung 1, 2, 3, 4, or 5")
    base_url = secure_url if application == "secure" else vulnerable_url
    wait_ready(base_url)
    with httpx.Client(base_url=base_url, timeout=10) as client:
        render(run_one(int(rung_text), application, client), verbose=verbose)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Compare function authorization behavior")
    parser.add_argument("--secure-url", default="http://127.0.0.1:8000")
    parser.add_argument("--vulnerable-url", default="http://127.0.0.1:8001")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("compare")
    subparsers.add_parser("interactive")
    args = parser.parse_args(argv)
    if args.command == "compare":
        compare(args.secure_url, args.vulnerable_url, verbose=args.verbose)
    else:
        interactive(args.secure_url, args.vulnerable_url, verbose=args.verbose)


if __name__ == "__main__":
    main()
