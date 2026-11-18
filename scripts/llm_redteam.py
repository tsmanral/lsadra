#!/usr/bin/env python3
"""Run the LLM prompt-injection red-team corpus (G-30).

Offline by default: checks fencing and that the validator refuses what an
obedient model would return. With --endpoint, also sends every case to an
OpenAI-compatible endpoint (llama-server) on this machine and scores the
replies deterministically. Exits non-zero if any case fails.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("LSADRA_DEV_MODE", "true")  # no server secrets needed for this tool


def main() -> int:
    from lsadra.llm.redteam import load_cases, run_live_case, run_offline_case

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--endpoint", help="base URL of a local OpenAI-compatible server")
    ap.add_argument("--model", help="model name to send (llama-server ignores it)")
    args = ap.parse_args()

    failed = 0
    for case in load_cases():
        results = [("offline", run_offline_case(case))]
        if args.endpoint:
            try:
                results.append(("live", run_live_case(case, args.endpoint, args.model)))
            except Exception as exc:  # noqa: BLE001 - report and keep going
                print(f"FAIL live    {case['id']}: request failed: {exc}")
                failed += 1
        for mode, res in results:
            status = "ok  " if res.passed else "FAIL"
            print(f"{status} {mode:7} {res.case_id}" + ("" if res.passed else f": {'; '.join(res.failures)}"))
            failed += 0 if res.passed else 1
    print(f"\n{failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
