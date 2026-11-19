#!/usr/bin/env python3
"""
Doorman-Security-Harness Unified Benchmark Orchestrator
Runs both the red-team attack vectors and benign false-positive evaluation,
validating safety gates and exporting a JSON metrics report.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time


def run_command(cmd: list[str]) -> tuple[int, str, str]:
    """Execute a subprocess command and return exit code, stdout, and stderr."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def main() -> None:
    print("=" * 50)
    print(" DOORMAN AI SECURITY HARNESS - BENCHMARK SUITE")
    print("=" * 50)

    start_time = time.perf_counter()
    reports_dir = Path("harness/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1. Execute Red-Team Attack Suite
    print("\n[*] Executing Red-Team Attack Suite...")
    rt_start = time.perf_counter()
    rt_code, rt_out, rt_err = run_command(
        [sys.executable, "-m", "pytest", "harness/test_runner.py", "-v", "--tb=short"]
    )
    rt_duration = time.perf_counter() - rt_start

    red_team_passed = rt_code == 0
    print(f"    Status: {'PASSED' if red_team_passed else 'FAILED'}")
    print(f"    Duration: {rt_duration:.2f}s")

    # 2. Execute Benign False-Positive Evaluation
    print("\n[*] Executing Benign False-Positive Evaluation...")
    fp_start = time.perf_counter()
    fp_code, fp_out, fp_err = run_command(
        [sys.executable, "harness/eval_false_positives.py"]
    )
    fp_duration = time.perf_counter() - fp_start

    false_positive_passed = fp_code == 0
    print(f"    Status: {'PASSED' if false_positive_passed else 'FAILED'}")
    print(f"    Duration: {fp_duration:.2f}s")

    total_duration = time.perf_counter() - start_time
    overall_passed = red_team_passed and false_positive_passed

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_passed": overall_passed,
        "total_duration_sec": round(total_duration, 4),
        "red_team": {
            "passed": red_team_passed,
            "exit_code": rt_code,
            "duration_sec": round(rt_duration, 4),
        },
        "false_positive": {
            "passed": false_positive_passed,
            "exit_code": fp_code,
            "duration_sec": round(fp_duration, 4),
        },
    }

    report_path = reports_dir / "benchmark_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[+] Report written to {report_path}")

    if not overall_passed:
        if rt_err:
            print(rt_err, file=sys.stderr)
        if fp_err:
            print(fp_err, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()