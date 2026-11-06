"""
Run the complete QuantumGuard test suite.

    python -m tests.run_all

Combines tests/test_all.py (Phases 1-5), tests/test_phase67.py (Phases 6-7
and the completeness attestation) and tests/test_tamper.py (bug regressions
and the tamper harness). Nothing requires PostgreSQL, eBPF or root.
"""
from __future__ import annotations

import sys
import unittest


def main() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for name in ("tests.test_all", "tests.test_phase67", "tests.test_tamper"):
        __import__(name)
        suite.addTests(loader.loadTestsFromModule(sys.modules[name]))

    result = unittest.TextTestRunner(verbosity=2).run(suite)

    print()
    print("=" * 62)
    print(f"  QuantumGuard: {result.testsRun} tests, "
          f"{len(result.failures)} failed, {len(result.errors)} errors")
    print("=" * 62)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
