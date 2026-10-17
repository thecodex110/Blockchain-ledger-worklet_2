"""
Unified Test Runner for Blockchain-Lite Ledger & Digital Wallet.
Loads and executes all available phase test suites deterministically.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

TEST_MODULES = [
    "tests.test_phase1_foundation",
    "tests.test_phase2_worklet1",
    "tests.test_phase3_worklet2",
    "tests.test_phase4_worklet3",
    "tests.test_phase5_integration",
    "tests.test_phase6_defensive_verification",
    "tests.test_phase7_advanced_features",
    "tests.test_attack_scenarios",
    "tests.test_phase9_core_engineering",
    "tests.test_phase10_dashboard_ui",
    "tests.test_phase11_fast_hash",
    "tests.test_phase12_serialization_properties",
    "tests.test_phase13_spv_and_keys",
    "tests.test_terminal_console",
]


def main() -> int:
    root = Path(__file__).resolve().parent
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for mod_name in TEST_MODULES:
        rel_path = root.joinpath(*mod_name.split(".")).with_suffix(".py")
        if os.path.isfile(rel_path):
            suite.addTests(loader.loadTestsFromName(mod_name))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
