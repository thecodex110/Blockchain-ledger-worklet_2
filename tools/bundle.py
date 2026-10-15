#!/usr/bin/env python3
"""
Automated Repository Bundler (`tools/bundle.py`).

Compiles the modular `blockchain_lite` package, test suite, and documentation
into a single-file distribution `blockchain_lite_complete.py`.

Includes:
- Dependency-ordered module concatenation with intra-package import resolution.
- Base64-encoded embedded repository unpacker (`--unpack <dir>`): source, tests, docs and
  config only. Generated or binary-ish artifacts (HTML exports, PDFs, images, archives)
  are never embedded.
- Direct CLI execution for full verification suite (`--test`) and viva demonstration (`--demo`).
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent

ORDERED_MODULES = [
    ("SECTION 1: CROSS-WORKLET INTERFACES & CONSTANTS", "blockchain_lite/interfaces.py"),
    ("SECTION 2: CANONICAL BYTEBUFFER SERIALIZATION", "blockchain_lite/serialization.py"),
    ("SECTION 3: BIT-LEVEL SHA-256 ENGINE (DLCO / WORKLET 2)", "blockchain_lite/crypto/hashing.py"),
    ("SECTION 3b: OPTIONAL HASHLIB SHA-256 BACKEND (--fast-hash)", "blockchain_lite/crypto/fast_hash.py"),
    ("SECTION 4: NUMBER THEORY & ARBITRARY-PRECISION RSA PRIMITIVES", "blockchain_lite/crypto/number_theory.py"),
    ("SECTION 5: RSA ASYMMETRIC CRYPTOGRAPHY ENGINE", "blockchain_lite/crypto/asymmetric.py"),
    ("SECTION 6: TRANSACTION MODEL & DOUBLE-SPEND DETECTION", "blockchain_lite/models/transaction.py"),
    ("SECTION 7: BLOCK MODEL & HEADER HASHING", "blockchain_lite/models/block.py"),
    ("SECTION 8: BINARY MERKLE TREE & SPV INCLUSION PROOFS", "blockchain_lite/ledger/merkle.py"),
    ("SECTION 8b: CONSENSUS RULES (DIFFICULTY SCHEDULE, TIMESTAMPS, COINBASE HEIGHT)", "blockchain_lite/ledger/consensus.py"),
    ("SECTION 9: PROOF-OF-WORK MINING & VERIFICATION ENGINE", "blockchain_lite/ledger/pow.py"),
    ("SECTION 10: UTXO SET STATE & CONSERVATION ENFORCEMENT", "blockchain_lite/ledger/utxo.py"),
    ("SECTION 11: FULL-CHAIN VALIDATOR & TAMPER CASCADE TRACER", "blockchain_lite/ledger/validator.py"),
    ("SECTION 12: DIGITAL WALLET CLIENT LAYER", "blockchain_lite/wallet/wallet.py"),
    ("SECTION 13: BLOCKCHAIN LEDGER & FORK RESOLUTION", "blockchain_lite/ledger/chain.py"),
    ("SECTION 14: ATOMIC DISK PERSISTENCE & INTEGRITY RECOVERY", "blockchain_lite/ledger/persistence.py"),
    ("SECTION 15: POW DIFFICULTY VS. MINING TIME BENCHMARK", "blockchain_lite/benchmarks/pow_benchmark.py"),
    ("SECTION 16: FRAMED NETWORK TRANSPORT & PROTOCOL ENVELOPE", "blockchain_lite/network/transport.py"),
    ("SECTION 17: LEDGER TCP SOCKET SERVER & DISPATCHER", "blockchain_lite/network/server.py"),
    ("SECTION 18: DIGITAL WALLET CLIENT & TCP TRANSPORT", "blockchain_lite/network/client.py"),
    ("SECTION 19: WEB EXPLORER & LIVE DASHBOARD", "blockchain_lite/network/web_dashboard.py"),
    ("SECTION 20: END-TO-END DEMO HARNESS", "blockchain_lite/cli/demo.py"),
]

# Standard library imports to collect and place at the very top
STANDARD_IMPORTS = [
    "from __future__ import annotations",
    "",
    "import argparse",
    "import ast",
    "import base64",
    "import json",
    "import math",
    "import os",
    "import pathlib",
    "import platform",
    "import socket",
    "import statistics",
    "import struct",
    "import sys",
    "import tempfile",
    "import threading",
    "import time",
    "import unittest",
    "import urllib.parse",
    "import urllib.request",
    "from abc import ABC, abstractmethod",
    "from concurrent.futures import ThreadPoolExecutor, as_completed",
    "from dataclasses import dataclass, replace",
    "from http import HTTPStatus",
    "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer",
    "from pathlib import Path",
    "from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple, Union",
    "",
    "# Ensure UTF-8 stdout/stderr encoding on Windows consoles",
    "if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':",
    "    try:",
    "        sys.stdout.reconfigure(encoding='utf-8')",
    "        sys.stderr.reconfigure(encoding='utf-8')",
    "    except Exception:",
    "        pass",
    "",
]


def clean_module_code(code: str) -> str:
    """Strip out future annotations, standard imports, intermediate main blocks, and relative blockchain_lite imports."""
    lines = code.splitlines()
    filtered = []
    skip_multiline = False
    paren_depth = 0
    in_main_block = False

    for line in lines:
        stripped = line.strip()

        if in_main_block:
            # If line is indented or empty, it belongs to the main block
            if not stripped or line.startswith(" ") or line.startswith("\t"):
                continue
            else:
                in_main_block = False

        if stripped.startswith('if __name__ == "__main__":') or stripped.startswith("if __name__ == '__main__':"):
            in_main_block = True
            continue

        if skip_multiline:
            # Inside a skipped multi-line import block
            code_part = stripped.split("#")[0]
            paren_depth += code_part.count("(") - code_part.count(")")
            if paren_depth <= 0 and not stripped.endswith("\\"):
                skip_multiline = False
                paren_depth = 0
            continue

        # Check if line initiates an import we want to skip
        is_future = stripped.startswith("from __future__")
        is_pkg_import = stripped.startswith("from blockchain_lite") or stripped.startswith("import blockchain_lite")
        is_std_import = bool(
            re.match(
                r"^(import|from)\s+(argparse|ast|base64|json|math|os|pathlib|platform|socket|statistics|struct|sys|tempfile|threading|time|unittest|urllib|abc|concurrent|dataclasses|http|typing)",
                stripped,
            )
        )

        if is_future or is_pkg_import or is_std_import:
            code_part = stripped.split("#")[0]
            net_parens = code_part.count("(") - code_part.count(")")
            if net_parens > 0:
                skip_multiline = True
                paren_depth = net_parens
                continue
            elif stripped.endswith("\\"):
                skip_multiline = True
                paren_depth = 0
                continue
            else:
                continue

        filtered.append(line)

    return "\n".join(filtered).strip()


def build_embedded_repo_dict() -> Dict[str, str]:
    """Collect all source code, tests, docs, and config files into a dict."""
    repo_files: Dict[str, str] = {}
    # No ".html": the only HTML files are generated exports (e.g. the 1.4 MB download hub).
    extensions = {".py", ".md", ".toml", ".yml", ".yaml", ".txt"}
    skip_dirs = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv",
                 "build", "dist", "scratch", "htmlcov"}

    for path in REPO_ROOT.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.is_file():
            if path.name == "blockchain_lite_complete.py":
                continue
            if path.suffix in extensions or path.name in {"Dockerfile", ".gitignore", ".dockerignore"}:
                try:
                    rel = path.relative_to(REPO_ROOT).as_posix()
                    repo_files[rel] = path.read_text(encoding="utf-8")
                except Exception:
                    pass
    return repo_files


def generate_bundle() -> Path:
    target = REPO_ROOT / "blockchain_lite_complete.py"
    print(f"[*] Building {target.name}...")

    repo_dict = build_embedded_repo_dict()
    repo_b64 = base64.b64encode(json.dumps(repo_dict).encode("utf-8")).decode("ascii")

    bundle_parts: List[str] = [
        "#!/usr/bin/env python3",
        '"""',
        "=" * 80,
        "MINI PROJECT 5: BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET (MONOLITHIC BUNDLE)",
        "COEP Technological University · Department of Computer Science & Engineering",
        "=" * 80,
        "",
        "Usage:",
        "  1. Run the full 6-stage end-to-end evaluation & viva demonstration:",
        "       python blockchain_lite_complete.py --demo",
        "  2. Run the complete automated verification suite (unpacks to a temp dir if needed):",
        "       python blockchain_lite_complete.py --test",
        "  3. Launch the interactive Web Explorer & Live Dashboard:",
        "       python blockchain_lite_complete.py --dashboard --port 8080",
        "  4. Unpack the full multi-file modular repository:",
        "       python blockchain_lite_complete.py --unpack ./blockchain_lite_project",
        '"""',
        "",
    ]

    bundle_parts.extend(STANDARD_IMPORTS)
    bundle_parts.append("\n")

    for section_title, rel_path in ORDERED_MODULES:
        file_path = REPO_ROOT / rel_path
        if not file_path.is_file():
            print(f"[-] Warning: module file not found: {rel_path}")
            continue

        raw_code = file_path.read_text(encoding="utf-8")
        clean_code = clean_module_code(raw_code)

        bundle_parts.append("# " + "=" * 78)
        bundle_parts.append(f"# {section_title} ({rel_path})")
        bundle_parts.append("# " + "=" * 78)
        bundle_parts.append(clean_code)
        bundle_parts.append("\n")

    # Append embedded unpacker & CLI dispatch
    bundle_parts.extend([
        "# " + "=" * 78,
        "# SECTION 21: EMBEDDED REPOSITORY UNPACKER & CLI ENTRYPOINT",
        "# " + "=" * 78,
        f'_EMBEDDED_REPO_B64 = "{repo_b64}"',
        "",
        """
def unpack_repository(target_dir: Path) -> int:
    raw_json = base64.b64decode(_EMBEDDED_REPO_B64).decode("utf-8")
    files: Dict[str, str] = json.loads(raw_json)
    target_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for rel_path, content in files.items():
        dst = target_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content, encoding="utf-8")
        count += 1
    print(f"[+] Successfully unpacked {count} project files into: {target_dir.resolve()}")
    return 0


def run_full_test_suite() -> int:
    temp_dir = None
    if not (Path.cwd() / "tests").is_dir():
        temp_dir = tempfile.TemporaryDirectory()
        unpack_repository(Path(temp_dir.name))
        sys.path.insert(0, temp_dir.name)

    try:
        root = Path(temp_dir.name) if temp_dir is not None else Path.cwd()
        suite = unittest.TestLoader().discover(start_dir=str(root / "tests"), top_level_dir=str(root))
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(description="Blockchain-Lite Monolithic Bundle")
    parser.add_argument("--demo", action="store_true", help="Run the full 6-stage interactive evaluation demo")
    parser.add_argument("--test", action="store_true", help="Execute the complete automated verification suite")
    parser.add_argument("--dashboard", action="store_true", help="Launch the interactive Web Explorer & Dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Web Dashboard port (default: 8080)")
    parser.add_argument("--unpack", type=str, metavar="DEST_DIR", help="Unpack modular project files to target directory")

    args = parser.parse_args()

    if args.unpack:
        sys.exit(unpack_repository(Path(args.unpack)))
    elif args.test:
        sys.exit(run_full_test_suite())
    elif args.dashboard:
        print(weak_key_warning(384), file=sys.stderr)
        print("[*] Initializing Blockchain-Lite Web Explorer (demo; loopback only)...")
        ledger, wallets = create_demo_ledger_and_wallets()
        server = WebDashboardServer(ledger=ledger, named_wallets=wallets, host="127.0.0.1", port=args.port)
        server.start()
        print(f"[+] Live at: {server.url}")
        print(f"[+] API token for POST routes (the page sends it automatically): {server.api_token}")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            server.stop()
            print("\\n[+] Web server terminated cleanly.")
    else:
        # Default behavior: run complete demonstration
        print(run_complete_demonstration())


if __name__ == "__main__":
    main()
""",
    ])

    content = "\n".join(bundle_parts)
    target.write_text(content, encoding="utf-8")
    print(f"[+] Generated {target.name} ({len(content):,} characters, {target.stat().st_size:,} bytes)")
    return target


if __name__ == "__main__":
    generate_bundle()
