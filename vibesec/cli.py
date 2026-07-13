from __future__ import annotations

import argparse
import json

from .scanner import scan_directory


def main() -> None:
    parser = argparse.ArgumentParser(prog="vibesec")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan an authorized local source directory")
    scan.add_argument("path")
    scan.add_argument("--format", choices=("json",), default="json")
    args = parser.parse_args()
    print(json.dumps(scan_directory(args.path), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
