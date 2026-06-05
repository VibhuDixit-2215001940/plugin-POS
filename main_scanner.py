#!/usr/bin/env python3
"""
main_scanner.py — CLI entry point for the Nessus-style plugin scanner.

Usage:
    python main_scanner.py                          # Interactive
    python main_scanner.py -t example.com           # Single target
    python main_scanner.py -t example.com -f http_headers,fingerprint
    python main_scanner.py -t example.com -w 30     # 30 threads
    python main_scanner.py -t example.com --report   # Generate HTML report
"""

import argparse
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import ScanEngine
from core.reporter import ReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Nessus-Style Plugin Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main_scanner.py -t example.com
  python main_scanner.py -t https://target.com -f fingerprint,http_headers
  python main_scanner.py -t target.com -w 30 --report
        """
    )

    parser.add_argument("-t", "--target", help="Target domain or URL")
    parser.add_argument("-f", "--families", help="Comma-separated plugin families to run (default: all)")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Max parallel threads (default: 20)")
    parser.add_argument("-o", "--output", default="findings", help="Output directory (default: findings)")
    parser.add_argument("-p", "--plugins-dir", default="plugins", help="Plugins directory (default: plugins)")
    parser.add_argument("--report", action="store_true", help="Generate HTML report after scan")

    args = parser.parse_args()

    # Get target
    target = args.target
    if not target:
        target = input("Enter target domain or URL: ").strip()
    if not target:
        print("[!] No target provided.")
        sys.exit(1)

    # Parse families
    families = None
    if args.families:
        families = [f.strip() for f in args.families.split(",")]

    # Resolve plugins dir relative to script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_dir = os.path.join(script_dir, args.plugins_dir)
    output_dir = os.path.join(script_dir, args.output)

    # Run scan
    engine = ScanEngine(
        target=target,
        plugins_dir=plugins_dir,
        output_dir=output_dir,
        max_workers=args.workers,
        families=families
    )

    results = engine.run()

    # Generate report
    if args.report or True:  # Always generate report
        print("\n[+] Generating HTML report...")
        reporter = ReportGenerator(engine.scan_dir, engine.target)
        json_path = reporter.generate_json(results)
        html_path = reporter.generate_html(results)
        print(f"  JSON : {json_path}")
        print(f"  HTML : {html_path}")


if __name__ == "__main__":
    main()
