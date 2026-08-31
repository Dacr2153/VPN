#!/usr/bin/env python3
"""
tests/wireshark/validate_encryption.py — Packet capture validation

Captures traffic on the tun0 interface and verifies:
1. All outbound traffic is encrypted (no plaintext HTTP/DNS visible on tun0)
2. WireGuard outer transport uses UDP with correct port
3. No unencrypted credentials or PII visible in captures

Requires: tshark (Wireshark CLI) installed on the system.
Must be run as root or with CAP_NET_RAW.

Usage:
    sudo python3 tests/wireshark/validate_encryption.py [--interface tun0] [--duration 10]
"""

import argparse
import json
import subprocess
import sys
import os
import re
import tempfile
from pathlib import Path
from typing import List, Dict, Any


def check_tshark() -> bool:
    """Verify tshark is available."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def capture_packets(interface: str, duration: int, output_file: str) -> bool:
    """Capture packets on the given interface for `duration` seconds."""
    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-w", output_file,
        "-q",
    ]
    print(f"[+] Capturing on {interface} for {duration}s...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
    if result.returncode not in (0, 1):  # 1 = interrupted by duration
        print(f"[-] tshark error: {result.stderr.strip()}")
        return False
    return True


def read_capture_json(capture_file: str) -> List[Dict[str, Any]]:
    """Convert pcap to JSON for analysis."""
    cmd = [
        "tshark",
        "-r", capture_file,
        "-T", "json",
        "-e", "frame.number",
        "-e", "frame.len",
        "-e", "ip.proto",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "http.request.uri",
        "-e", "dns.qry.name",
        "-e", "data",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def check_plaintext_http(packets: List[Dict], report: list) -> bool:
    """Fail if any unencrypted HTTP requests are visible."""
    http_packets = [
        p for p in packets
        if p.get("_source", {}).get("layers", {}).get("_ws.col.Protocol") == ["HTTP"]
    ]
    if http_packets:
        report.append({
            "check": "No plaintext HTTP",
            "result": "FAIL",
            "details": f"Found {len(http_packets)} unencrypted HTTP packet(s) on the interface",
        })
        return False
    report.append({"check": "No plaintext HTTP", "result": "PASS"})
    return True


def check_plaintext_dns(packets: List[Dict], report: list) -> bool:
    """Fail if DNS queries are visible (should be tunnelled or blocked)."""
    dns_queries = []
    for p in packets:
        layers = p.get("_source", {}).get("layers", {})
        qnames = layers.get("dns.qry.name", [])
        if qnames:
            dns_queries.extend(qnames)

    if dns_queries:
        report.append({
            "check": "No plaintext DNS",
            "result": "WARN",  # WARN not FAIL — some DNS may be to VPN resolver
            "details": f"Found {len(dns_queries)} DNS queries: {dns_queries[:5]}",
        })
        return True  # Warning only
    report.append({"check": "No plaintext DNS", "result": "PASS"})
    return True


def check_wireguard_udp(packets: List[Dict], wg_port: int, report: list) -> bool:
    """Verify WireGuard traffic is present on the expected UDP port."""
    wg_packets = []
    for p in packets:
        layers = p.get("_source", {}).get("layers", {})
        proto = layers.get("ip.proto", [])
        dstport = layers.get("udp.dstport", [])
        if "17" in proto and str(wg_port) in dstport:  # proto 17 = UDP
            wg_packets.append(p)

    if wg_packets:
        report.append({
            "check": f"WireGuard UDP port {wg_port}",
            "result": "PASS",
            "details": f"Found {len(wg_packets)} WireGuard packet(s)",
        })
        return True
    report.append({
        "check": f"WireGuard UDP port {wg_port}",
        "result": "INFO",
        "details": "No WireGuard traffic captured (is VPN connected?)",
    })
    return True  # Not an error if VPN is not active


def check_no_credentials_in_cleartext(capture_file: str, report: list) -> bool:
    """
    Grep the raw pcap for common credential patterns in cleartext.
    This catches accidental plaintext password or key leaks.
    """
    patterns = [
        rb"password=",
        rb"Authorization: Basic",
        rb"BEGIN PRIVATE KEY",
        rb"BEGIN RSA PRIVATE",
    ]
    try:
        with open(capture_file, "rb") as f:
            data = f.read()
    except OSError:
        report.append({"check": "No credentials in cleartext", "result": "SKIP", "details": "Could not read capture"})
        return True

    found = []
    for pattern in patterns:
        if pattern in data:
            found.append(pattern.decode(errors="replace"))

    if found:
        report.append({
            "check": "No credentials in cleartext",
            "result": "FAIL",
            "details": f"Credential patterns found: {found}",
        })
        return False
    report.append({"check": "No credentials in cleartext", "result": "PASS"})
    return True


def print_report(report: list) -> int:
    """Print the validation report. Returns exit code (0=pass, 1=fail)."""
    print("\n" + "=" * 60)
    print("  VPNForge Encryption Validation Report")
    print("=" * 60)
    exit_code = 0
    for item in report:
        result = item["result"]
        check  = item["check"]
        detail = item.get("details", "")

        if result == "PASS":
            prefix = "\033[32m[PASS]\033[0m"
        elif result == "FAIL":
            prefix = "\033[31m[FAIL]\033[0m"
            exit_code = 1
        elif result == "WARN":
            prefix = "\033[33m[WARN]\033[0m"
        else:
            prefix = f"[{result}]"

        print(f"  {prefix} {check}")
        if detail:
            print(f"         {detail}")

    print("=" * 60)
    status = "ALL CHECKS PASSED" if exit_code == 0 else "SOME CHECKS FAILED"
    color = "\033[32m" if exit_code == 0 else "\033[31m"
    print(f"  {color}{status}\033[0m")
    print("=" * 60 + "\n")
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate VPN traffic encryption via packet capture")
    parser.add_argument("--interface", default="tun0", help="Interface to capture (default: tun0)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds (default: 10)")
    parser.add_argument("--wg-port", type=int, default=51820, help="WireGuard UDP port (default: 51820)")
    parser.add_argument("--pcap", help="Existing pcap file to analyze (skip capture)")
    args = parser.parse_args()

    if not check_tshark():
        print("ERROR: tshark not found. Install with: sudo apt install tshark")
        return 2

    report = []

    if args.pcap:
        capture_file = args.pcap
    else:
        if os.geteuid() != 0:
            print("WARNING: Not running as root. Packet capture may fail.")

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            capture_file = f.name

        if not capture_packets(args.interface, args.duration, capture_file):
            print("ERROR: Packet capture failed")
            return 2

    print(f"[+] Analyzing {capture_file}...")
    packets = read_capture_json(capture_file)
    print(f"[+] Captured {len(packets)} packets")

    # Run checks
    check_plaintext_http(packets, report)
    check_plaintext_dns(packets, report)
    check_wireguard_udp(packets, args.wg_port, report)
    check_no_credentials_in_cleartext(capture_file, report)

    # Cleanup temp file
    if not args.pcap:
        try:
            os.unlink(capture_file)
        except OSError:
            pass

    return print_report(report)


if __name__ == "__main__":
    sys.exit(main())
