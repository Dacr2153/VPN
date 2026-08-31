#!/usr/bin/env python3
"""
tests/wireshark/check_dns_leak.py — DNS leak detection

Verifies that all DNS queries are routed through the VPN DNS resolver.
Sends test DNS queries and checks which network interface/resolver responds.

Usage:
    sudo python3 tests/wireshark/check_dns_leak.py [--vpn-resolver 10.0.0.1]
"""

import argparse
import socket
import struct
import time
import sys
import os
import subprocess
from typing import Optional, Tuple, List


# Test domains (use domains that resolve quickly but won't log unusual queries)
TEST_DOMAINS = [
    "example.com",
    "example.org",
    "iana.org",
]

# Well-known public resolvers — a response from these indicates a DNS leak
KNOWN_PUBLIC_RESOLVERS = {
    "8.8.8.8":       "Google DNS",
    "8.8.4.4":       "Google DNS (secondary)",
    "1.1.1.1":       "Cloudflare DNS",
    "1.0.0.1":       "Cloudflare DNS (secondary)",
    "9.9.9.9":       "Quad9",
    "208.67.222.222":"OpenDNS",
    "208.67.220.220":"OpenDNS (secondary)",
}


def build_dns_query(domain: str, query_id: int = 0x1234) -> bytes:
    """Build a minimal DNS A query packet."""
    # Header: ID, flags (standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

    # Question: QNAME, QTYPE=A (1), QCLASS=IN (1)
    qname = b""
    for label in domain.split("."):
        encoded = label.encode()
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"  # root label

    question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def send_dns_query(resolver_ip: str, domain: str, timeout: float = 3.0) -> Optional[str]:
    """
    Send a DNS query to a specific resolver and return the first A record answer,
    or None on failure/timeout.
    """
    query = build_dns_query(domain)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (resolver_ip, 53))
        response, addr = sock.recvfrom(512)
        sock.close()

        # Parse answer count from response header
        _, _, qdcount, ancount = struct.unpack(">HHHH", response[0:8])
        if ancount == 0:
            return None

        # Skip header (12 bytes) + question section
        offset = 12
        # Skip question labels
        while response[offset] != 0:
            if response[offset] & 0xC0 == 0xC0:  # pointer
                offset += 2
                break
            offset += response[offset] + 1
        else:
            offset += 1
        offset += 4  # QTYPE + QCLASS

        # Parse first answer
        if response[offset] & 0xC0 == 0xC0:
            offset += 2  # name pointer
        else:
            while response[offset] != 0:
                offset += response[offset] + 1
            offset += 1
        offset += 8  # TYPE + CLASS + TTL
        rdlength = struct.unpack(">H", response[offset:offset+2])[0]
        offset += 2
        if rdlength == 4:  # IPv4 A record
            ip = ".".join(str(b) for b in response[offset:offset+4])
            return ip
        return None
    except (socket.timeout, OSError, struct.error):
        return None


def get_current_resolvers() -> List[str]:
    """Read /etc/resolv.conf to find active DNS resolvers."""
    resolvers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1])
    except OSError:
        pass
    return resolvers


def check_resolver_responds(resolver_ip: str, domain: str) -> bool:
    """Check if a specific resolver responds to queries."""
    return send_dns_query(resolver_ip, domain) is not None


def run_tshark_dns_capture(duration: int) -> List[str]:
    """
    Capture DNS traffic for `duration` seconds and return list of responding server IPs.
    Requires tshark and root privileges.
    """
    if os.geteuid() != 0:
        return []

    try:
        result = subprocess.run(
            [
                "tshark", "-i", "any",
                "-a", f"duration:{duration}",
                "-Y", "dns",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "dns.flags.response",
                "-q",
            ],
            capture_output=True, text=True, timeout=duration + 10
        )
        responding = set()
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[1] == "1":  # flag=1 means response
                responding.add(parts[0].strip())
        return list(responding)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def main() -> int:
    parser = argparse.ArgumentParser(description="DNS leak detection for VPNForge")
    parser.add_argument("--vpn-resolver", default=None,
                        help="Expected VPN DNS resolver IP (e.g. 10.0.0.1)")
    parser.add_argument("--capture-duration", type=int, default=5,
                        help="Seconds to capture DNS traffic via tshark (requires root)")
    args = parser.parse_args()

    print("=" * 60)
    print("  VPNForge DNS Leak Detection")
    print("=" * 60)

    report = []
    leaked = False

    # ── Step 1: Check /etc/resolv.conf ────────────────────────────────────────
    resolvers = get_current_resolvers()
    print(f"\n[+] Current resolvers from /etc/resolv.conf: {resolvers}")

    for resolver in resolvers:
        if resolver in KNOWN_PUBLIC_RESOLVERS:
            print(f"  \033[31m[LEAK]\033[0m {resolver} is a public resolver ({KNOWN_PUBLIC_RESOLVERS[resolver]})")
            leaked = True
            report.append({
                "type": "resolv.conf leak",
                "resolver": resolver,
                "name": KNOWN_PUBLIC_RESOLVERS[resolver],
            })
        else:
            print(f"  \033[32m[OK]\033[0m   {resolver} (not a known public resolver)")

    # ── Step 2: Test if public resolvers respond (indicates DNS bypass) ────────
    print("\n[+] Testing if known public resolvers respond to queries...")
    for ip, name in list(KNOWN_PUBLIC_RESOLVERS.items())[:4]:  # Test first 4
        domain = TEST_DOMAINS[0]
        responds = check_resolver_responds(ip, domain)
        if responds:
            print(f"  \033[31m[LEAK]\033[0m {ip} ({name}) responded to DNS query for {domain}")
            leaked = True
            report.append({"type": "public resolver reachable", "resolver": ip, "name": name})
        else:
            print(f"  \033[32m[OK]\033[0m   {ip} ({name}) did not respond (blocked by kill switch)")

    # ── Step 3: Verify VPN resolver responds (if specified) ───────────────────
    if args.vpn_resolver:
        print(f"\n[+] Testing VPN resolver {args.vpn_resolver}...")
        for domain in TEST_DOMAINS[:2]:
            result = send_dns_query(args.vpn_resolver, domain)
            if result:
                print(f"  \033[32m[OK]\033[0m   {args.vpn_resolver} resolved {domain} → {result}")
            else:
                print(f"  \033[33m[WARN]\033[0m {args.vpn_resolver} did not respond for {domain}")

    # ── Step 4: Live capture (optional, requires root + tshark) ───────────────
    if os.geteuid() == 0:
        print(f"\n[+] Live DNS capture ({args.capture_duration}s)...")
        responding_servers = run_tshark_dns_capture(args.capture_duration)
        if responding_servers:
            print(f"  DNS responses seen from: {responding_servers}")
            for ip in responding_servers:
                if ip in KNOWN_PUBLIC_RESOLVERS:
                    print(f"  \033[31m[LEAK]\033[0m DNS response from public resolver {ip}")
                    leaked = True

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if leaked:
        print("  \033[31mRESULT: DNS LEAK DETECTED\033[0m")
        print("\n  Recommendations:")
        print("    1. Enable the kill switch: vpnctl kill-switch enable")
        print("    2. Verify /etc/resolv.conf only contains the VPN resolver")
        print("    3. Check systemd-resolved configuration")
    else:
        print("  \033[32mRESULT: NO DNS LEAKS DETECTED\033[0m")
    print("=" * 60 + "\n")

    return 1 if leaked else 0


if __name__ == "__main__":
    sys.exit(main())
