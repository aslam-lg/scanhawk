#!/usr/bin/env python3
"""
ScanHawk — A fast, multi-threaded TCP port scanner for cybersecurity
network reconnaissance and auditing.

LEGAL / ETHICAL NOTICE:
Only use this tool against hosts and networks you own or have explicit
written permission to test. Unauthorized scanning of systems you don't
control may be illegal under laws such as the U.S. Computer Fraud and
Abuse Act (or equivalent laws in your country).

Features:
  - Multi-threaded TCP connect scanning (fast on large port ranges)
  - Service name guessing (via socket.getservbyport)
  - Optional banner grabbing on open ports
  - Common-ports shortcut (--top-ports)
  - CSV / JSON export
  - Simple, readable CLI output

Usage examples:
  python3 scanhawk.py 192.168.1.10
  python3 scanhawk.py 192.168.1.10 -p 1-1000
  python3 scanhawk.py scanme.nmap.org -p 22,80,443 --banner
  python3 scanhawk.py 10.0.0.5 --top-ports --json results.json
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime

# A reasonably useful "top ports" list (subset inspired by nmap's top ports)
TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636,
    993, 995, 1025, 1080, 1433, 1521, 1723, 2049, 2121, 3128, 3306,
    3389, 5432, 5900, 5985, 6379, 8000, 8008, 8080, 8443, 8888, 9200,
    27017,
]


def parse_ports(port_str):
    """Parse a port string like '22,80,443' or '1-1000' or a mix."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def resolve_target(target):
    """Resolve a hostname to an IP, or validate an IP address."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise SystemExit(f"[!] Could not resolve host '{target}': {e}")


def grab_banner(sock):
    """Try to read a short banner from an already-connected socket."""
    try:
        sock.settimeout(1.0)
        data = sock.recv(256)
        if data:
            return data.decode(errors="replace").strip().splitlines()[0][:120]
    except Exception:
        pass
    return ""


def scan_port(ip, port, timeout, banner):
    """Attempt a TCP connect to a single port. Returns a result dict or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                banner_text = grab_banner(s) if banner else ""
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner_text,
                }
    except Exception:
        pass
    return None


def run_scan(ip, ports, threads, timeout, banner, verbose):
    open_ports = []
    total = len(ports)
    completed = 0
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, banner): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if verbose and completed % 200 == 0:
                pct = completed / total * 100
                print(f"    ...scanned {completed}/{total} ports ({pct:.0f}%)", file=sys.stderr)
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda r: r["port"])
    elapsed = time.time() - start
    return open_ports, elapsed


def print_results(target, ip, open_ports, elapsed, total_ports):
    print(f"\nScan report for {target} ({ip})")
    print(f"Scanned {total_ports} ports in {elapsed:.2f}s")
    print("-" * 60)
    if not open_ports:
        print("No open ports found.")
        return
    print(f"{'PORT':<10}{'STATE':<8}{'SERVICE':<15}BANNER")
    for r in open_ports:
        print(f"{r['port']:<10}{r['state']:<8}{r['service']:<15}{r['banner']}")
    print("-" * 60)
    print(f"{len(open_ports)} open port(s) found.")


def export_json(path, target, ip, open_ports, elapsed):
    payload = {
        "target": target,
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "open_ports": open_ports,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[+] JSON results written to {path}")


def export_csv(path, open_ports):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
        writer.writeheader()
        writer.writerows(open_ports)
    print(f"[+] CSV results written to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="ScanHawk — A multi-threaded TCP port scanner for cybersecurity auditing. "
                     "Only scan hosts you own or are authorized to test.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan: e.g. '22,80,443' or '1-1000' or '22,80,1000-2000'"
    )
    parser.add_argument(
        "--top-ports", action="store_true",
        help="Scan a curated list of commonly-used ports instead of -p"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=200,
        help="Number of concurrent worker threads"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.75,
        help="Per-connection timeout in seconds"
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Attempt to grab a service banner on open ports"
    )
    parser.add_argument("--json", metavar="FILE", help="Write results to a JSON file")
    parser.add_argument("--csv", metavar="FILE", help="Write results to a CSV file")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show progress while scanning"
    )
    parser.add_argument(
        "--i-have-permission", action="store_true",
        help="Confirm you are authorized to scan this target (required)"
    )

    args = parser.parse_args()

    if not args.i_have_permission:
        parser.error(
            "You must pass --i-have-permission to confirm you own this target "
            "or have explicit authorization to scan it."
        )

    ip = resolve_target(args.target)

    ports = TOP_PORTS if args.top_ports else parse_ports(args.ports)

    print(f"Starting scan of {args.target} ({ip}) — {len(ports)} port(s)")
    if args.verbose:
        print(f"    threads={args.threads} timeout={args.timeout}s banner={args.banner}", file=sys.stderr)

    open_ports, elapsed = run_scan(
        ip, ports, args.threads, args.timeout, args.banner, args.verbose
    )

    print_results(args.target, ip, open_ports, elapsed, len(ports))

    if args.json:
        export_json(args.json, args.target, ip, open_ports, elapsed)
    if args.csv:
        export_csv(args.csv, open_ports)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
