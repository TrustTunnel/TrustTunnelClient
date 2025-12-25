#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TUN Echo Test Script

Requirements:
    - Python 3 installed
    - test_tun_echo server running

Usage:
    Terminal 1 (server):
        sudo ./test_tun_echo

    Terminal 2 (test client):
        python3 test_tun_echo.py
"""

import socket
import threading
import platform
import subprocess
import re
import sys
from typing import Tuple

# --- Test configuration ---------------------------------------------------

TUN_IP = "1.2.3.4"
TCP_PORT = 1234
TEST_MESSAGE = "Hello TUN Echo Test"

# --- Output colors (ANSI) -------------------

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"

TESTS_PASSED = 0
TESTS_FAILED = 0


# --- Helper functions for output ------------------------------------------

def print_header(text: str) -> None:
    print(f"{BLUE}========================================{NC}")
    print(f"{BLUE}{text}{NC}")
    print(f"{BLUE}========================================{NC}")


def print_test(text: str) -> None:
    print(f"{YELLOW}[TEST]{NC} {text}")


def print_success(text: str) -> None:
    global TESTS_PASSED
    print(f"{GREEN}[PASS]{NC} {text}")
    TESTS_PASSED += 1


def print_failure(text: str) -> None:
    global TESTS_FAILED
    print(f"{RED}[FAIL]{NC} {text}")
    TESTS_FAILED += 1


def print_info(text: str) -> None:
    print(f"{BLUE}[INFO]{NC} {text}")


# --- ICMP ping (via system ping command, cross-platform) ------------------

def run_ping(ip: str, count: int = 4, timeout_sec: int = 2) -> Tuple[bool, float]:
    """
    Returns (ok, packet_loss_percent).
    Uses system ping command, handles different flags.
    """
    system = platform.system().lower()
    if system == "windows":
        # ping -n <count> -w <timeout_ms>
        cmd = ["ping", "-n", str(count), "-w", str(timeout_sec * 1000), ip]
    else:
        # Linux/macOS: ping -c <count> -W <timeout>
        cmd = ["ping", "-c", str(count), "-W", str(timeout_sec), ip]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except FileNotFoundError:
        print_failure("'ping' command not found in system")
        return False, 100.0

    output = proc.stdout

    # Parse packet loss percentage
    packet_loss = 100.0

    if "packet loss" in output:
        # Unix format: "4 packets transmitted, 4 received, 0.0% packet loss"
        m = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", output)
        if m:
            packet_loss = float(m.group(1))
    elif "Packets: Sent" in output or "Lost =" in output:
        # Windows format:
        # "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        m = re.search(r"(\d+)%\s*loss", output)
        if m:
            packet_loss = float(m.group(1))

    ok = packet_loss == 0.0
    return ok, packet_loss


# --- TCP / UDP primitives --------------------------------------------------

def tcp_echo(message: str, ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Sends message via TCP and returns the response.
    """
    data = message.encode("utf-8")
    received = b""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(data)
        # Tell server we finished sending
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass

        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                received += chunk
                if len(received) >= len(data):
                    # Assume server echoes exactly the same amount
                    break
            except socket.timeout:
                break

    return received.decode("utf-8", errors="ignore")


def udp_echo(message: str, ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Sends message via UDP and returns the response (if server responds).
    """
    data = message.encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(data, (ip, port))
        try:
            received, _ = s.recvfrom(4096)
        except socket.timeout:
            return ""
    return received.decode("utf-8", errors="ignore")


# --- Tests -----------------------------------------------------------------

def check_server() -> bool:
    print_test("Checking if TUN interface is configured...")
    ok, loss = run_ping(TUN_IP, count=1, timeout_sec=1)
    if ok:
        print_success(f"TUN interface {TUN_IP} is reachable (0% packet loss)")
        return True
    else:
        print_failure(f"TUN interface {TUN_IP} is NOT reachable ({loss}% packet loss)")
        print("Make sure test_tun_echo is running with sudo")
        return False


def test_tcp_echo() -> None:
    print_test(f"Testing TCP echo on port {TCP_PORT}...")
    try:
        resp = tcp_echo(TEST_MESSAGE, TUN_IP, TCP_PORT, timeout=2.0)
    except Exception as e:
        print_failure(f"TCP echo: exception: {e}")
        return

    if resp == TEST_MESSAGE:
        print_success("TCP echo works correctly")
        print_info(f"Sent: '{TEST_MESSAGE}'")
        print_info(f"Received: '{resp}'")
    else:
        print_failure("TCP echo failed")
        print_info(f"Sent: '{TEST_MESSAGE}'")
        print_info(f"Received: '{resp}'")


def test_udp_echo() -> None:
    print_test(f"Testing UDP echo on port {TCP_PORT}...")
    try:
        resp = udp_echo(TEST_MESSAGE, TUN_IP, TCP_PORT, timeout=1.0)
    except Exception as e:
        print_failure(f"UDP echo: exception: {e}")
        return

    if resp == TEST_MESSAGE:
        print_success("UDP echo works correctly")
        print_info(f"Sent: '{TEST_MESSAGE}'")
        print_info(f"Received: '{resp}'")
    else:
        print_failure("UDP echo failed")
        print_info(f"Sent: '{TEST_MESSAGE}'")
        print_info(f"Received: '{resp}'")


def test_icmp_ping() -> None:
    print_test("Testing ICMP ping (4 packets)...")
    ok, loss = run_ping(TUN_IP, count=4, timeout_sec=2)
    if ok:
        print_success("ICMP ping works correctly (0% packet loss)")
        print_info("See system ping output for detailed RTT statistics")
    else:
        print_failure(f"ICMP ping failed ({loss}% packet loss)")


def test_multiple_tcp() -> None:
    print_test("Testing multiple TCP connections...")
    success = 0
    for i in range(1, 6):
        msg = f"Test {i}"
        try:
            resp = tcp_echo(msg, TUN_IP, TCP_PORT, timeout=2.0)
            if resp == msg:
                success += 1
        except Exception:
            pass

    if success == 5:
        print_success("Multiple TCP connections work (5/5 successful)")
    else:
        print_failure(f"Multiple TCP connections failed ({success}/5 successful)")


def test_large_data() -> None:
    print_test("Testing large data transfer (1KB)...")
    large_data = "A" * 1024

    try:
        resp = tcp_echo(large_data, TUN_IP, TCP_PORT, timeout=5.0)
    except Exception as e:
        print_failure(f"Large data transfer: exception: {e}")
        return

    if resp == large_data:
        print_success("Large data transfer works (1KB)")
    else:
        print_failure("Large data transfer failed")
        print_info(f"Sent bytes: {len(large_data)}")
        print_info(f"Received bytes: {len(resp)}")


def _concurrent_worker(msg: str, result_dict: dict, key: str) -> None:
    try:
        resp = tcp_echo(msg, TUN_IP, TCP_PORT, timeout=2.0)
        result_dict[key] = (resp == msg)
    except Exception:
        result_dict[key] = False


def test_concurrent() -> None:
    print_test("Testing concurrent connections (3 parallel)...")
    messages = ["Concurrent 1", "Concurrent 2", "Concurrent 3"]
    result = {}
    threads = []

    for idx, msg in enumerate(messages, start=1):
        key = f"c{idx}"
        t = threading.Thread(target=_concurrent_worker, args=(msg, result, key))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    success = sum(1 for v in result.values() if v)

    if success == 3:
        print_success("Concurrent connections work (3/3 successful)")
    else:
        print_failure(f"Concurrent connections failed ({success}/3 successful)")


# --- Main ------------------------------------------------------------------

def main() -> int:
    print_header("TUN Echo Test Suite (Python, cross-platform)")
    print()
    print_info(f"Target: {TUN_IP}:{TCP_PORT}")
    print_info(f"Test message: '{TEST_MESSAGE}'")
    print()

    if not check_server():
        print()
        print_failure("Cannot reach server. Aborting tests.")
        return 1

    print()
    # Run all tests, even if some fail:
    test_tcp_echo()
    print()

    test_udp_echo()
    print()

    test_icmp_ping()
    print()

    test_multiple_tcp()
    print()

    test_large_data()
    print()

    test_concurrent()
    print()

    print_header("Test Summary")
    total = TESTS_PASSED + TESTS_FAILED
    print(f"Tests passed: {GREEN}{TESTS_PASSED}{NC}")
    print(f"Tests failed: {RED}{TESTS_FAILED}{NC}")
    print(f"Total tests:  {total}")
    print()

    if TESTS_FAILED == 0:
        print_success("All tests passed!")
        return 0
    else:
        print_failure("Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
