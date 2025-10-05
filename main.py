#!/usr/bin/env python3
"""
Secure Network Port Scanner
Security-first implementation with proper input validation and rate limiting
"""

import socket
import threading
import argparse
import ipaddress
import time
import logging
from datetime import datetime
from typing import List, Tuple

# Configure secure logging (no sensitive data logged)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurePortScanner:
    def __init__(self, max_threads: int = 100, rate_limit: float = 0.01):
        self.max_threads = max_threads
        self.rate_limit = rate_limit  # Delay between scans
        self.results = []
        self.lock = threading.Lock()

    def validate_host(self, host: str) -> bool:
        """Validate target host - prevent scanning of internal/private networks"""
        try:
            ip = ipaddress.ip_address(host)

            # Block RFC 1918 private networks (unless explicitly allowed)
            if ip.is_private:
                logger.warning(f"Attempted scan of private IP: {ip}")
                return False

            # Block localhost
            if ip.is_loopback:
                logger.warning(f"Attempted scan of loopback: {ip}")
                return False

            # Block multicast
            if ip.is_multicast:
                logger.warning(f"Attempted scan of multicast: {ip}")
                return False

            return True

        except ValueError:
            # Try to resolve hostname
            try:
                resolved_ip = socket.gethostbyname(host)
                return self.validate_host(resolved_ip)
            except socket.gaierror:
                logger.error(f"Cannot resolve hostname: {host}")
                return False

    def validate_port_range(self, start_port: int, end_port: int) -> bool:
        """Validate port range to prevent abuse"""
        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            logger.error("Port range must be between 1-65535")
            return False

        if end_port < start_port:
            logger.error("End port must be greater than start port")
            return False

        port_range = end_port - start_port + 1
        if port_range > 10000:  # Limit scan range
            logger.error(f"Port range too large: {port_range} ports")
            return False

        return True

    def scan_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Securely scan a single port with proper error handling"""
        try:
            # Rate limiting to prevent overwhelming target
            time.sleep(self.rate_limit)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            return result == 0

        except Exception as e:
            # Log error but don't expose sensitive details
            logger.debug(f"Port scan error on {port}: {type(e).__name__}")
            return False

    def scan_worker(self, host: str, port: int):
        """Worker thread for port scanning"""
        if self.scan_port(host, port):
            with self.lock:
                self.results.append(port)
                logger.info(f"Open port found: {port}")

    def scan_ports(self, host: str, start_port: int, end_port: int) -> List[int]:
        """Main scanning function with security controls"""

        # Input validation
        if not self.validate_host(host):
            raise ValueError("Invalid or restricted target host")

        if not self.validate_port_range(start_port, end_port):
            raise ValueError("Invalid port range")

        logger.info(f"Starting secure port scan of {host}")
        logger.info(f"Port range: {start_port}-{end_port}")

        self.results = []
        threads = []

        for port in range(start_port, end_port + 1):
            # Limit concurrent threads
            while len(threads) >= self.max_threads:
                threads = [t for t in threads if t.is_alive()]
                time.sleep(0.01)

            thread = threading.Thread(target=self.scan_worker, args=(host, port))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        logger.info(f"Scan complete. Found {len(self.results)} open ports")
        return sorted(self.results)

def main():
    parser = argparse.ArgumentParser(
        description='Secure Network Port Scanner',
        epilogue='WARNING: Only scan systems you own or have permission to test'
    )
    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('-s', '--start', type=int, default=1, help='Start port (1-65535)')
    parser.add_argument('-e', '--end', type=int, default=1000, help='End port (1-65535)')
    parser.add_argument('-t', '--timeout', type=float, default=2.0, help='Connection timeout')
    parser.add_argument('--threads', type=int, default=100, help='Max concurrent threads')
    parser.add_argument('--rate-limit', type=float, default=0.01, help='Delay between scans')

    args = parser.parse_args()

    # Additional security warnings
    print("🛡️  Secure Port Scanner")
    print("⚠️  LEGAL WARNING: Only scan systems you own or have explicit permission to test")
    print("⚠️  Unauthorized port scanning may violate laws and policies")

    try:
        scanner = SecurePortScanner(
            max_threads=args.threads,
            rate_limit=args.rate_limit
        )

        open_ports = scanner.scan_ports(args.host, args.start, args.end)

        print(f"\n📊 Scan Results:")
        print(f"Target: {args.host}")
        print(f"Open ports: {len(open_ports)}")

        if open_ports:
            print(f"Ports: {', '.join(map(str, open_ports))}")
        else:
            print("No open ports found in specified range")

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Scan failed: {type(e).__name__}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
