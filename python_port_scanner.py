import socket
import threading
import argparse
import sys
from datetime import datetime
from queue import Queue

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    119: "NNTP", 123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 194: "IRC", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    27017: "MongoDB"
}

print_lock = threading.Lock()
open_ports = []

def get_service(port):
    """Return service name for a port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def grab_banner(sock):
    """Try to grab a service banner."""
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner.split("\n")[0][:60] if banner else None
    except:
        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner.split("\n")[0][:60] if banner else None
        except:
            return None

def scan_port(host, port, timeout=1.0):
    """Scan a single port. Returns (port, is_open, service, banner)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = get_service(port)
            banner = grab_banner(sock)
            sock.close()
            return (port, True, service, banner)
        sock.close()
    except socket.error:
        pass
    return (port, False, None, None)

def worker(host, queue, timeout):
    """Thread worker: pull ports from queue and scan them."""
    while not queue.empty():
        port = queue.get()
        port_num, is_open, service, banner = scan_port(host, port, timeout)
        if is_open:
            with print_lock:
                banner_str = f"  [{banner}]" if banner else ""
                print(f"  [+] Port {port_num:<6} OPEN   {service:<15}{banner_str}")
                open_ports.append((port_num, service, banner))
        queue.task_done()

def resolve_host(host):
    """Resolve hostname to IP."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP Port Scanner with Service Detection",
        epilog="Example: python port_scanner.py scanme.nmap.org 1 1024 --threads 100"
    )
    parser.add_argument("host", help="Target host (IP or hostname)")
    parser.add_argument("start_port", nargs="?", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("end_port", nargs="?", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    args = parser.parse_args()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        print("[!] Invalid port range. Use 1-65535.")
        sys.exit(1)

    ip = resolve_host(args.host)
    total_ports = args.end_port - args.start_port + 1

    print("=" * 60)
    print(f"  Port Scanner by Nicolas-Costin Tanasache")
    print("=" * 60)
    print(f"  Target   : {args.host} ({ip})")
    print(f"  Range    : {args.start_port} - {args.end_port} ({total_ports} ports)")
    print(f"  Threads  : {args.threads}")
    print(f"  Timeout  : {args.timeout}s")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    queue = Queue()
    for port in range(args.start_port, args.end_port + 1):
        queue.put(port)

    start_time = datetime.now()

    num_threads = min(args.threads, total_ports)
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(ip, queue, args.timeout))
        t.daemon = True
        t.start()

    queue.join()

    duration = (datetime.now() - start_time).total_seconds()

    print()
    print("=" * 60)
    print(f"  Scan complete in {duration:.2f}s")
    print(f"  Open ports found: {len(open_ports)}")
    
    if open_ports:
        print()
        print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'-'*50}")
        for port, service, banner in sorted(open_ports, key=lambda x: x[0]):
            banner_str = banner if banner else "-"
            print(f"  {port:<8} {service:<15} {banner_str[:40]}")
    print("=" * 60)

if __name__ == "__main__":
    main()