import psutil
import requests
import socket
from datetime import datetime

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_EXIT_CACHE = set()
LAST_FETCH = None


def fetch_tor_exit_nodes():
    """
    Download live Tor exit node list from Tor Project.
    Updated every 30 minutes by Tor Project servers.
    This is real data — not hardcoded.
    """
    global TOR_EXIT_CACHE, LAST_FETCH

    print("  Fetching live Tor exit node list...")
    try:
        response = requests.get(TOR_EXIT_LIST_URL, timeout=10)
        if response.status_code == 200:
            nodes = set(
                line.strip()
                for line in response.text.splitlines()
                if line.strip() and not line.startswith('#')
            )
            TOR_EXIT_CACHE = nodes
            LAST_FETCH = datetime.now()
            print(f"  Loaded {len(nodes)} known Tor exit nodes.")
            return nodes
        else:
            print(f"  Failed to fetch Tor list: HTTP {response.status_code}")
            return set()
    except Exception as e:
        print(f"  Error fetching Tor exit nodes: {e}")
        return set()


def get_active_connections():
    """
    Get all active outbound network connections from this machine.
    Uses psutil to read live network state — real data from
    your actual machine's network stack.
    """
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else None

                # Get process name if available
                process_name = 'unknown'
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                except Exception:
                    pass

                connections.append({
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'local_port': local_port,
                    'process': process_name,
                    'pid': conn.pid
                })
    except Exception as e:
        print(f"  Error reading network connections: {e}")

    return connections


def check_tor_connections(connections, tor_nodes):
    """
    Cross-reference active connections against Tor exit node list.
    Any match = a process on this machine is communicating
    with a known Tor exit node.
    """
    findings = []

    for conn in connections:
        if conn['remote_ip'] in tor_nodes:
            findings.append({
                'remote_ip': conn['remote_ip'],
                'remote_port': conn['remote_port'],
                'process': conn['process'],
                'pid': conn['pid'],
                'severity': 'CRITICAL',
                'finding': f"Active connection to Tor exit node {conn['remote_ip']}:{conn['remote_port']}",
                'process_risk': assess_process_risk(conn['process'])
            })

    return findings


def assess_process_risk(process_name):
    """
    Assess how suspicious it is for THIS specific process
    to be connecting to Tor.
    Trusted apps connecting to Tor = LotX C2 pattern.
    """
    # These processes should NEVER connect to Tor
    # If they do it's a strong LotX indicator
    high_risk_processes = [
        'chrome', 'firefox', 'safari', 'msedge',  # browsers
        'python', 'python3', 'pythonw',             # scripts
        'node', 'nodejs',                           # JS runtimes
        'curl', 'wget',                             # download tools
        'powershell', 'cmd',                        # shells
        'outlook', 'thunderbird',                   # email clients
        'slack', 'teams', 'zoom',                   # comms apps
        'dropbox', 'onedrive', 'googledrivefs',     # cloud storage
    ]

    process_lower = process_name.lower()
    for risky in high_risk_processes:
        if risky in process_lower:
            return f"HIGH RISK — {process_name} is a trusted app connecting to Tor (LotX indicator)"

    return f"UNKNOWN process {process_name} connecting to Tor"


def run_tor_scan():
    """
    Full Tor exit node scan — fetch live list, check connections,
    return findings.
    """
    # Fetch live Tor exit nodes
    tor_nodes = fetch_tor_exit_nodes()

    if not tor_nodes:
        print("  Could not load Tor exit node list — scan aborted.")
        return []

    # Get active connections from this machine
    connections = get_active_connections()
    print(f"  Active network connections: {len(connections)}")

    # Cross-reference
    findings = check_tor_connections(connections, tor_nodes)

    return findings


def print_tor_report(findings):
    """Print Tor connection findings."""
    print("\n" + "="*60)
    print("  LotX Detector — Tor Exit Node Monitor")
    print("  Live network connection analysis")
    print("="*60)

    if not findings:
        print("\n  No connections to Tor exit nodes detected.")
        print("  Network traffic within normal parameters.\n")
    else:
        print(f"\n  ⚠  {len(findings)} Tor connection(s) detected:\n")
        for f in findings:
            print(f"  [CRITICAL] {f['process']} (PID {f['pid']})")
            print(f"  → {f['finding']}")
            print(f"  → {f['process_risk']}")
            print(f"  Cloudflare fix:")
            print(f"    ⚡ Block via Magic Firewall — IP {f['remote_ip']}")
            print(f"    ⚡ Add to Gateway DNS blocklist immediately")
            print(f"    ⚡ Isolate endpoint via Cloudflare Zero Trust")
            print()

    print("="*60 + "\n")


if __name__ == "__main__":
    findings = run_tor_scan()
    print_tor_report(findings)