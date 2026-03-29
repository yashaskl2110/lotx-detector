import psutil
import json
import os
from datetime import datetime, timezone

BASELINE_FILE = 'results/baseline.json'

# Known legitimate processes — suppress localhost connection alerts
# These are normal system/gaming processes that connect to localhost
KNOWN_LOCAL_PROCESSES = {
    'ArmouryCrate.UserSessionHelper.exe',
    'ArmouryCrate.Service.exe',
    'AuraWallpaperService.exe',
    'GameBar.exe',
    'MpDefenderCoreService.exe',
    'NVIDIA Web Helper.exe',
    'nvcontainer.exe',
}

# High risk ports — unusual to see outbound connections to these
HIGH_RISK_PORTS = {
    4444, 4445, 4446,
    1337, 31337,
    6666, 6667, 6668,
    9001, 9030,
    8080, 8443,
    2222,
    5555,
}


def get_live_connections():
    """
    Read all active network connections from this machine right now.
    Uses psutil to read directly from the OS network stack.
    Returns real IPs and ports — no hardcoded values.
    """
    connections = []
    seen = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                process_name = 'unknown'
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                except Exception:
                    pass

                # Deduplicate same IP+process combinations
                key = (conn.raddr.ip, conn.raddr.port, process_name)
                if key in seen:
                    continue
                seen.add(key)

                connections.append({
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'process': process_name,
                    'pid': conn.pid
                })
    except Exception as e:
        print(f"  Error reading connections: {e}")

    return connections


def build_baseline(connections):
    """
    Build a baseline profile from current connections.
    Records which IPs, ports, and processes are normal.
    """
    baseline = {
        'created': datetime.now(timezone.utc).isoformat(),
        'total_connections': len(connections),
        'known_ips': {},
        'known_processes': {},
        'known_ports': []
    }

    port_set = set()
    for conn in connections:
        ip = conn['remote_ip']
        process = conn['process']
        port = conn['remote_port']

        if ip not in baseline['known_ips']:
            baseline['known_ips'][ip] = {
                'count': 0,
                'processes': [],
                'ports': []
            }
        baseline['known_ips'][ip]['count'] += 1
        if process not in baseline['known_ips'][ip]['processes']:
            baseline['known_ips'][ip]['processes'].append(process)
        if port not in baseline['known_ips'][ip]['ports']:
            baseline['known_ips'][ip]['ports'].append(port)

        if process not in baseline['known_processes']:
            baseline['known_processes'][process] = 0
        baseline['known_processes'][process] += 1

        port_set.add(port)

    baseline['known_ports'] = list(port_set)
    return baseline


def load_baseline():
    """Load saved baseline from disk."""
    if not os.path.exists(BASELINE_FILE):
        return None
    try:
        with open(BASELINE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def save_baseline(baseline):
    """Save baseline to disk."""
    os.makedirs('results', exist_ok=True)
    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=2)


def compare_against_baseline(current_connections, baseline):
    """
    Compare current live connections against saved baseline.
    Flags new IPs, process hijacks, high-risk ports, and spikes.
    All data from real network stack — no hardcoded values.
    """
    findings = []
    seen_findings = set()
    known_ips = set(baseline.get('known_ips', {}).keys())
    baseline_count = baseline.get('total_connections', 0)

    for conn in current_connections:
        ip = conn['remote_ip']
        process = conn['process']
        port = conn['remote_port']

        # Skip whitelisted local processes
        if process in KNOWN_LOCAL_PROCESSES and ip == '127.0.0.1':
            continue

        # New IP never seen in baseline
        if ip not in known_ips:
            key = f"NEW_IP_{ip}_{process}"
            if key not in seen_findings:
                seen_findings.add(key)
                findings.append({
                    'type': 'NEW_IP',
                    'risk': 'MEDIUM',
                    'finding': f"New IP not in baseline: {ip}:{port} via {process}",
                    'remediation': f"Verify {process} legitimately connects to {ip}"
                })

        # Known IP now used by new process — possible hijack
        elif ip in baseline.get('known_ips', {}):
            known_procs_for_ip = baseline['known_ips'][ip].get('processes', [])
            if (process not in known_procs_for_ip
                    and process != 'unknown'
                    and process not in KNOWN_LOCAL_PROCESSES):
                key = f"NEW_PROC_{ip}_{process}"
                if key not in seen_findings:
                    seen_findings.add(key)
                    findings.append({
                        'type': 'NEW_PROCESS_FOR_IP',
                        'risk': 'HIGH',
                        'finding': f"New process {process} connecting to known IP {ip} — possible process hijack",
                        'remediation': f"Verify {process} should be connecting to {ip}"
                    })

        # High risk port
        if port in HIGH_RISK_PORTS:
            key = f"HIGH_PORT_{ip}_{port}"
            if key not in seen_findings:
                seen_findings.add(key)
                findings.append({
                    'type': 'HIGH_RISK_PORT',
                    'risk': 'CRITICAL',
                    'finding': f"Connection to high-risk port {port} at {ip} via {process}",
                    'remediation': f"Investigate {process} connection to port {port} immediately"
                })

    # Spike in connection count
    if baseline_count > 0:
        spike_ratio = len(current_connections) / baseline_count
        if spike_ratio > 2.0:
            findings.append({
                'type': 'CONNECTION_SPIKE',
                'risk': 'HIGH',
                'finding': f"Connection spike: {len(current_connections)} vs baseline {baseline_count} ({spike_ratio:.1f}x)",
                'remediation': 'Investigate unusual network activity'
            })

    return findings


def run_baseline_scan():
    """
    Main baseline profiling function.
    First run: establishes baseline.
    Subsequent runs: compares against baseline.
    """
    current_connections = get_live_connections()
    baseline = load_baseline()

    if not baseline:
        print(f"  No baseline found — establishing from {len(current_connections)} live connections...")
        new_baseline = build_baseline(current_connections)
        save_baseline(new_baseline)
        print(f"  Baseline saved. Future scans will compare against this.")
        print(f"  Known IPs: {len(new_baseline['known_ips'])}")
        print(f"  Known processes: {len(new_baseline['known_processes'])}")
        return [], True
    else:
        baseline_age = baseline.get('created', 'unknown')
        print(f"  Comparing against baseline from {baseline_age}")
        print(f"  Live connections: {len(current_connections)}")
        findings = compare_against_baseline(current_connections, baseline)
        return findings, False


def print_baseline_report(findings, baseline_created=False):
    """Print network baseline report."""
    print("\n" + "="*60)
    print("  LotX Detector — Network Baseline Monitor")
    print("  Live connection deviation analysis")
    print("="*60)

    if baseline_created:
        print("\n  Baseline established from current network state.")
        print("  Run again to detect deviations.\n")
        print("="*60 + "\n")
        return

    if not findings:
        print("\n  No deviations from baseline detected.")
        print("  Network activity within normal parameters.\n")
    else:
        critical = [f for f in findings if f['risk'] == 'CRITICAL']
        high = [f for f in findings if f['risk'] == 'HIGH']
        medium = [f for f in findings if f['risk'] == 'MEDIUM']

        print(f"\n  Deviations detected: {len(findings)}")
        print(f"  Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)}\n")

        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(findings, key=lambda x: risk_order[x['risk']])

        for f in sorted_findings:
            print(f"  [{f['risk']}] {f['finding']}")
            print(f"    ⚡ {f['remediation']}")
            print()

    print("="*60 + "\n")


if __name__ == "__main__":
    print("\n  Running network baseline scan...")
    findings, baseline_created = run_baseline_scan()
    print_baseline_report(findings, baseline_created)