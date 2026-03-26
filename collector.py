import json
import os
from datetime import datetime, timezone

RESULTS_FILE = 'results/findings.json'


def ensure_results_dir():
    """Create results directory if it doesn't exist."""
    os.makedirs('results', exist_ok=True)


def load_findings():
    """Load all existing findings."""
    ensure_results_dir()
    if not os.path.exists(RESULTS_FILE):
        return {}
    try:
        with open(RESULTS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_finding(device_id, module, findings):
    """
    Save findings from any device to central store.
    device_id = unique identifier for the scanning device
    module = which scanner produced this finding
    findings = list of findings from that scanner
    """
    ensure_results_dir()
    all_findings = load_findings()

    if device_id not in all_findings:
        all_findings[device_id] = {}

    all_findings[device_id][module] = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'findings': findings,
        'count': len(findings) if isinstance(findings, list) else 0
    }

    with open(RESULTS_FILE, 'w') as f:
        json.dump(all_findings, f, indent=2)


def get_device_id():
    """
    Generate unique ID for this device.
    Uses hostname + platform so each device has its own identity.
    """
    import socket
    import platform
    hostname = socket.gethostname()
    system = platform.system()
    return f"{hostname}_{system}"


def print_aggregated_report():
    """Print findings from all devices in one unified report."""
    all_findings = load_findings()

    print("\n" + "="*60)
    print("  LotX Detector — Aggregated Multi-Device Report")
    print("="*60)

    if not all_findings:
        print("\n  No findings from any device yet.\n")
        return

    total_critical = 0
    total_high = 0

    for device_id, modules in all_findings.items():
        print(f"\n  Device: {device_id}")
        print("  " + "-"*40)
        for module, data in modules.items():
            count = data['count']
            timestamp = data['timestamp']
            findings = data['findings']
            status = "⚠ FINDINGS" if count > 0 else "✓ Clean"
            print(f"  [{status}] {module} — {count} finding(s)")
            print(f"  Last scan: {timestamp}")
            if findings and isinstance(findings, list):
                for f in findings[:2]:
                    if isinstance(f, dict):
                        msg = (
                            f.get('finding') or
                            f.get('event') or
                            f.get('scope') or
                            str(f)
                        )
                        risk = f.get('risk', '')
                        print(f"    → [{risk}] {msg[:80]}")
                        if risk == 'CRITICAL':
                            total_critical += 1
                        elif risk == 'HIGH':
                            total_high += 1

    print(f"\n  Total across all devices:")
    print(f"  Critical: {total_critical} | High: {total_high}")
    print("\n" + "="*60 + "\n")