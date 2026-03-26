import json
import os
import time
from datetime import datetime, timezone
from google_calendar import fetch_events
from detector import scan_events

RESULTS_FILE = 'previous_results.json'


def load_previous_results():
    """Load results from last scan."""
    if not os.path.exists(RESULTS_FILE):
        return {}
    try:
        with open(RESULTS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_results(results):
    """Save current scan results for comparison next run."""
    data = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'findings': {
            r['event']: {
                'risk': r['risk'],
                'flags': r['flags'],
                'entropy': r['entropy']
            }
            for r in results
            if r['risk'] != 'LOW'
        }
    }
    with open(RESULTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    return data


def find_new_findings(current_results, previous_data):
    """
    Compare current scan against previous results.
    Only return findings that are NEW since last scan.
    This is what turns a point-in-time tool into a monitor.
    """
    previous_findings = previous_data.get('findings', {})
    new_findings = []

    for result in current_results:
        if result['risk'] == 'LOW':
            continue
        event_name = result['event']
        if event_name not in previous_findings:
            result['status'] = 'NEW'
            new_findings.append(result)
        elif previous_findings[event_name]['risk'] != result['risk']:
            result['status'] = f"ESCALATED from {previous_findings[event_name]['risk']}"
            new_findings.append(result)

    return new_findings


def print_monitor_report(new_findings, scan_count, last_scan):
    """Print monitoring report showing only new findings."""
    print("\n" + "="*60)
    print("  LotX Detector — Continuous Monitor")
    print(f"  Scan #{scan_count} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if last_scan:
        print(f"  Previous scan: {last_scan}")
    print("="*60)

    if not new_findings:
        print("\n  No new threats detected since last scan.")
        print("  Calendar activity within normal parameters.\n")
    else:
        print(f"\n  ⚠  {len(new_findings)} NEW finding(s) since last scan:\n")
        for r in new_findings:
            status = r.get('status', 'NEW')
            print(f"  [{r['risk']}] {r['event']} — {status}")
            print(f"  Entropy: {r['entropy']} | Flags: {len(r['flags'])}")
            for e in r['evidence']:
                print(f"    → {e}")
            if r.get('remediation'):
                for rem in r['remediation']:
                    print(f"    ⚡ {rem}")
            print()

    print("="*60)
    print(f"  Next scan in 24 hours.")
    print("="*60 + "\n")


def run_monitor(interval_hours=24, max_scans=None):
    """
    Main monitoring loop.
    Runs every interval_hours, alerts only on new findings.
    """
    scan_count = 0

    print("\n" + "="*60)
    print("  LotX Detector — Starting Continuous Monitor")
    print(f"  Scan interval: every {interval_hours} hours")
    print(f"  Monitoring Google Calendar for C2 indicators")
    print("="*60 + "\n")

    while True:
        scan_count += 1

        # Load previous results
        previous_data = load_previous_results()
        last_scan = previous_data.get('timestamp', 'First scan')

        # Fetch and scan
        print(f"  Running scan #{scan_count}...")
        events = fetch_events(max_results=50)

        if events:
            results = scan_events(events)

            # Find only NEW findings
            new_findings = find_new_findings(results, previous_data)

            # Save current results as baseline for next scan
            save_results(results)

            # Report
            print_monitor_report(new_findings, scan_count, last_scan)
        else:
            print("  No events fetched — skipping comparison.\n")

        # Stop if max_scans reached (for testing)
        if max_scans and scan_count >= max_scans:
            print("  Max scans reached — stopping monitor.")
            break

        # Wait for next scan
        print(f"  Sleeping {interval_hours} hours until next scan...")
        time.sleep(interval_hours * 3600)


if __name__ == "__main__":
    import sys

    # Pass 'test' argument to run once immediately without waiting
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        run_monitor(interval_hours=24, max_scans=1)
    else:
        run_monitor(interval_hours=24)