import socket
import platform
from google_calendar import fetch_events
from detector import scan_events, print_report, check_volume_spike, print_spike_report
from tor_monitor import TOR_EXIT_CACHE,run_tor_scan, print_tor_report, fetch_tor_exit_nodes
from oauth_scope_checker import get_real_scopes, assess_real_scopes, print_scope_report
from github_auditor import get_github_token_scopes, get_oauth_apps, assess_github_risk, print_github_report
from android_scanner import scan_android, print_android_report
from collector import save_finding, get_device_id, print_aggregated_report


def check_adb_connected():
    """Check if Android device is connected via ADB."""
    import subprocess
    result = subprocess.run(
        'adb devices',
        shell=True,
        capture_output=True,
        text=True
    )
    lines = [l for l in result.stdout.splitlines() if 'device' in l and 'List' not in l]
    return len(lines) > 0


def main():
    device_id = get_device_id()

    print("\n" + "="*60)
    print("  LotX Detector — Full Security Scan")
    print(f"  Device: {device_id}")
    print("  Cloudflare 2026 Threat Report — C2 Detection")
    print("="*60)

    # Module 1 — Tor exit node scan
    print("\n  [1/5] Running Tor exit node scan...")
    tor_findings = run_tor_scan()
    tor_nodes = set()
    tor_nodes = TOR_EXIT_CACHE
    print_tor_report(tor_findings)
    save_finding(device_id, 'tor_monitor', tor_findings)

    # Module 2 — Google OAuth scope audit
    print("\n  [2/5] Running Google OAuth scope audit...")
    token_data = get_real_scopes()
    if token_data:
        findings, overall_risk = assess_real_scopes(token_data)
        print_scope_report(token_data, findings, overall_risk)
        save_finding(device_id, 'google_oauth', findings)

    # Module 3 — GitHub OAuth audit
    print("\n  [3/5] Running GitHub OAuth audit...")
    github_data = get_github_token_scopes()
    oauth_apps = get_oauth_apps()
    if github_data:
        scope_findings, app_findings, overall_risk = assess_github_risk(
            github_data, oauth_apps
        )
        print_github_report(
            github_data, scope_findings, app_findings, overall_risk
        )
        save_finding(device_id, 'github_oauth', scope_findings)

    # Module 4 — Calendar C2 scan
    print("\n  [4/5] Running Calendar C2 scan...")
    events = fetch_events(max_results=50)
    if events:
        results = scan_events(events)
        print_report(results)
        spikes = check_volume_spike(events)
        print_spike_report(spikes)
        critical = [r for r in results if r['risk'] in ('CRITICAL', 'HIGH')]
        save_finding(device_id, 'calendar_c2', critical)

    # Module 5 — Android device scan
    print("\n  [5/5] Running Android device scan...")
    if check_adb_connected():
        android_findings, device_info = scan_android(tor_nodes)
        print_android_report(android_findings, device_info)
        save_finding(device_id, 'android_scan', android_findings)
    else:
        print("  No Android device connected — skipping.")
        print("  Connect device via USB and enable USB debugging to scan.")

    # Aggregated report from all devices
    print_aggregated_report()


if __name__ == "__main__":
    main()