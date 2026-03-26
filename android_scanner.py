import subprocess
import re
from datetime import datetime

# Dangerous Android permissions that indicate over-privileged apps
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_CONTACTS':       ('HIGH',     'Read all contacts'),
    'android.permission.WRITE_CONTACTS':      ('HIGH',     'Write contacts'),
    'android.permission.READ_CALL_LOG':       ('CRITICAL', 'Read call history'),
    'android.permission.WRITE_CALL_LOG':      ('CRITICAL', 'Write call history'),
    'android.permission.PROCESS_OUTGOING_CALLS': ('CRITICAL', 'Intercept outgoing calls'),
    'android.permission.READ_SMS':            ('CRITICAL', 'Read SMS messages'),
    'android.permission.RECEIVE_SMS':         ('CRITICAL', 'Receive SMS messages'),
    'android.permission.SEND_SMS':            ('CRITICAL', 'Send SMS messages'),
    'android.permission.RECORD_AUDIO':        ('HIGH',     'Record microphone'),
    'android.permission.CAMERA':              ('HIGH',     'Access camera'),
    'android.permission.ACCESS_FINE_LOCATION':('HIGH',     'Precise GPS location'),
    'android.permission.ACCESS_COARSE_LOCATION': ('MEDIUM','Approximate location'),
    'android.permission.READ_EXTERNAL_STORAGE': ('MEDIUM', 'Read all files'),
    'android.permission.WRITE_EXTERNAL_STORAGE': ('HIGH',  'Write all files'),
    'android.permission.GET_ACCOUNTS':        ('LOW',      'Access all accounts'),
    'android.permission.USE_CREDENTIALS':     ('LOW',      'Use account credentials'),
    'android.permission.MANAGE_ACCOUNTS':     ('LOW',      'Manage all accounts'),
    'android.permission.INTERNET':            ('LOW',      'Internet access'),
    'android.permission.READ_PHONE_STATE':    ('HIGH',     'Read device identifiers'),
    'android.permission.CALL_PHONE':          ('HIGH',     'Make phone calls'),
    'android.permission.BIND_ACCESSIBILITY_SERVICE': ('CRITICAL', 'Full screen reader — spyware indicator'),
    'android.permission.SYSTEM_ALERT_WINDOW': ('HIGH',     'Draw over other apps'),
    'android.permission.DEVICE_ADMIN':        ('CRITICAL', 'Device administrator access'),
}

# Suspicious combinations for UNKNOWN apps only
SUSPICIOUS_COMBINATIONS = [
    ('INTERNET', 'READ_SMS'),
    ('INTERNET', 'RECORD_AUDIO'),
    ('INTERNET', 'READ_CALL_LOG'),
    ('INTERNET', 'BIND_ACCESSIBILITY_SERVICE'),
    ('INTERNET', 'ACCESS_FINE_LOCATION'),
]

# Known legitimate apps — whitelisted from suspicious combination alerts
# Only truly critical unexpected permissions still get flagged
KNOWN_LEGITIMATE_APPS = {
    # Google
    'com.google.android.apps.photos',
    'com.google.android.apps.docs',
    'com.google.android.gm',
    'com.google.android.apps.maps',
    'com.google.android.youtube',
    'com.google.android.apps.meet',
    'com.google.android.apps.tachyon',
    'com.google.android.calendar',
    'com.google.android.contacts',
    'com.google.android.dialer',
    # Microsoft
    'com.microsoft.office.outlook',
    'com.microsoft.teams',
    'com.azure.authenticator',
    'com.microsoft.intune',
    'com.microsoft.windowsintune.companyportal',
    'com.microsoft.office.word',
    'com.microsoft.office.excel',
    # Samsung built-in
    'com.samsung.android.spay',
    'com.samsung.android.oneconnect',
    'com.samsung.android.ardrawing',
    'com.samsung.android.arzone',
    'com.samsung.android.app.watchmanager',
    'com.samsung.android.app.notes',
    'com.samsung.android.app.spage',
    'com.samsung.android.game.gamehome',
    'com.samsung.android.voc',
    'com.sec.android.app.sbrowser',
    'com.sec.android.app.clockpackage',
    'com.sec.android.app.voicenote',
    'com.sec.android.app.kidshome',
    # Social media
    'com.whatsapp',
    'com.instagram.android',
    'com.facebook.katana',
    'com.linkedin.android',
    'com.snapchat.android',
    'com.twitter.android',
    'org.telegram.messenger',
    # Shopping / finance
    'com.amazon.mShop.android.shopping',
    'com.coinbase.android',
    'com.lebara.wallet',
    # Transport
    'com.pal.train',
    'com.uber.driver',
    'com.ubercab',
}

# Truly critical permissions that flag even on known apps
# These should never appear unexpectedly on any app
ALWAYS_FLAG_PERMISSIONS = {
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.SEND_SMS',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.DEVICE_ADMIN',
}


def run_adb(command):
    """Run an ADB command and return output."""
    try:
        result = subprocess.run(
            f'adb {command}',
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ''
    except Exception as e:
        print(f"  ADB error: {e}")
        return ''


def get_device_info():
    """Get basic device information from real device via ADB."""
    model = run_adb('shell getprop ro.product.model')
    android_version = run_adb('shell getprop ro.build.version.release')
    security_patch = run_adb('shell getprop ro.build.version.security_patch')
    serial = run_adb('get-serialno')
    return {
        'model': model,
        'android_version': android_version,
        'security_patch': security_patch,
        'serial': serial
    }


def get_installed_packages():
    """Get list of all installed third-party apps from real device."""
    output = run_adb('shell pm list packages -3')
    packages = []
    for line in output.splitlines():
        if line.startswith('package:'):
            packages.append(line.replace('package:', '').strip())
    return packages


def get_app_permissions(package):
    """Get real granted permissions for a specific app."""
    output = run_adb(f'shell dumpsys package {package}')
    granted_permissions = []
    for line in output.splitlines():
        if 'granted=true' in line:
            match = re.search(r'(android\.permission\.\w+)', line)
            if match:
                granted_permissions.append(match.group(1))
    return granted_permissions


def check_suspicious_combinations(package, permissions):
    """
    Check for suspicious permission combinations.
    Known apps still get flagged for LotX-specific combinations
    because trusted apps are exactly what LotX attackers abuse.
    Unknown apps get flagged for all suspicious combinations.
    """
    perm_short = [p.replace('android.permission.', '') for p in permissions]
    triggered = []

    # LotX combinations — flag even known apps
    # These are the exact patterns Cloudflare documented
    lotx_combinations = [
        ('INTERNET', 'RECORD_AUDIO'),
        ('INTERNET', 'READ_SMS'),
        ('INTERNET', 'READ_CALL_LOG'),
        ('INTERNET', 'BIND_ACCESSIBILITY_SERVICE'),
    ]

    # Additional combinations — unknown apps only
    unknown_only_combinations = [
        ('INTERNET', 'ACCESS_FINE_LOCATION'),
    ]

    for combo in lotx_combinations:
        if all(c in perm_short for c in combo):
            if package in KNOWN_LEGITIMATE_APPS:
                triggered.append({
                    'combo': f"{combo[0]} + {combo[1]}",
                    'type': 'LOTX_KNOWN_APP',
                    'note': 'Known app — monitor for abnormal usage'
                })
            else:
                triggered.append({
                    'combo': f"{combo[0]} + {combo[1]}",
                    'type': 'LOTX_UNKNOWN_APP',
                    'note': 'Unknown app — high suspicion'
                })

    if package not in KNOWN_LEGITIMATE_APPS:
        for combo in unknown_only_combinations:
            if all(c in perm_short for c in combo):
                triggered.append({
                    'combo': f"{combo[0]} + {combo[1]}",
                    'type': 'UNKNOWN_APP',
                    'note': 'Unknown app with location access'
                })

    return triggered


def get_active_connections():
    """
    Get active network connections from the real Android device.
    Reads directly from /proc/net/tcp via ADB.
    """
    connections = []

    # IPv4 connections
    output = run_adb('shell cat /proc/net/tcp')
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            remote_hex = parts[2]
            state = parts[3]
            if state != '01':
                continue
            remote_addr, remote_port_hex = remote_hex.split(':')
            addr_int = int(remote_addr, 16)
            ip = '.'.join([
                str((addr_int >> i) & 0xFF)
                for i in [0, 8, 16, 24]
            ])
            port = int(remote_port_hex, 16)
            if ip != '0.0.0.0' and not ip.startswith('127.'):
                connections.append({'remote_ip': ip, 'remote_port': port})
        except Exception:
            continue

    return connections


def scan_android(tor_nodes=None):
    """
    Full Android device scan using real ADB data.
    No hardcoded values — all data from actual device.
    """
    print("  Scanning Android device via ADB...")

    device_info = get_device_info()
    print(f"  Device: {device_info['model']} (Android {device_info['android_version']})")
    print(f"  Security patch: {device_info['security_patch']}")

    findings = []
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    # Check security patch age
    try:
        patch_date = datetime.strptime(device_info['security_patch'], '%Y-%m-%d')
        days_old = (datetime.now() - patch_date).days
        if days_old > 90:
            findings.append({
                'type': 'OUTDATED_SECURITY_PATCH',
                'risk': 'HIGH',
                'finding': f"Security patch is {days_old} days old (last: {device_info['security_patch']})",
                'remediation': 'Update Android security patch immediately'
            })
    except Exception:
        pass

    # Scan installed apps
    print("  Scanning installed apps for dangerous permissions...")
    packages = get_installed_packages()
    print(f"  Found {len(packages)} third-party apps")

    for package in packages:
        permissions = get_app_permissions(package)
        is_known = package in KNOWN_LEGITIMATE_APPS

        # Check dangerous permissions
        dangerous_found = []
        highest_risk = 'LOW'
        always_flag = []

        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                risk, description = DANGEROUS_PERMISSIONS[perm]
                dangerous_found.append({
                    'permission': perm,
                    'risk': risk,
                    'description': description
                })
                if risk_order[risk] < risk_order[highest_risk]:
                    highest_risk = risk
            # Always flag these regardless of whitelist
            if perm in ALWAYS_FLAG_PERMISSIONS:
                always_flag.append(perm)

        # Check suspicious combinations (unknown apps only)
        suspicious = check_suspicious_combinations(package, permissions)

        if suspicious:
            for s in suspicious:
                if s['type'] == 'LOTX_KNOWN_APP':
                    findings.append({
                        'type': 'LOTX_PATTERN_KNOWN_APP',
                        'risk': 'HIGH',
                        'package': package,
                        'finding': f"{package} has LotX pattern: {s['combo']} — {s['note']}",
                        'permissions': dangerous_found,
                        'remediation': f'Monitor {package} for unusual API calls or data exfiltration'
                    })
                else:
                    findings.append({
                        'type': 'SUSPICIOUS_PERMISSION_COMBO',
                        'risk': 'CRITICAL',
                        'package': package,
                        'finding': f"Unknown app {package} has suspicious combination: {s['combo']}",
                        'permissions': dangerous_found,
                        'remediation': f'Review and consider removing {package}'
                    })
        elif always_flag:
            findings.append({
                'type': 'ALWAYS_FLAG_PERMISSION',
                'risk': 'CRITICAL',
                'package': package,
                'finding': f"{package} has high-risk permission: {always_flag}",
                'permissions': dangerous_found,
                'remediation': f'Verify {package} legitimately requires {always_flag}'
            })
        elif not is_known and highest_risk in ('CRITICAL', 'HIGH'):
            findings.append({
                'type': 'DANGEROUS_PERMISSIONS',
                'risk': highest_risk,
                'package': package,
                'finding': f"Unknown app {package} has {len(dangerous_found)} dangerous permission(s)",
                'permissions': dangerous_found,
                'remediation': f'Review permissions for {package}'
            })

    # Check network connections against Tor nodes
    if tor_nodes:
        print("  Checking Android network connections against Tor exit nodes...")
        connections = get_active_connections()
        print(f"  Active connections on device: {len(connections)}")
        for conn in connections:
            if conn['remote_ip'] in tor_nodes:
                findings.append({
                    'type': 'TOR_CONNECTION',
                    'risk': 'CRITICAL',
                    'finding': f"Device connected to Tor exit node: {conn['remote_ip']}:{conn['remote_port']}",
                    'remediation': 'Isolate device immediately — possible C2 channel active'
                })

    return findings, device_info


def print_android_report(findings, device_info):
    """Print Android scan report."""
    print("\n" + "="*60)
    print("  LotX Detector — Android Device Scan")
    print(f"  {device_info['model']} | Android {device_info['android_version']}")
    print("="*60)

    critical = [f for f in findings if f['risk'] == 'CRITICAL']
    high = [f for f in findings if f['risk'] == 'HIGH']

    print(f"\n  Total findings: {len(findings)}")
    print(f"  Critical:       {len(critical)}")
    print(f"  High:           {len(high)}")
    print()

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_findings = sorted(findings, key=lambda x: risk_order[x['risk']])

    for f in sorted_findings:
        if f['risk'] in ('CRITICAL', 'HIGH', 'MEDIUM'):
            print(f"  [{f['risk']}] {f['finding']}")
            if 'permissions' in f:
                for p in f['permissions'][:3]:
                    if p['risk'] in ('CRITICAL', 'HIGH'):
                        print(f"    ⚠ {p['permission']}")
                        print(f"       {p['description']}")
            print(f"    ⚡ {f['remediation']}")
            print()

    print("="*60 + "\n")


if __name__ == "__main__":
    from tor_monitor import fetch_tor_exit_nodes
    tor_nodes = fetch_tor_exit_nodes()
    findings, device_info = scan_android(tor_nodes)
    print_android_report(findings, device_info)