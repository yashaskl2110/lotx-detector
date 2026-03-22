from google_calendar import fetch_events
from detector import scan_events, print_report

def main():
    print("\n" + "="*60)
    print("  LotX Detector — Live Calendar Scanner")
    print("  Cloudflare 2026 Threat Report — C2 Detection")
    print("="*60)

    # Fetch real events from Google Calendar
    events = fetch_events(max_results=50)

    if not events:
        print("  No events to scan.")
        return

    # Run detection engine
    results = scan_events(events)

    # Print report
    print_report(results)

if __name__ == "__main__":
    main()