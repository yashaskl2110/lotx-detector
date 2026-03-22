import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from datetime import datetime, timezone

# Only requesting read access to calendar events
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

def authenticate():
    """
    Authenticate with Google Calendar API using OAuth2.
    First run opens browser for permission — saves token.json
    for all future runs without needing to log in again.
    """
    creds = None

    # Load existing token if available
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If no valid token, authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES
            )
            creds = flow.run_local_server(port=0)

        # Save token for next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return creds


def fetch_events(max_results=50):
    """
    Fetch upcoming and recent calendar events.
    Returns list of events in same format as detector.py expects.
    """
    creds = authenticate()
    service = build('calendar', 'v3', credentials=creds)

    # Fetch events from the last 30 days to now
    now = datetime.now(timezone.utc).isoformat()

    print(f"\n  Fetching last {max_results} calendar events...")

    events_result = service.events().list(
        calendarId='primary',
        maxResults=max_results,
        singleEvents=True,
        orderBy='updated'
    ).execute()

    raw_events = events_result.get('items', [])

    if not raw_events:
        print("  No events found.")
        return []

    # Normalise to the format detector.py expects
    events = []
    for e in raw_events:
        events.append({
            'summary': e.get('summary', 'Untitled'),
            'description': e.get('description', ''),
            'created': e.get('created', ''),
            'updated': e.get('updated', ''),
            'organizer': e.get('organizer', {}).get('email', ''),
            'raw': e
        })

    print(f"  Fetched {len(events)} events from Google Calendar.")
    return events