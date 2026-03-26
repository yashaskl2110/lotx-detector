import requests
from google.oauth2.credentials import Credentials


# What each real Google scope actually grants
SCOPE_DESCRIPTIONS = {
    'https://www.googleapis.com/auth/calendar.readonly':
        ('MEDIUM', 'Read all calendar events'),
    'https://www.googleapis.com/auth/calendar':
        ('HIGH', 'Full calendar read and write'),
    'https://www.googleapis.com/auth/gmail.readonly':
        ('HIGH', 'Read all Gmail messages'),
    'https://www.googleapis.com/auth/gmail.modify':
        ('CRITICAL', 'Read modify and delete Gmail'),
    'https://www.googleapis.com/auth/drive':
        ('CRITICAL', 'Full Google Drive access'),
    'https://www.googleapis.com/auth/drive.readonly':
        ('HIGH', 'Read all Google Drive files'),
    'https://www.googleapis.com/auth/admin.directory.user':
        ('CRITICAL', 'Manage all Google Workspace users'),
    'https://www.googleapis.com/auth/spreadsheets':
        ('HIGH', 'Read and write all Google Sheets'),
    'https://www.googleapis.com/auth/contacts':
        ('HIGH', 'Read and write all contacts'),
    'openid':
        ('LOW', 'Verify identity'),
    'https://www.googleapis.com/auth/userinfo.email':
        ('LOW', 'Read email address'),
    'https://www.googleapis.com/auth/userinfo.profile':
        ('LOW', 'Read basic profile info'),
}


def get_real_scopes():
    """
    Call Google tokeninfo endpoint with your real token.
    Returns the actual scopes your OAuth token has been granted.
    This is real data from your real Google account — not hardcoded.
    """
    try:
        creds = Credentials.from_authorized_user_file(
            'token.json',
            scopes=['https://www.googleapis.com/auth/calendar.readonly']
        )

        # Refresh token if expired
        if not creds.valid:
            from google.auth.transport.requests import Request
            creds.refresh(Request())
            # Save refreshed token
            with open('token.json', 'w') as f:
                f.write(creds.to_json())

        token = creds.token

        response = requests.get(
            'https://oauth2.googleapis.com/tokeninfo',
            params={'access_token': token},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            scopes_raw = data.get('scope', '')
            scopes = scopes_raw.split(' ')
            email = data.get('email', 'unknown')
            expires_in = data.get('expires_in', 0)
            return {
                'scopes': scopes,
                'email': email,
                'expires_in_seconds': int(expires_in),
                'raw': data
            }
        else:
            print(f"  Token error: {response.status_code}")
            return None

    except Exception as e:
        print(f"  Error checking token: {e}")
        return None

def assess_real_scopes(token_data):
    """
    Assess risk of your actual granted scopes.
    Every finding here is from your real Google account.
    """
    if not token_data:
        return []

    scopes = token_data['scopes']
    findings = []
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    overall_risk = 'LOW'

    for scope in scopes:
        if scope in SCOPE_DESCRIPTIONS:
            risk, description = SCOPE_DESCRIPTIONS[scope]
            findings.append({
                'scope': scope,
                'risk': risk,
                'description': description
            })
            if risk_order[risk] < risk_order[overall_risk]:
                overall_risk = risk

    return findings, overall_risk


def print_scope_report(token_data, findings, overall_risk):
    """Print real OAuth scope audit report."""
    print("\n" + "="*60)
    print("  LotX Detector — Real OAuth Scope Audit")
    print("  Live data from your Google account")
    print("="*60)

    if not token_data:
        print("\n  Could not retrieve token data.")
        print("  Run main.py first to authenticate.\n")
        return

    print(f"\n  Account:     {token_data['email']}")
    print(f"  Token expires in: {token_data['expires_in_seconds']} seconds")
    print(f"  Overall risk: {overall_risk}")
    print(f"  Scopes granted: {len(token_data['scopes'])}\n")

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings_sorted = sorted(
        findings,
        key=lambda x: risk_order[x['risk']]
    )

    for f in findings_sorted:
        marker = '⚠' if f['risk'] in ('CRITICAL', 'HIGH') else '→'
        print(f"  {marker} [{f['risk']}] {f['scope']}")
        print(f"       {f['description']}")

    print(f"\n  Cloudflare remediation:")
    if overall_risk in ('CRITICAL', 'HIGH'):
        print(f"    ⚡ Review and reduce OAuth scopes to minimum required")
        print(f"    ⚡ Enable Cloudflare CASB to monitor scope usage")
        print(f"    ⚡ Configure Access policy to alert on scope changes")
    else:
        print(f"    ✓ Scopes within acceptable range")
        print(f"    ⚡ Continue monitoring via Cloudflare CASB")

    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    print("\n  Checking real OAuth scopes from your Google account...")
    token_data = get_real_scopes()
    if token_data:
        findings, overall_risk = assess_real_scopes(token_data)
        print_scope_report(token_data, findings, overall_risk)
    else:
        print("  Run python main.py first to authenticate.")