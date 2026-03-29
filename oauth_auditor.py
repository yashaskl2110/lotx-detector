from oauth_scope_checker import get_real_scopes, assess_real_scopes
from github_auditor import get_github_token_scopes, assess_github_risk, get_oauth_apps

# Scope to capability mapping — what each real scope actually exposes
SCOPE_IMPACT = {
    # Google scopes
    'https://www.googleapis.com/auth/gmail.modify':          ['email_read', 'email_delete', 'email_send', 'attachment_access'],
    'https://www.googleapis.com/auth/gmail.readonly':        ['email_read', 'attachment_access'],
    'https://www.googleapis.com/auth/drive':                 ['file_read', 'file_write', 'file_delete', 'file_share'],
    'https://www.googleapis.com/auth/drive.readonly':        ['file_read'],
    'https://www.googleapis.com/auth/calendar':              ['calendar_read', 'calendar_write', 'meeting_access'],
    'https://www.googleapis.com/auth/calendar.readonly':     ['calendar_read', 'meeting_access'],
    'https://www.googleapis.com/auth/admin.directory.user':  ['user_create', 'user_delete', 'user_modify', 'password_reset', 'org_admin'],
    'https://www.googleapis.com/auth/spreadsheets':          ['data_read', 'data_write', 'formula_exec'],
    'https://www.googleapis.com/auth/contacts':              ['contact_read', 'contact_write', 'org_chart'],
    # GitHub scopes
    'repo':             ['code_read', 'code_write', 'secret_access', 'ci_trigger', 'deploy_trigger'],
    'admin:org':        ['org_admin', 'user_manage', 'billing_access', 'sso_bypass'],
    'delete_repo':      ['code_delete', 'history_destroy'],
    'write:packages':   ['artifact_write', 'deploy_trigger'],
    'read:org':         ['org_chart', 'user_enumerate'],
    'user:email':       ['email_read'],
    'public_repo':      ['code_read'],
    'read:user':        ['user_enumerate'],
}

# Impact weights — each capability maps to real downstream exposure
IMPACT_WEIGHTS = {
    'org_admin':          15,
    'sso_bypass':         12,
    'password_reset':     10,
    'secret_access':       9,
    'credential_harvest':  8,
    'user_delete':         8,
    'user_create':         8,
    'deploy_trigger':      7,
    'code_write':          6,
    'code_delete':         6,
    'user_modify':         5,
    'email_send':          5,
    'phishing_vector':     5,
    'billing_access':      4,
    'file_delete':         4,
    'history_destroy':     4,
    'data_write':          4,
    'secret_exposure':     4,
    'ci_trigger':          4,
    'formula_exec':        3,
    'artifact_write':      3,
    'message_read':        3,
    'file_read':           3,
    'email_read':          3,
    'calendar_write':      3,
    'message_send':        3,
    'code_read':           2,
    'file_share':          2,
    'attachment_access':   2,
    'data_read':           2,
    'contact_read':        2,
    'user_enumerate':      2,
    'contact_write':       2,
    'org_chart':           1,
    'channel_enumerate':   1,
    'meeting_access':      1,
    'calendar_read':       1,
    'user_manage':         5,
    'file_write':          4,
}


def calculate_blast_radius(scopes):
    """
    Calculate blast radius from real granted scopes.
    Every number comes from actual scope data — nothing hardcoded.
    """
    exposed_capabilities = set()

    for scope in scopes:
        impacts = SCOPE_IMPACT.get(scope, [])
        for impact in impacts:
            exposed_capabilities.add(impact)

    blast_score = sum(
        IMPACT_WEIGHTS.get(cap, 1)
        for cap in exposed_capabilities
    )

    high_impact = sorted(
        [cap for cap in exposed_capabilities if IMPACT_WEIGHTS.get(cap, 0) >= 4],
        key=lambda c: IMPACT_WEIGHTS.get(c, 0),
        reverse=True
    )

    description = ', '.join(high_impact[:4]) if high_impact else 'minimal exposure'
    return blast_score, description, list(exposed_capabilities)


def run_blast_radius_audit():
    """
    Pull real OAuth scopes from Google and GitHub accounts.
    Calculate blast radius from actual granted permissions.
    No hardcoded connections — all data is live.
    """
    results = []

    # Google — real scopes from your actual account
    print("  Fetching real Google OAuth scopes...")
    google_token = get_real_scopes()
    if google_token:
        scopes = google_token.get('scopes', [])
        blast_score, description, capabilities = calculate_blast_radius(scopes)
        results.append({
            'account': f"Google ({google_token.get('email', 'unknown')})",
            'platform': 'google',
            'scopes': scopes,
            'blast_score': blast_score,
            'high_impact_capabilities': description,
            'capabilities': capabilities,
            'token_expires_in': google_token.get('expires_in_seconds', 0)
        })

    # GitHub — real scopes from your actual account
    print("  Fetching real GitHub OAuth scopes...")
    github_data = get_github_token_scopes()
    if github_data:
        scopes = github_data.get('scopes', [])
        blast_score, description, capabilities = calculate_blast_radius(scopes)
        results.append({
            'account': f"GitHub ({github_data.get('username', 'unknown')})",
            'platform': 'github',
            'scopes': scopes,
            'blast_score': blast_score,
            'high_impact_capabilities': description,
            'capabilities': capabilities,
            'two_factor': github_data.get('two_factor', False),
            'public_repos': github_data.get('public_repos', 0)
        })

    return results


def print_blast_report(results):
    """Print real blast radius report."""
    print("\n" + "="*60)
    print("  LotX Detector — OAuth Blast Radius Report")
    print("  Real scope data from your actual accounts")
    print("="*60)

    if not results:
        print("\n  No OAuth data retrieved.\n")
        return

    total_blast = sum(r['blast_score'] for r in results)
    print(f"\n  Accounts audited: {len(results)}")
    print(f"  Combined blast score: {total_blast}")
    print(f"  If any token is compromised, attacker gains access to")
    print(f"  capabilities scoring {total_blast} impact points\n")

    for r in results:
        print(f"  [{r['platform'].upper()}] {r['account']}")
        print(f"  Blast score:  {r['blast_score']}")
        print(f"  Scopes:       {len(r['scopes'])}")
        print(f"  High-impact:  {r['high_impact_capabilities']}")

        if r.get('two_factor') is False:
            print(f"  ⚠ [CRITICAL] 2FA not enabled — account takeover risk elevated")

        print(f"  Granted scopes:")
        for scope in r['scopes']:
            print(f"    → {scope}")

        print(f"\n  Cloudflare remediation:")
        if r['blast_score'] > 20:
            print(f"    ⚡ High blast score — enable Cloudflare CASB monitoring")
            print(f"    ⚡ Reduce OAuth scopes to minimum required")
        else:
            print(f"    ✓ Blast score within acceptable range")
            print(f"    ⚡ Continue monitoring via Cloudflare CASB")
        print()

    print("="*60 + "\n")


if __name__ == "__main__":
    results = run_blast_radius_audit()
    print_blast_report(results)