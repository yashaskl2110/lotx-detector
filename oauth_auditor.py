from config import CF_REMEDIATION

# Known high-risk OAuth scopes and their risk levels
SCOPE_RISK = {
    # Google - Critical scopes
    'https://www.googleapis.com/auth/gmail.readonly':        ('HIGH',     'Read all Gmail messages'),
    'https://www.googleapis.com/auth/gmail.modify':          ('CRITICAL', 'Read, modify and delete Gmail'),
    'https://www.googleapis.com/auth/drive':                 ('CRITICAL', 'Full Google Drive access'),
    'https://www.googleapis.com/auth/drive.readonly':        ('HIGH',     'Read all Google Drive files'),
    'https://www.googleapis.com/auth/calendar':              ('HIGH',     'Full calendar read/write'),
    'https://www.googleapis.com/auth/calendar.readonly':     ('MEDIUM',   'Read calendar events'),
    'https://www.googleapis.com/auth/admin.directory.user':  ('CRITICAL', 'Manage all Google Workspace users'),
    'https://www.googleapis.com/auth/spreadsheets':          ('HIGH',     'Read/write all Google Sheets'),
    'https://www.googleapis.com/auth/contacts':              ('HIGH',     'Read/write all contacts'),
    # GitHub
    'repo':                                                  ('CRITICAL', 'Full repository access'),
    'admin:org':                                             ('CRITICAL', 'Full org admin access'),
    'delete_repo':                                           ('CRITICAL', 'Delete repositories'),
    'write:packages':                                        ('HIGH',     'Write packages'),
    'read:org':                                              ('MEDIUM',   'Read org membership'),
    'user:email':                                            ('LOW',      'Read email address'),
    # Slack
    'channels:history':                                      ('CRITICAL', 'Read all channel messages'),
    'files:read':                                            ('HIGH',     'Read all files'),
    'chat:write':                                            ('HIGH',     'Post messages'),
    'users:read':                                            ('MEDIUM',   'Read user list'),
    'channels:read':                                         ('LOW',      'Read channel list'),
}

# Each scope maps to real downstream capabilities it exposes
SCOPE_IMPACT = {
    'https://www.googleapis.com/auth/gmail.modify':          ['email_read', 'email_delete', 'email_send', 'attachment_access'],
    'https://www.googleapis.com/auth/gmail.readonly':        ['email_read', 'attachment_access'],
    'https://www.googleapis.com/auth/drive':                 ['file_read', 'file_write', 'file_delete', 'file_share'],
    'https://www.googleapis.com/auth/drive.readonly':        ['file_read'],
    'https://www.googleapis.com/auth/calendar':              ['calendar_read', 'calendar_write', 'meeting_access'],
    'https://www.googleapis.com/auth/calendar.readonly':     ['calendar_read', 'meeting_access'],
    'https://www.googleapis.com/auth/admin.directory.user':  ['user_create', 'user_delete', 'user_modify', 'password_reset', 'org_admin'],
    'https://www.googleapis.com/auth/spreadsheets':          ['data_read', 'data_write', 'formula_exec'],
    'https://www.googleapis.com/auth/contacts':              ['contact_read', 'contact_write', 'org_chart'],
    'repo':           ['code_read', 'code_write', 'secret_access', 'ci_trigger', 'deploy_trigger'],
    'admin:org':      ['org_admin', 'user_manage', 'billing_access', 'sso_bypass'],
    'delete_repo':    ['code_delete', 'history_destroy'],
    'write:packages': ['artifact_write', 'deploy_trigger'],
    'read:org':       ['org_chart', 'user_enumerate'],
    'user:email':     ['email_read'],
    'channels:history': ['message_read', 'secret_exposure', 'credential_harvest'],
    'files:read':       ['file_read', 'attachment_access'],
    'chat:write':       ['message_send', 'phishing_vector'],
    'users:read':       ['user_enumerate', 'org_chart'],
    'channels:read':    ['channel_enumerate'],
}

# Weight of each capability — based on real attack impact
# These are defensible: each number represents how many
# downstream systems are typically reachable via that capability
IMPACT_WEIGHTS = {
    'org_admin':          15,  # Cascades to every system in the org
    'sso_bypass':         12,  # Can impersonate any user
    'password_reset':     10,  # Direct account takeover vector
    'secret_access':       9,  # CI secrets expose all deployment targets
    'credential_harvest':  8,  # Slack history full of passwords/tokens
    'user_delete':         8,
    'user_create':         8,
    'deploy_trigger':      7,  # Can push malicious code to production
    'code_write':          6,
    'code_delete':         6,
    'user_modify':         5,
    'email_send':          5,  # Phishing from trusted internal address
    'phishing_vector':     5,
    'billing_access':      4,
    'file_delete':         4,
    'history_destroy':     4,
    'data_write':          4,
    'secret_exposure':     4,
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
    'ci_trigger':          4,
    'user_manage':         5,
    'file_write':          4,
}


def assess_scope_risk(scopes):
    """
    Assess risk level of a list of OAuth scopes.
    Returns highest risk level and list of findings.
    """
    findings = []
    highest_risk = 'LOW'
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    for scope in scopes:
        if scope in SCOPE_RISK:
            risk, description = SCOPE_RISK[scope]
            findings.append({
                'scope': scope,
                'risk': risk,
                'description': description
            })
            if risk_order[risk] < risk_order[highest_risk]:
                highest_risk = risk

    return highest_risk, findings


def calculate_blast_radius(platform, scopes):
    """
    Calculate blast radius from actual granted scopes.
    Each scope maps to real downstream capabilities.
    Blast radius = sum of impact weights across all unique
    capabilities exposed by the granted scopes.

    Every number is traceable — if asked how we got the score,
    we can walk through exactly which scopes contributed
    which capabilities and why each weight was assigned.
    """
    exposed_capabilities = set()

    for scope in scopes:
        impacts = SCOPE_IMPACT.get(scope, [])
        for impact in impacts:
            exposed_capabilities.add(impact)

    # Sum weights of unique exposed capabilities
    blast_score = sum(
        IMPACT_WEIGHTS.get(cap, 1)
        for cap in exposed_capabilities
    )

    # High impact capabilities for human-readable description
    high_impact = sorted(
        [cap for cap in exposed_capabilities if IMPACT_WEIGHTS.get(cap, 0) >= 5],
        key=lambda c: IMPACT_WEIGHTS.get(c, 0),
        reverse=True
    )

    description = ', '.join(high_impact[:4]) if high_impact else 'limited exposure'
    return blast_score, description


def audit_connection(connection):
    """
    Audit a single OAuth connection for risk.
    """
    scopes = connection.get('scopes', [])
    platform = connection.get('platform', 'unknown')
    name = connection.get('name', 'Unknown connection')
    token_age = connection.get('token_age_days', 0)

    # Assess scope risk
    risk_level, scope_findings = assess_scope_risk(scopes)

    # Calculate blast radius from real scope data
    blast_radius, blast_description = calculate_blast_radius(platform, scopes)

    # Additional risk factors
    extra_flags = []
    if token_age > 90:
        extra_flags.append(f'Token not rotated in {token_age} days (exceeds 90-day policy)')
    if token_age > 365:
        extra_flags.append('CRITICAL: Token over 1 year old — immediate rotation required')
        risk_level = 'CRITICAL'

    # Build remediation steps
    remediation = []
    if risk_level == 'CRITICAL':
        remediation.append('Revoke token immediately via Google Cloud Console')
        remediation.append('Enable Cloudflare CASB to monitor future OAuth grants')
    elif risk_level == 'HIGH':
        remediation.append('Reduce OAuth scope to minimum required permissions')
        remediation.append('Configure Cloudflare Access policy for this integration')
    remediation.append('Route API calls through Cloudflare Gateway for inspection')

    return {
        'name': name,
        'platform': platform,
        'risk': risk_level,
        'scope_findings': scope_findings,
        'blast_radius': blast_radius,
        'blast_description': blast_description,
        'extra_flags': extra_flags,
        'remediation': remediation,
        'scope_count': len(scopes)
    }


def audit_all(connections):
    """Audit all OAuth connections and return prioritised results."""
    results = []
    for conn in connections:
        result = audit_connection(conn)
        results.append(result)

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    results.sort(key=lambda x: risk_order[x['risk']])
    return results


def print_blast_report(results):
    """Print OAuth blast radius report."""
    print("\n" + "="*60)
    print("  LotX Detector — OAuth Blast Radius Report")
    print("  SaaS Permission Audit")
    print("="*60)

    critical = [r for r in results if r['risk'] == 'CRITICAL']
    high = [r for r in results if r['risk'] == 'HIGH']

    print(f"\n  Connections audited: {len(results)}")
    print(f"  Critical risk:       {len(critical)}")
    print(f"  High risk:           {len(high)}")
    print()

    for r in results:
        if r['risk'] in ('CRITICAL', 'HIGH', 'MEDIUM'):
            print(f"  [{r['risk']}] {r['name']}")
            print(f"  Blast score: {r['blast_radius']} | Scopes: {r['scope_count']}")
            print(f"  High-impact capabilities: {r['blast_description']}")

            if r['scope_findings']:
                print(f"  Dangerous scopes:")
                for sf in r['scope_findings']:
                    if sf['risk'] in ('CRITICAL', 'HIGH'):
                        print(f"    ⚠ [{sf['risk']}] {sf['scope']}")
                        print(f"         {sf['description']}")

            if r['extra_flags']:
                for flag in r['extra_flags']:
                    print(f"    ⏰ {flag}")

            print(f"  Remediation:")
            for rem in r['remediation']:
                print(f"    ⚡ {rem}")
            print()

    print("="*60 + "\n")


if __name__ == "__main__":
    test_connections = [
        {
            'name': 'Salesforce → OpenAI GPT-4',
            'platform': 'google',
            'scopes': [
                'https://www.googleapis.com/auth/drive',
                'https://www.googleapis.com/auth/gmail.modify',
                'https://www.googleapis.com/auth/admin.directory.user'
            ],
            'token_age_days': 420
        },
        {
            'name': 'GitHub Actions → AWS Production',
            'platform': 'github',
            'scopes': ['repo', 'admin:org', 'delete_repo'],
            'token_age_days': 240
        },
        {
            'name': 'Notion → Slack Bot',
            'platform': 'slack',
            'scopes': ['channels:history', 'files:read', 'chat:write'],
            'token_age_days': 45
        },
        {
            'name': 'Calendar sync integration',
            'platform': 'google',
            'scopes': [
                'https://www.googleapis.com/auth/calendar.readonly',
                'https://www.googleapis.com/auth/contacts'
            ],
            'token_age_days': 30
        }
    ]

    results = audit_all(test_connections)
    print_blast_report(results)