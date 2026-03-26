import requests
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_API = 'https://api.github.com'

SCOPE_RISK = {
    'repo':             ('CRITICAL', 'Full control of private repositories'),
    'admin:org':        ('CRITICAL', 'Full org admin access'),
    'delete_repo':      ('CRITICAL', 'Delete repositories'),
    'admin:repo_hook':  ('HIGH',     'Full control of repository webhooks'),
    'write:packages':   ('HIGH',     'Write and delete packages'),
    'admin:gpg_key':    ('HIGH',     'Full control of GPG keys'),
    'admin:ssh_signing_key': ('HIGH','Full control of SSH signing keys'),
    'gist':             ('MEDIUM',   'Write gists'),
    'read:org':         ('LOW',      'Read org membership'),
    'read:user':        ('LOW',      'Read user profile'),
    'public_repo':      ('LOW',      'Access public repositories'),
    'user:email':       ('LOW',      'Read email addresses'),
    'workflow':         ('CRITICAL', 'Update GitHub Actions workflows'),
}


def get_github_token_scopes():
    """
    Call GitHub API with your real token.
    GitHub returns the actual granted scopes in response headers.
    This is real data from your real GitHub account.
    """
    if not GITHUB_TOKEN:
        print("  No GITHUB_TOKEN found in .env file.")
        return None

    try:
        response = requests.get(
            f'{GITHUB_API}/user',
            headers={
                'Authorization': f'token {GITHUB_TOKEN}',
                'Accept': 'application/vnd.github.v3+json'
            },
            timeout=10
        )

        if response.status_code == 200:
            user_data = response.json()
            # GitHub returns granted scopes in X-OAuth-Scopes header
            scopes_header = response.headers.get('X-OAuth-Scopes', '')
            scopes = [s.strip() for s in scopes_header.split(',') if s.strip()]

            return {
                'username': user_data.get('login', 'unknown'),
                'email': user_data.get('email', 'unknown'),
                'public_repos': user_data.get('public_repos', 0),
                'private_repos': user_data.get('total_private_repos', 0),
                'scopes': scopes,
                'two_factor': user_data.get('two_factor_authentication', False)
            }
        else:
            print(f"  GitHub API error: {response.status_code}")
            return None

    except Exception as e:
        print(f"  Error calling GitHub API: {e}")
        return None


def get_oauth_apps():
    """
    Get real OAuth apps authorised on your GitHub account.
    Returns apps that have been granted access — the actual
    third party integrations connected to your account.
    """
    if not GITHUB_TOKEN:
        return []

    try:
        response = requests.get(
            f'{GITHUB_API}/user/installations',
            headers={
                'Authorization': f'token {GITHUB_TOKEN}',
                'Accept': 'application/vnd.github.v3+json'
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            installations = data.get('installations', [])
            apps = []
            for install in installations:
                apps.append({
                    'name': install.get('app_slug', 'unknown'),
                    'app_id': install.get('app_id'),
                    'permissions': install.get('permissions', {}),
                    'created_at': install.get('created_at', ''),
                    'updated_at': install.get('updated_at', '')
                })
            return apps
        else:
            return []

    except Exception as e:
        print(f"  Error fetching OAuth apps: {e}")
        return []


def assess_github_risk(token_data, oauth_apps):
    """
    Assess risk of your real GitHub token scopes
    and connected OAuth applications.
    """
    if not token_data:
        return [], 'UNKNOWN'

    scopes = token_data['scopes']
    findings = []
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    overall_risk = 'LOW'

    for scope in scopes:
        if scope in SCOPE_RISK:
            risk, description = SCOPE_RISK[scope]
            findings.append({
                'scope': scope,
                'risk': risk,
                'description': description
            })
            if risk_order[risk] < risk_order[overall_risk]:
                overall_risk = risk

    # Assess connected OAuth apps
    app_findings = []
    for app in oauth_apps:
        permissions = app.get('permissions', {})
        dangerous_perms = [
            p for p, level in permissions.items()
            if level in ('write', 'admin')
        ]
        if dangerous_perms:
            app_findings.append({
                'app': app['name'],
                'dangerous_permissions': dangerous_perms,
                'risk': 'HIGH'
            })
            if risk_order['HIGH'] < risk_order[overall_risk]:
                overall_risk = 'HIGH'

    return findings, app_findings, overall_risk


def print_github_report(token_data, scope_findings, app_findings, overall_risk):
    """Print GitHub OAuth audit report."""
    print("\n" + "="*60)
    print("  LotX Detector — GitHub OAuth Audit")
    print("  Live data from your GitHub account")
    print("="*60)

    if not token_data:
        print("\n  Could not retrieve GitHub token data.\n")
        return

    print(f"\n  Username:      {token_data['username']}")
    print(f"  Public repos:  {token_data['public_repos']}")
    print(f"  2FA enabled:   {token_data['two_factor']}")
    print(f"  Overall risk:  {overall_risk}")
    print(f"  Scopes granted: {len(token_data['scopes'])}\n")

    if not token_data['two_factor']:
        print("  ⚠ [CRITICAL] 2FA is not enabled on this account")
        print("       Account takeover risk is significantly elevated\n")

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_findings = sorted(
        scope_findings,
        key=lambda x: risk_order[x['risk']]
    )

    for f in sorted_findings:
        marker = '⚠' if f['risk'] in ('CRITICAL', 'HIGH') else '→'
        print(f"  {marker} [{f['risk']}] {f['scope']}")
        print(f"       {f['description']}")

    if app_findings:
        print(f"\n  Connected OAuth apps with dangerous permissions:")
        for app in app_findings:
            print(f"  ⚠ [{app['risk']}] {app['app']}")
            print(f"       Dangerous permissions: {app['dangerous_permissions']}")
    else:
        print(f"\n  Connected OAuth apps: none with dangerous permissions")

    print(f"\n  Cloudflare remediation:")
    if overall_risk in ('CRITICAL', 'HIGH'):
        print(f"    ⚡ Rotate token immediately")
        print(f"    ⚡ Enable Cloudflare Access policy for GitHub integration")
        print(f"    ⚡ Monitor via Cloudflare CASB")
    else:
        print(f"    ✓ Token scopes within acceptable range")
        print(f"    ⚡ Continue monitoring via Cloudflare CASB")

    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    print("\n  Checking real OAuth scopes from your GitHub account...")
    token_data = get_github_token_scopes()
    oauth_apps = get_oauth_apps()
    if token_data:
        scope_findings, app_findings, overall_risk = assess_github_risk(
            token_data, oauth_apps
        )
        print_github_report(
            token_data, scope_findings, app_findings, overall_risk
        )
    else:
        print("  Check your GITHUB_TOKEN in .env file.")