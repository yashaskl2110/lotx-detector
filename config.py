# LotX Detector — Configuration
# Adjust these thresholds based on your environment

# Shannon entropy threshold
# Legitimate calendar text: ~3.5
# Encoded C2 payloads: typically >4.5
ENTROPY_THRESHOLD = 4.5

# Minimum decoded length to flag as base64
BASE64_MIN_LENGTH = 20

# Business hours (24hr format)
BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 22

# Suspicious title/description ratio
SHORT_TITLE_MAX = 10
LONG_DESCRIPTION_MIN = 200

# Known C2 command markers
C2_MARKERS = [
    'cmd=', 'exec=', 'payload=',
    '/bin/', 'powershell', 'wget',
    'curl -s', 'bash -i', 'nc -e',
    'base64 -d', '/dev/tcp'
]

# Risk scoring thresholds
CRITICAL_FLAG_COUNT = 3
HIGH_FLAG_COUNT = 2
MEDIUM_FLAG_COUNT = 1

# Cloudflare Zero Trust remediation mapping
CF_REMEDIATION = {
    'HIGH_ENTROPY':       'Enable Cloudflare CASB scanning on Google Workspace',
    'BASE64_PAYLOAD':     'Create Gateway HTTP policy to inspect Calendar API responses',
    'OFF_HOURS_CREATION': 'Configure Access policy to alert on off-hours OAuth activity',
    'SUSPICIOUS_RATIO':   'Enable DLP profile for Calendar event descriptions',
    'C2_MARKERS':         'Block via Magic Firewall — add IOC to Gateway DNS policy'
}
