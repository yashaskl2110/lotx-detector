# LotX Detector — Living-off-the-Cloud C2 Detection Tool

Built in response to Cloudflare's 2026 Threat Report findings on 
state-sponsored actors using trusted SaaS platforms as C2 channels.

## The Threat
Cloudflare's Cloudforce One team documented Chinese APT groups embedding 
encrypted payloads inside Google Calendar event descriptions to communicate 
with infected hosts — blending malicious traffic with legitimate SaaS usage 
to evade detection entirely.

Traditional perimeter defences don't catch this. The traffic looks normal. 
The platform is trusted. The C2 channel is invisible.

## What This Tool Detects
- Encrypted/encoded payloads in Google Calendar event descriptions
- Anomalous OAuth token forwarding from CRM platforms to external AI APIs
- SaaS-to-SaaS permission blast radius — how many services collapse 
  if one OAuth token is compromised
- Out-of-hours API call spikes from trusted SaaS integrations
- Outbound connections to known Tor exit nodes from trusted processes

## Technical Approach
- Python-based detection engine
- OAuth token permission auditing via provider APIs (Google, Slack, GitHub)
- Entropy analysis on calendar/note fields to detect encoded payloads
- Network baseline profiling to surface anomalous call volumes
- Risk scoring engine with Cloudflare Zero Trust remediation mapping

## Status
Core detection engine in active development.

## Background
Currently researching kernel exploits targeting memory registers
applying low-level attacker perspective to cloud-layer threat detection. 
CompTIA Sec+ certified. Computer engineering and Cybersecurity background.

## References
- [Cloudflare 2026 Threat Report](https://blog.cloudflare.com)
- [Cloudflare BGP Outage Post-mortem, February 2026](https://blog.cloudflare.com)
- [Cloudforce One Threat Intelligence](https://cloudforce.one)
