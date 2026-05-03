# bb-recon

Passive bug bounty recon toolkit for subdomain enumeration, CNAME analysis, and DNS takeover detection.

## Features

- Subdomain enumeration via crt.sh certificate transparency logs
- CNAME chain analysis — detects dangling records pointing to deleted services
- DNS takeover fingerprinting (AWS ELB, Heroku, Vercel, Fastly, GitHub Pages, Shopify, Zendesk)
- HTTP header inspection — HSTS, security headers, server disclosure
- Wayback Machine URL discovery
- GitHub dork generation for target
- Zero dependencies — pure Python 3, no API keys required
- Auto-saves markdown report

## Usage

```bash
python3 recon.py <target>
```

## Example

```bash
python3 recon.py zomato.com
```

## What It Finds

- Dangling CNAME records → potential subdomain takeover
- Missing HSTS headers
- Exposed server information
- Historical URLs via Wayback Machine
- Related GitHub repositories

## Findings

This tool has been used to discover Critical and High severity vulnerabilities in programs including Stripe, Trip.com, and Zomato on HackerOne.

## Author

Alex Kedwell — [alexkedwell.com](https://alexkedwell.com)  
Cybersecurity Researcher | Bug Bounty Hunter | Founder @ [Tech Guys AI](https://techguysai.com)

## Disclaimer

For authorized security testing and bug bounty programs only. All testing should be passive and non-exploitative.
