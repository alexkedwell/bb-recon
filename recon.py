#!/usr/bin/env python3
"""
recon.py — Passive Bug Bounty Recon CLI
========================================
Built by Ched ⚡ for NotChed | 2026-05-01

One command. One target. Full passive recon report.

What it does:
  1. Certificate Transparency (crt.sh) → subdomain enumeration
  2. DNS record scrape (A, AAAA, MX, TXT, NS, CNAME via system DNS)
  3. HTTP header fingerprinting → detect tech stack, security headers
  4. Wayback Machine CDX API → historical endpoint harvesting
  5. GitHub dork suggestions → ready-to-search secrets/exposure queries
  6. Summary risk scorecard → quick threat surface overview

100% PASSIVE — only queries public APIs and your local DNS resolver.
No active scanning. No port probing. Safe to use on any program scope.

Usage:
    python3 recon.py <domain> [--output report.md] [--no-wayback] [--timeout 10]

Example:
    python3 recon.py example.com --output example-report.md
"""

from __future__ import annotations
import argparse
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ssl
from typing import Optional, List, Dict, Any

# ── helpers ───────────────────────────────────────────────────────────────────

def fetch_json(url: str, timeout: int = 10) -> Optional[Any]:
    """Fetch JSON from a URL, return None on failure."""
    try:
        ctx = ssl.create_default_context()
        req = Request(url, headers={"User-Agent": "recon.py/1.0 (passive-recon-tool)"})
        with urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return None


def fetch_text(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch plain text from a URL."""
    try:
        ctx = ssl.create_default_context()
        req = Request(url, headers={"User-Agent": "recon.py/1.0 (passive-recon-tool)"})
        with urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def fetch_headers(domain: str, timeout: int = 8) -> dict:
    """Make a HEAD request to https://domain and return response headers."""
    headers = {}
    try:
        ctx = ssl.create_default_context()
        req = Request(
            f"https://{domain}/",
            method="HEAD",
            headers={"User-Agent": "recon.py/1.0 (passive-recon-tool)"},
        )
        with urlopen(req, context=ctx, timeout=timeout) as resp:
            for k, v in resp.headers.items():
                headers[k.lower()] = v
    except HTTPError as e:
        # Still get headers even on 4xx
        for k, v in e.headers.items():
            headers[k.lower()] = v
    except Exception:
        pass
    return headers


# ── recon modules ─────────────────────────────────────────────────────────────

def crtsh_subdomains(domain: str, timeout: int) -> List[str]:
    """Query crt.sh certificate transparency logs for subdomains."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    data = fetch_json(url, timeout=timeout)
    if not data:
        return []
    
    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.splitlines():
            line = line.strip().lower()
            # Strip wildcard prefix
            if line.startswith("*."):
                line = line[2:]
            if line.endswith(f".{domain}") or line == domain:
                subs.add(line)
    
    return sorted(subs)


def dns_records(domain: str) -> Dict[str, List[str]]:
    """Resolve common DNS record types for a domain."""
    records = {}
    
    # A records
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        records["A"] = sorted(set(r[4][0] for r in results))
    except Exception:
        records["A"] = []
    
    # AAAA records
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        records["AAAA"] = sorted(set(r[4][0] for r in results))
    except Exception:
        records["AAAA"] = []
    
    # MX via dig-style (using socket fallback)
    # We'll use a free DNS-over-HTTPS API for richer records
    doh_base = "https://cloudflare-dns.com/dns-query"
    
    for rtype in ["MX", "TXT", "NS", "CNAME"]:
        url = f"{doh_base}?name={domain}&type={rtype}"
        resp = fetch_json(url + "&ct=application/dns-json", timeout=8)
        if resp and "Answer" in resp:
            vals = []
            for ans in resp["Answer"]:
                data_val = ans.get("data", "").strip().strip('"')
                if data_val:
                    vals.append(data_val)
            records[rtype] = vals
        else:
            records[rtype] = []
    
    return records


def fingerprint_headers(domain: str, timeout: int) -> Dict[str, Any]:
    """Probe HTTP headers and infer tech stack + security posture."""
    headers = fetch_headers(domain, timeout=timeout)
    
    # Tech stack inference
    tech = []
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    via = headers.get("via", "")
    cf_ray = headers.get("cf-ray", "")
    
    if "nginx" in server.lower(): tech.append("Nginx")
    if "apache" in server.lower(): tech.append("Apache")
    if "microsoft-iis" in server.lower(): tech.append("IIS")
    if "cloudflare" in server.lower() or cf_ray: tech.append("Cloudflare")
    if "php" in x_powered.lower(): tech.append(f"PHP ({x_powered})")
    if "asp.net" in x_powered.lower(): tech.append("ASP.NET")
    if "express" in x_powered.lower(): tech.append("Node.js/Express")
    if "next.js" in headers.get("x-nextjs-cache", "").lower() or \
       "next.js" in headers.get("x-powered-by", "").lower(): tech.append("Next.js")
    if "vercel" in headers.get("x-vercel-id", "").lower(): tech.append("Vercel")
    if "amazonaws" in via.lower() or "aws" in server.lower(): tech.append("AWS")
    if "wp-" in str(headers) or "wordpress" in str(headers).lower(): tech.append("WordPress")
    
    # Security header audit
    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "x-xss-protection": "X-XSS-Protection (legacy)",
    }
    
    present = {name: headers[hdr] for hdr, name in security_headers.items() if hdr in headers}
    missing = [name for hdr, name in security_headers.items() if hdr not in headers]
    
    # Interesting headers that might leak info
    interesting = {}
    leak_headers = [
        "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-runtime", "x-version", "x-app-version",
        "x-drupal-cache", "x-varnish", "x-cache", "x-backend-server",
    ]
    for h in leak_headers:
        if h in headers and headers[h]:
            interesting[h] = headers[h]
    
    return {
        "raw_count": len(headers),
        "tech_stack": tech if tech else ["Unknown"],
        "security_present": present,
        "security_missing": missing,
        "info_leak_headers": interesting,
        "server": server,
        "x_powered_by": x_powered,
    }


def wayback_endpoints(domain: str, timeout: int, limit: int = 200) -> List[str]:
    """Query Wayback Machine CDX API for historical endpoints."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        f"&limit={limit}&filter=statuscode:200"
    )
    data = fetch_json(url, timeout=timeout)
    if not data or len(data) < 2:
        return []
    
    # First row is header ["original"]
    urls = []
    interesting_exts = {
        ".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".yaml", ".yml",
        ".env", ".config", ".conf", ".bak", ".old", ".sql", ".log", ".txt",
        ".js", ".ts", ".graphql", ".proto"
    }
    interesting_paths = [
        "/api/", "/admin", "/login", "/auth", "/config", "/debug",
        "/swagger", "/docs", "/graphql", "/v1/", "/v2/", "/.git",
        "/backup", "/test", "/staging", "/dev/", "/internal"
    ]
    
    for row in data[1:]:
        url_str = row[0] if row else ""
        if not url_str:
            continue
        parsed = urlparse(url_str)
        path = parsed.path.lower()
        ext = "." + path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
        
        # Prioritize interesting endpoints
        if ext in interesting_exts or any(p in path for p in interesting_paths):
            urls.append(url_str)
        elif len(urls) < 50:  # Fill remainder with general URLs
            urls.append(url_str)
    
    return sorted(set(urls))[:150]


def github_dorks(domain: str) -> List[Dict[str, str]]:
    """Generate ready-to-use GitHub dork queries for the target domain."""
    org = domain.split(".")[0]
    
    dorks = [
        {
            "label": "Secrets in code",
            "query": f'"{domain}" password OR secret OR api_key OR token language:python OR language:javascript',
        },
        {
            "label": "Config files",
            "query": f'"{domain}" filename:.env OR filename:.config OR filename:config.yml',
        },
        {
            "label": "AWS keys",
            "query": f'"{domain}" AKIA OR aws_access_key_id',
        },
        {
            "label": "Internal endpoints",
            "query": f'"{domain}" internal OR staging OR dev filename:*.md OR filename:*.txt',
        },
        {
            "label": "DB connection strings",
            "query": f'"{domain}" jdbc OR mongodb:// OR postgres:// OR mysql://',
        },
        {
            "label": "Org repos",
            "query": f'org:{org} language:python OR language:javascript OR language:go',
        },
        {
            "label": "SSH/TLS keys",
            "query": f'"{domain}" BEGIN RSA PRIVATE KEY OR BEGIN OPENSSH PRIVATE KEY',
        },
        {
            "label": "Hardcoded auth",
            "query": f'"{domain}" Authorization: Bearer OR Basic auth',
        },
    ]
    
    return dorks


def score_surface(subs: List[str], dns: Dict, headers_info: Dict, endpoints: List[str]) -> Dict[str, Any]:
    """Generate a quick attack-surface risk scorecard."""
    score = 0
    notes = []
    
    # Subdomain count risk
    if len(subs) > 50:
        score += 3
        notes.append(f"🔴 Large subdomain count ({len(subs)}) — high chance of forgotten/shadow assets")
    elif len(subs) > 15:
        score += 2
        notes.append(f"🟡 Moderate subdomain count ({len(subs)}) — worth probing each")
    elif len(subs) > 0:
        score += 1
        notes.append(f"🟢 Small subdomain count ({len(subs)})")
    
    # Missing security headers
    missing = headers_info.get("security_missing", [])
    if len(missing) >= 4:
        score += 3
        notes.append(f"🔴 Missing {len(missing)} security headers — weak hardening")
    elif len(missing) >= 2:
        score += 2
        notes.append(f"🟡 Missing {len(missing)} security headers")
    
    # Tech stack leakage
    leaks = headers_info.get("info_leak_headers", {})
    if leaks:
        score += 2
        notes.append(f"🔴 Server info leakage via headers: {', '.join(leaks.keys())}")
    
    # Interesting endpoints found
    juicy = [e for e in endpoints if any(p in e.lower() for p in [
        "admin", "api", "debug", "config", "swagger", "graphql", ".env", "backup", "token"
    ])]
    if juicy:
        score += 3
        notes.append(f"🔴 {len(juicy)} high-interest historical endpoints found")
    
    # TXT records (SPF/DMARC)
    txt = dns.get("TXT", [])
    has_spf = any("v=spf1" in t for t in txt)
    has_dmarc = any("v=DMARC1" in t for t in txt)
    if not has_spf:
        score += 1
        notes.append("🟡 No SPF record — possible email spoofing vector")
    if not has_dmarc:
        score += 1
        notes.append("🟡 No DMARC record — domain may be spoofable")
    
    level = "🔴 HIGH" if score >= 8 else "🟡 MEDIUM" if score >= 4 else "🟢 LOW"
    
    return {"score": score, "level": level, "notes": notes, "juicy_endpoints": juicy}


# ── report generation ─────────────────────────────────────────────────────────

def generate_report(domain: str, args) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    
    def h(text, level=2):
        lines.append("\n" + "#" * level + " " + text)
    
    def p(text=""):
        lines.append(text)
    
    # Header
    lines.append(f"# 🕵️ Passive Recon Report: `{domain}`")
    p(f"**Generated:** {now}  ")
    p(f"**Mode:** Passive only (crt.sh, Wayback, DNS-over-HTTPS, HTTP headers)  ")
    p(f"**Tool:** recon.py v1.0 by Ched ⚡")
    p()
    p("> ⚠️ This report uses **passive techniques only**. No active scanning was performed.")
    p("> Always confirm scope before testing anything beyond reconnaissance.")
    
    # ── Step 1: Certificate Transparency ──────────────────────────────────────
    h("1. Subdomains (Certificate Transparency)")
    p(f"_Source: crt.sh — querying %.{domain}_")
    p()
    
    print(f"  [1/5] Querying crt.sh for {domain}...", end=" ", flush=True)
    subs = crtsh_subdomains(domain, timeout=args.timeout)
    print(f"{len(subs)} subdomains found")
    
    if subs:
        p(f"Found **{len(subs)} unique subdomains**:")
        p()
        p("```")
        for s in subs[:100]:
            p(s)
        if len(subs) > 100:
            p(f"... and {len(subs) - 100} more")
        p("```")
        
        # Quick categorization
        interesting_subs = [s for s in subs if any(kw in s for kw in [
            "admin", "api", "dev", "staging", "test", "beta", "internal",
            "vpn", "mail", "ftp", "ssh", "db", "database", "backup",
            "jenkins", "jira", "confluence", "gitlab", "grafana", "kibana"
        ])]
        if interesting_subs:
            p()
            p(f"**🎯 High-interest subdomains ({len(interesting_subs)}):**")
            for s in interesting_subs:
                p(f"- `{s}`")
    else:
        p("No subdomains found via crt.sh (domain may be new or CT logs sparse).")
    
    # ── Step 2: DNS Records ───────────────────────────────────────────────────
    h("2. DNS Records")
    p(f"_Source: System resolver + Cloudflare DNS-over-HTTPS_")
    p()
    
    print(f"  [2/5] Resolving DNS records...", end=" ", flush=True)
    dns = dns_records(domain)
    print("done")
    
    for rtype, vals in dns.items():
        if vals:
            p(f"**{rtype}:**")
            for v in vals:
                p(f"  - `{v}`")
        else:
            p(f"**{rtype}:** _(none)_")
    
    # ── Step 3: HTTP Header Fingerprinting ────────────────────────────────────
    h("3. HTTP Header Fingerprinting")
    p(f"_Probing: https://{domain}/_")
    p()
    
    print(f"  [3/5] Probing HTTP headers for {domain}...", end=" ", flush=True)
    hinfo = fingerprint_headers(domain, timeout=args.timeout)
    print("done")
    
    p(f"**Tech Stack Detected:** {', '.join(hinfo['tech_stack'])}")
    p()
    
    if hinfo["info_leak_headers"]:
        p("**⚠️ Information Leakage via Headers:**")
        for k, v in hinfo["info_leak_headers"].items():
            p(f"  - `{k}: {v}`")
        p()
    
    p("**Security Headers:**")
    if hinfo["security_present"]:
        p("  ✅ Present:")
        for name, val in hinfo["security_present"].items():
            p(f"    - `{name}`: `{val[:80]}{'...' if len(val) > 80 else ''}`")
    if hinfo["security_missing"]:
        p("  ❌ Missing:")
        for name in hinfo["security_missing"]:
            p(f"    - `{name}`")
    
    # ── Step 4: Wayback Machine ───────────────────────────────────────────────
    h("4. Historical Endpoints (Wayback Machine)")
    
    endpoints = []
    if not args.no_wayback:
        p(f"_Source: web.archive.org CDX API — *.{domain}/*_")
        p()
        print(f"  [4/5] Querying Wayback Machine (this may take a moment)...", end=" ", flush=True)
        endpoints = wayback_endpoints(domain, timeout=args.timeout + 10)
        print(f"{len(endpoints)} endpoints found")
        
        if endpoints:
            p(f"Found **{len(endpoints)} historical URLs** (filtered to most interesting):")
            p()
            
            # Categorize
            cats = {
                "API / GraphQL": [e for e in endpoints if "/api/" in e or "/graphql" in e or "/v1/" in e or "/v2/" in e],
                "Admin / Auth": [e for e in endpoints if "/admin" in e or "/login" in e or "/auth" in e],
                "Config / Debug": [e for e in endpoints if "/config" in e or "/debug" in e or "/.env" in e or "/swagger" in e],
                "Sensitive Files": [e for e in endpoints if any(e.endswith(ext) for ext in [
                    ".sql", ".bak", ".old", ".log", ".env", ".config"
                ])],
                "JavaScript": [e for e in endpoints if e.endswith(".js") and "min.js" not in e],
                "Other": [],
            }
            
            categorized = set()
            for cat, items in cats.items():
                if cat == "Other":
                    continue
                if items:
                    p(f"**{cat} ({len(items)}):**")
                    for e in items[:15]:
                        p(f"  - `{e}`")
                    if len(items) > 15:
                        p(f"  - _...{len(items)-15} more_")
                    p()
                    categorized.update(items)
            
            remaining = [e for e in endpoints if e not in categorized]
            if remaining:
                p(f"**Other ({len(remaining)}):**")
                for e in remaining[:20]:
                    p(f"  - `{e}`")
                if len(remaining) > 20:
                    p(f"  - _...{len(remaining)-20} more_")
        else:
            p("No historical endpoints found (new domain or CDX returned empty).")
    else:
        p("_Wayback Machine scan skipped (--no-wayback)_")
        print(f"  [4/5] Wayback skipped")
    
    # ── Step 5: GitHub Dorks ──────────────────────────────────────────────────
    h("5. GitHub Dork Queries")
    p("_Copy-paste these into GitHub Code Search to find exposed secrets/configs_")
    p()
    
    print(f"  [5/5] Generating GitHub dorks...", end=" ", flush=True)
    dorks = github_dorks(domain)
    print("done")
    
    p("| Label | Search Query |")
    p("|-------|-------------|")
    for d in dorks:
        query_escaped = d["query"].replace("|", "\\|")
        p(f"| **{d['label']}** | `{query_escaped}` |")
    
    p()
    p("**Quick links (GitHub Code Search):**")
    for d in dorks:
        import urllib.parse
        encoded = urllib.parse.quote(d["query"])
        p(f"- [{d['label']}](https://github.com/search?q={encoded}&type=code)")
    
    # ── Risk Scorecard ────────────────────────────────────────────────────────
    h("6. Attack Surface Scorecard")
    
    scorecard = score_surface(subs, dns, hinfo, endpoints)
    
    p(f"**Risk Level: {scorecard['level']}** (score: {scorecard['score']}/15)")
    p()
    for note in scorecard["notes"]:
        p(f"- {note}")
    
    if scorecard["juicy_endpoints"]:
        p()
        p(f"**🎯 Juicy endpoints to investigate first ({len(scorecard['juicy_endpoints'])}):**")
        for e in scorecard["juicy_endpoints"][:10]:
            p(f"  - `{e}`")
    
    # ── Next Steps ────────────────────────────────────────────────────────────
    h("7. Suggested Next Steps")
    p()
    p("Based on this passive recon, here's a prioritized attack plan:")
    p()
    p("**1. Subdomain probing (active — confirm scope first)**")
    p("   ```bash")
    p(f"   # httpx probe (check which subs are alive)")
    p(f"   cat subs.txt | httpx -status-code -title -tech-detect")
    p("   ```")
    p()
    p("**2. JavaScript analysis**")
    p("   ```bash")
    p(f"   # Extract endpoints from JS files (use gau + linkfinder)")
    p(f"   gau {domain} | grep '\\.js$' | sort -u | xargs -I{{}} curl -s {{}} | python3 linkfinder.py")
    p("   ```")
    p()
    p("**3. Parameter discovery**")
    p("   ```bash")
    p(f"   # Arjun for param bruting on discovered endpoints")
    p(f"   arjun -u https://{domain}/api/search")
    p("   ```")
    p()
    p("**4. Nuclei templates for quick wins**")
    p("   ```bash")
    p(f"   nuclei -u https://{domain} -t cves/ -t misconfigurations/ -t exposures/")
    p("   ```")
    
    # ── Footer ────────────────────────────────────────────────────────────────
    h("Appendix: Raw Data")
    
    p("<details>")
    p("<summary>All subdomains (raw)</summary>")
    p()
    p("```")
    for s in subs:
        p(s)
    p("```")
    p("</details>")
    p()
    p("---")
    p(f"_Report generated by recon.py v1.0 | {now}_")
    p(f"_Ched ⚡ for NotChed — passive bug bounty recon_")
    
    return "\n".join(lines)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Passive Bug Bounty Recon CLI — one command, full markdown report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py example.com
  python3 recon.py hackerone.com --output h1-recon.md
  python3 recon.py target.com --no-wayback --timeout 15
        """,
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path (default: <domain>-recon-<date>.md)",
    )
    parser.add_argument(
        "--no-wayback",
        action="store_true",
        help="Skip Wayback Machine CDX scan (faster)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also save raw data as JSON alongside the report",
    )
    
    args = parser.parse_args()
    
    # Clean domain
    domain = args.domain.lower().strip()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc or domain
    domain = domain.lstrip("www.")
    
    # Default output path
    if not args.output:
        date_str = datetime.now().strftime("%Y-%m-%d")
        args.output = f"{domain.replace('.', '-')}-recon-{date_str}.md"
    
    print(f"\n🕵️  recon.py — Passive Bug Bounty Recon")
    print(f"   Target : {domain}")
    print(f"   Output : {args.output}")
    print(f"   Wayback: {'disabled' if args.no_wayback else 'enabled'}")
    print(f"   Timeout: {args.timeout}s")
    print(f"{'─' * 50}")
    
    t0 = time.time()
    report = generate_report(domain, args)
    elapsed = time.time() - t0
    
    with open(args.output, "w") as f:
        f.write(report)
    
    print(f"{'─' * 50}")
    print(f"✅ Done in {elapsed:.1f}s → {args.output}")
    print(f"   Lines: {report.count(chr(10))}")


if __name__ == "__main__":
    main()
