#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║          PHANTOM OSINT — All-Around Recon Tool        ║
║          For ethical/authorized use only              ║
╚═══════════════════════════════════════════════════════╝
"""

import socket
import ssl
import json
import re
import os
import sys
import time
import struct
import hashlib
import base64
import urllib.parse
import urllib.request
import urllib.error
import subprocess
import ipaddress
import threading
import concurrent.futures
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─────────────────────────────────────────────
#  ANSI COLOR PALETTE
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    CYAN    = "\033[36m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    RED     = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE    = "\033[34m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_DARK = "\033[48;5;234m"
    ORANGE  = "\033[38;5;214m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{C.RESET}
{C.GRAY}           ░  Open Source Intelligence Framework  ░{C.RESET}
{C.ORANGE}           ⚡  Ethical use only — authorized targets  ⚡{C.RESET}
""")

def section(title: str):
    width = 58
    print(f"\n{C.CYAN}{'─'*width}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  ◈  {title}{C.RESET}")
    print(f"{C.CYAN}{'─'*width}{C.RESET}")

def info(label: str, value, color=C.GREEN):
    print(f"  {C.GRAY}{label:<28}{C.RESET}{color}{value}{C.RESET}")

def warn(msg: str):
    print(f"  {C.YELLOW}⚠  {msg}{C.RESET}")

def err(msg: str):
    print(f"  {C.RED}✗  {msg}{C.RESET}")

def ok(msg: str):
    print(f"  {C.GREEN}✓  {msg}{C.RESET}")

def spinner_task(label, func, *args, **kwargs):
    """Run a function with a simple progress indicator."""
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    result = [None]
    exc    = [None]
    done   = threading.Event()

    def worker():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exc[0] = e
        finally:
            done.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    i = 0
    while not done.is_set():
        sys.stdout.write(f"\r  {C.CYAN}{frames[i % len(frames)]}{C.RESET}  {C.DIM}{label}...{C.RESET}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write(f"\r  {C.GREEN}✓{C.RESET}  {C.DIM}{label}{C.RESET}          \n")
    sys.stdout.flush()

    if exc[0]:
        raise exc[0]
    return result[0]


# ─────────────────────────────────────────────
#  1. TARGET CLASSIFIER
# ─────────────────────────────────────────────
def classify_target(target: str) -> dict:
    target = target.strip()
    result = {"raw": target, "type": None, "value": target}

    # IP address?
    try:
        obj = ipaddress.ip_address(target)
        result["type"] = "ipv6" if obj.version == 6 else "ip"
        result["is_private"] = obj.is_private
        result["is_loopback"] = obj.is_loopback
        return result
    except ValueError:
        pass

    # CIDR range?
    try:
        net = ipaddress.ip_network(target, strict=False)
        result["type"] = "cidr"
        result["network"] = str(net)
        result["num_hosts"] = net.num_addresses
        return result
    except ValueError:
        pass

    # Email?
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", target):
        result["type"] = "email"
        result["domain"] = target.split("@")[1]
        return result

    # URL → extract domain
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        result["type"] = "url"
        result["domain"] = parsed.netloc
        result["path"]   = parsed.path
        result["value"]  = parsed.netloc
        return result

    # Username heuristic (no dots for TLD, no spaces)
    if re.match(r"^[a-zA-Z0-9_.\-]{3,32}$", target) and "." not in target:
        result["type"] = "username"
        return result

    # Phone number
    if re.match(r"^\+?[\d\s\-().]{7,20}$", target):
        result["type"] = "phone"
        return result

    # Default: domain
    result["type"] = "domain"
    return result


# ─────────────────────────────────────────────
#  2. DNS LOOKUPS (pure socket / stdlib)
# ─────────────────────────────────────────────
DNS_RECORD_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "MX": 15,
    "TXT": 16, "AAAA": 28,
}

def build_dns_query(domain: str, qtype: int) -> bytes:
    """Craft a minimal DNS query packet."""
    txid = os.urandom(2)
    flags = b"\x01\x00"  # standard recursive query
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = txid + flags + qdcount + ancount + nscount + arcount

    qname = b""
    for part in domain.split("."):
        encoded = part.encode()
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"

    qtype_b  = struct.pack(">H", qtype)
    qclass_b = b"\x00\x01"
    return header + qname + qtype_b + qclass_b


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name from packet data (with compression)."""
    labels = []
    visited = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in visited:
                break
            visited.add(ptr)
            sub, _ = parse_dns_name(data, ptr)
            labels.append(sub)
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode(errors="replace"))
            offset += length
    return ".".join(labels), offset


def dns_query(domain: str, record_type: str, server="8.8.8.8", timeout=3) -> list[str]:
    """Send a raw DNS query and parse text answers."""
    qtype = DNS_RECORD_TYPES.get(record_type.upper(), 1)
    packet = build_dns_query(domain, qtype)
    results = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()
    except Exception:
        return results

    if len(response) < 12:
        return results

    ancount = struct.unpack(">H", response[6:8])[0]
    # skip header (12 bytes) + question section
    offset = 12
    # skip question
    while offset < len(response) and response[offset] != 0:
        if (response[offset] & 0xC0) == 0xC0:
            offset += 2
            break
        offset += response[offset] + 1
    else:
        offset += 1
    offset += 4  # qtype + qclass

    for _ in range(min(ancount, 20)):
        if offset >= len(response):
            break
        # name (may be compressed)
        if offset < len(response) and (response[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while offset < len(response) and response[offset] != 0:
                offset += response[offset] + 1
            offset += 1

        if offset + 10 > len(response):
            break
        rtype  = struct.unpack(">H", response[offset:offset+2])[0]
        rdlen  = struct.unpack(">H", response[offset+8:offset+10])[0]
        offset += 10
        rdata = response[offset:offset+rdlen]
        offset += rdlen

        try:
            if rtype == 1 and len(rdata) == 4:   # A
                results.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and len(rdata) == 16: # AAAA
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype in (2, 5, 12):             # NS, CNAME, PTR
                name, _ = parse_dns_name(response, offset - rdlen)
                results.append(name)
            elif rtype == 15:                      # MX
                name, _ = parse_dns_name(response, offset - rdlen + 2)
                pref = struct.unpack(">H", rdata[:2])[0]
                results.append(f"{pref} {name}")
            elif rtype == 16:                      # TXT
                txt_parts = []
                i = 0
                while i < len(rdata):
                    seg_len = rdata[i]
                    i += 1
                    txt_parts.append(rdata[i:i+seg_len].decode(errors="replace"))
                    i += seg_len
                results.append("".join(txt_parts))
        except Exception:
            pass

    return results


def full_dns_enum(domain: str) -> dict:
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        r = dns_query(domain, rtype)
        if r:
            records[rtype] = r
    return records


# ─────────────────────────────────────────────
#  3. WHOIS (via WHOIS protocol port 43)
# ─────────────────────────────────────────────
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "co":  "whois.nic.co",
    "uk":  "whois.nic.uk",
    "de":  "whois.denic.de",
    "fr":  "whois.nic.fr",
    "ru":  "whois.tcinet.ru",
    "us":  "whois.nic.us",
    "info":"whois.afilias.net",
    "biz": "whois.biz",
    "gov": "whois.dotgov.gov",
    "edu": "whois.educause.edu",
}

def raw_whois(query: str, server: str, port=43, timeout=8) -> str:
    try:
        sock = socket.create_connection((server, port), timeout=timeout)
        sock.sendall((query + "\r\n").encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data.decode(errors="replace")
    except Exception as e:
        return f"[error: {e}]"


def whois_lookup(target: str) -> dict:
    result = {"raw": "", "parsed": {}}
    tld = target.split(".")[-1].lower() if "." in target else ""
    server = WHOIS_SERVERS.get(tld, "whois.iana.org")
    raw = raw_whois(target, server)

    # Follow referrals
    refer_match = re.search(r"(?i)refer:\s*(\S+)", raw)
    if refer_match and "iana" in server:
        raw = raw_whois(target, refer_match.group(1))

    result["raw"] = raw

    # Parse key fields
    fields = {
        "Registrar":      r"(?i)registrar:\s*(.+)",
        "Created":        r"(?i)(?:creation date|registered on|created):\s*(.+)",
        "Updated":        r"(?i)(?:updated date|last updated):\s*(.+)",
        "Expires":        r"(?i)(?:expiry date|expiration date|registry expiry date):\s*(.+)",
        "Name Servers":   r"(?i)name server:\s*(.+)",
        "Status":         r"(?i)domain status:\s*(.+)",
        "Registrant Org": r"(?i)registrant organization:\s*(.+)",
        "Registrant Country": r"(?i)registrant country:\s*(.+)",
        "DNSSEC":         r"(?i)dnssec:\s*(.+)",
        "Abuse Email":    r"(?i)abuse-mailbox:\s*(.+)",
    }
    for key, pattern in fields.items():
        matches = re.findall(pattern, raw)
        if matches:
            vals = list(dict.fromkeys([m.strip() for m in matches]))[:3]
            result["parsed"][key] = vals if len(vals) > 1 else vals[0]

    return result


# ─────────────────────────────────────────────
#  4. IP GEOLOCATION (ip-api.com free)
# ─────────────────────────────────────────────
def geoip(ip: str) -> dict:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting,mobile"
        req = urllib.request.Request(url, headers={"User-Agent": "PhantomOSINT/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"status": "fail", "message": str(e)}


# ─────────────────────────────────────────────
#  5. PORT SCANNER
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch", 27017: "MongoDB",
}

def grab_banner(ip: str, port: int, timeout=2) -> Optional[str]:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        if port in (80, 8080, 8888):
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        elif port == 443:
            sock.close()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(socket.socket(), server_hostname=ip)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        banner = sock.recv(256).decode(errors="replace").strip()
        sock.close()
        return banner.split("\n")[0][:80] if banner else None
    except Exception:
        return None


def scan_port(ip: str, port: int, timeout=1.5) -> Optional[dict]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            return {"port": port, "service": service}
        return None
    except Exception:
        return None


def port_scan(ip: str, ports: list[int] = None, workers=50) -> list[dict]:
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports, key=lambda x: x["port"])


# ─────────────────────────────────────────────
#  6. SSL/TLS CERTIFICATE INFO
# ─────────────────────────────────────────────
def get_ssl_info(host: str, port=443) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.settimeout(5)
            sock.connect((host, port))
            cert = sock.getpeercert()
            cipher = sock.cipher()
            proto  = sock.version()

        result = {
            "subject":       dict(x[0] for x in cert.get("subject", [])),
            "issuer":        dict(x[0] for x in cert.get("issuer", [])),
            "not_before":    cert.get("notBefore"),
            "not_after":     cert.get("notAfter"),
            "san":           [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
            "cipher":        cipher[0] if cipher else "N/A",
            "protocol":      proto,
            "serial":        str(cert.get("serialNumber", "")),
        }
        return result
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
#  7. HTTP HEADERS & TECH STACK
# ─────────────────────────────────────────────
TECH_SIGNATURES = {
    "WordPress":       r"wp-content|wp-includes|wordpress",
    "Drupal":          r"drupal|sites/default/files",
    "Joomla":          r"joomla|/components/com_",
    "React":           r"react\.js|react-dom|__react",
    "Vue.js":          r"vue\.js|vue\.min\.js|__vue",
    "Angular":         r"angular\.js|ng-app|ng-controller",
    "jQuery":          r"jquery[\./]",
    "Bootstrap":       r"bootstrap[\./]",
    "Laravel":         r"laravel_session|XSRF-TOKEN",
    "Django":          r"csrfmiddlewaretoken|django",
    "Rails":           r"rails|_rails_|ruby on rails",
    "Next.js":         r"__next|_next/static",
    "Nuxt.js":         r"__nuxt|_nuxt/",
    "Nginx":           r"nginx",
    "Apache":          r"apache",
    "Cloudflare":      r"cloudflare|cf-ray",
    "Fastly":          r"fastly",
    "AWS":             r"amazonaws|aws-",
    "Google Cloud":    r"goog|google-cloud",
    "Shopify":         r"shopify|myshopify",
    "Wix":             r"wix\.com",
    "Squarespace":     r"squarespace",
}


def http_recon(url: str) -> dict:
    result = {"headers": {}, "technologies": [], "status": None, "redirect": None, "title": None, "meta": {}}
    if not url.startswith("http"):
        url = "https://" + url
    try:
        if HAS_REQUESTS:
            resp = requests.get(url, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 PhantomOSINT/1.0"},
                                verify=False)
            headers = dict(resp.headers)
            body    = resp.text
            result["status"]   = resp.status_code
            result["redirect"] = str(resp.url) if resp.url != url else None
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 PhantomOSINT/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                headers = dict(r.headers)
                body    = r.read(50000).decode(errors="replace")
                result["status"] = r.status
    except Exception as e:
        result["error"] = str(e)
        return result

    result["headers"] = {k: v for k, v in headers.items()}

    # Tech detection
    combined = (body + " " + " ".join(headers.values())).lower()
    for tech, pattern in TECH_SIGNATURES.items():
        if re.search(pattern, combined, re.I):
            result["technologies"].append(tech)

    # Parse title + meta
    try:
        soup = BeautifulSoup(body, "html.parser") if HAS_REQUESTS else None
        if soup:
            title_tag = soup.find("title")
            if title_tag:
                result["title"] = title_tag.text.strip()[:100]
            for meta in soup.find_all("meta"):
                name = meta.get("name", meta.get("property", ""))
                content = meta.get("content", "")
                if name and content:
                    result["meta"][name.lower()] = content[:200]
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────
#  8. SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────
SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","webmail","ns1","ns2","mx",
    "api","dev","staging","test","admin","portal","vpn","remote","secure",
    "app","shop","blog","forum","m","mobile","cdn","static","assets",
    "img","images","video","media","support","help","docs","wiki",
    "auth","login","dashboard","panel","control","manage","git","svn",
    "jenkins","jira","confluence","gitlab","github","ci","build","deploy",
    "beta","alpha","demo","sandbox","qa","uat","prod","production","old",
    "new","backup","archive","status","monitor","metrics","grafana","kibana",
    "db","database","mysql","postgres","redis","mongo","elastic","solr",
    "smtp2","mail2","mx1","mx2","ns3","ns4","intranet","internal","corp",
    "extranet","webdisk","cpanel","whm","autodiscover","autoconfig",
]

def check_subdomain(subdomain: str, domain: str) -> Optional[dict]:
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip}
    except Exception:
        return None


def subdomain_enum(domain: str, wordlist: list[str] = None, workers=80) -> list[dict]:
    if wordlist is None:
        wordlist = SUBDOMAINS
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_subdomain, sub, domain): sub for sub in wordlist}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                found.append(res)
    return sorted(found, key=lambda x: x["subdomain"])


# ─────────────────────────────────────────────
#  9. EMAIL BREACH CHECK (HaveIBeenPwned-style placeholder)
#     Uses public APIs that don't require keys
# ─────────────────────────────────────────────
def check_email_hunter(email: str) -> dict:
    """Check email via emailrep.io (free, no key required)."""
    result = {}
    try:
        req = urllib.request.Request(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "PhantomOSINT/1.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
            result = {
                "reputation":    data.get("reputation"),
                "suspicious":    data.get("suspicious"),
                "references":    data.get("references"),
                "details":       data.get("details", {}),
            }
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────
# 10. USERNAME SEARCH (social media presence)
# ─────────────────────────────────────────────
SOCIAL_SITES = [
    ("GitHub",       "https://github.com/{}"),
    ("Twitter/X",    "https://twitter.com/{}"),
    ("Instagram",    "https://www.instagram.com/{}/"),
    ("Reddit",       "https://www.reddit.com/user/{}"),
    ("TikTok",       "https://www.tiktok.com/@{}"),
    ("YouTube",      "https://www.youtube.com/@{}"),
    ("LinkedIn",     "https://www.linkedin.com/in/{}"),
    ("Medium",       "https://medium.com/@{}"),
    ("Dev.to",       "https://dev.to/{}"),
    ("Pastebin",     "https://pastebin.com/u/{}"),
    ("Twitch",       "https://www.twitch.tv/{}"),
    ("Pinterest",    "https://www.pinterest.com/{}/"),
    ("Flickr",       "https://www.flickr.com/people/{}"),
    ("Keybase",      "https://keybase.io/{}"),
    ("Replit",       "https://replit.com/@{}"),
    ("HackerNews",   "https://news.ycombinator.com/user?id={}"),
    ("ProductHunt",  "https://www.producthunt.com/@{}"),
    ("Behance",      "https://www.behance.net/{}"),
    ("Dribbble",     "https://dribbble.com/{}"),
    ("Soundcloud",   "https://soundcloud.com/{}"),
    ("Spotify",      "https://open.spotify.com/user/{}"),
]

def check_username_site(username: str, site_name: str, url_template: str) -> dict:
    url = url_template.format(username)
    try:
        if HAS_REQUESTS:
            resp = requests.get(url, timeout=6, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0"},
                                verify=False)
            if resp.status_code == 200:
                return {"site": site_name, "url": url, "status": "FOUND"}
            elif resp.status_code == 404:
                return {"site": site_name, "url": url, "status": "NOT FOUND"}
            else:
                return {"site": site_name, "url": url, "status": f"HTTP {resp.status_code}"}
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                if r.status == 200:
                    return {"site": site_name, "url": url, "status": "FOUND"}
    except urllib.error.HTTPError as e:
        return {"site": site_name, "url": url, "status": f"HTTP {e.code}"}
    except Exception:
        return {"site": site_name, "url": url, "status": "ERROR"}
    return {"site": site_name, "url": url, "status": "UNKNOWN"}


def username_search(username: str) -> list[dict]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(check_username_site, username, name, tmpl): name
            for name, tmpl in SOCIAL_SITES
        }
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
    return sorted(results, key=lambda x: (x["status"] != "FOUND", x["site"]))


# ─────────────────────────────────────────────
# 11. REVERSE IP LOOKUP
# ─────────────────────────────────────────────
def reverse_ip_lookup(ip: str) -> list[str]:
    """Use HackerTarget's free API."""
    domains = []
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "PhantomOSINT/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = resp.read().decode()
            if "No records" not in data and "error" not in data.lower():
                domains = [d.strip() for d in data.strip().split("\n") if d.strip()]
    except Exception:
        pass
    return domains[:50]


# ─────────────────────────────────────────────
# 12. ASN / BGP INFO
# ─────────────────────────────────────────────
def asn_lookup(ip: str) -> dict:
    """Query Team Cymru whois for ASN info."""
    result = {}
    try:
        resp = raw_whois(f" -v {ip}", "whois.cymru.com", timeout=6)
        lines = [l.strip() for l in resp.strip().split("\n") if l.strip() and not l.startswith("Bulk")]
        if len(lines) >= 2:
            parts = [p.strip() for p in lines[-1].split("|")]
            if len(parts) >= 5:
                result = {
                    "asn":     parts[0],
                    "ip":      parts[1],
                    "bgp_pfx": parts[2],
                    "cc":      parts[3],
                    "org":     parts[4],
                }
    except Exception:
        pass
    return result


# ─────────────────────────────────────────────
# 13. GOOGLE DORK GENERATOR
# ─────────────────────────────────────────────
def generate_dorks(target: str, target_type: str) -> list[dict]:
    dorks = []
    domain = target

    if target_type == "email":
        domain = target.split("@")[1]

    base = [
        ("Find all indexed pages",         f"site:{domain}"),
        ("Open directories",               f'site:{domain} intitle:"index of"'),
        ("Exposed config files",           f'site:{domain} ext:env OR ext:cfg OR ext:conf OR ext:ini'),
        ("Database files",                 f'site:{domain} ext:sql OR ext:db OR ext:sqlite'),
        ("Log files",                      f'site:{domain} ext:log'),
        ("Backup files",                   f'site:{domain} ext:bak OR ext:backup OR ext:old OR ext:zip'),
        ("Exposed credentials",            f'site:{domain} "password" OR "passwd" OR "credentials" filetype:txt'),
        ("Login portals",                  f'site:{domain} inurl:login OR inurl:admin OR inurl:signin'),
        ("API endpoints",                  f'site:{domain} inurl:api OR inurl:v1 OR inurl:v2'),
        ("Subdomains via Google",          f'site:*.{domain}'),
        ("phpMyAdmin panels",              f'site:{domain} inurl:phpmyadmin'),
        ("WordPress wp-admin",             f'site:{domain} inurl:wp-admin'),
        ("Error messages",                 f'site:{domain} "sql syntax" OR "stack trace" OR "fatal error"'),
        ("Email addresses on site",        f'site:{domain} "@{domain}"'),
        ("Documents (PDF/DOCX)",           f'site:{domain} ext:pdf OR ext:docx OR ext:xlsx'),
        ("Camera/CCTV feeds",             f'site:{domain} inurl:view/index.shtml'),
        ("GitLab/GitHub exposure",         f'"{domain}" site:github.com OR site:gitlab.com'),
        ("Pastebin leaks",                 f'"{domain}" site:pastebin.com'),
        ("Cache of removed pages",         f'cache:{domain}'),
        ("LinkedIn employees",             f'site:linkedin.com "{domain}" employees'),
    ]

    if target_type == "email":
        base += [
            ("Email on paste sites",       f'"{target}" site:pastebin.com OR site:ghostbin.com'),
            ("Email mentions",             f'"{target}"'),
        ]
    elif target_type == "username":
        base = [
            ("Username across web",        f'"{target}"'),
            ("GitHub profile",             f'site:github.com "{target}"'),
            ("Paste sites",                f'"{target}" site:pastebin.com'),
            ("Forum activity",             f'"{target}" site:reddit.com OR site:stackoverflow.com'),
        ]

    for desc, dork in base:
        encoded = urllib.parse.quote_plus(dork)
        dorks.append({
            "description": desc,
            "dork":        dork,
            "url":         f"https://www.google.com/search?q={encoded}",
        })

    return dorks


# ─────────────────────────────────────────────
# 14. METADATA / HASH INFO (files)
# ─────────────────────────────────────────────
def compute_hashes(filepath: str) -> dict:
    hashes = {}
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        hashes["MD5"]    = hashlib.md5(data).hexdigest()
        hashes["SHA1"]   = hashlib.sha1(data).hexdigest()
        hashes["SHA256"] = hashlib.sha256(data).hexdigest()
        hashes["size"]   = len(data)
    except Exception as e:
        hashes["error"] = str(e)
    return hashes


# ─────────────────────────────────────────────
# 15. REPORT EXPORT
# ─────────────────────────────────────────────
def save_report(data: dict, filename: str = None) -> str:
    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = re.sub(r"[^\w\-.]", "_", data.get("target", "unknown"))
        filename = f"osint_report_{target_safe}_{ts}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return filename


# ─────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────
def display_dns(records: dict):
    if not records:
        warn("No DNS records found")
        return
    for rtype, values in records.items():
        for v in values:
            info(rtype, v, C.GREEN)


def display_whois(whois_data: dict):
    parsed = whois_data.get("parsed", {})
    if not parsed:
        warn("No WHOIS data parsed")
        return
    for key, val in parsed.items():
        if isinstance(val, list):
            for v in val:
                info(key, v)
        else:
            info(key, str(val))


def display_geo(geo: dict):
    if geo.get("status") != "success":
        warn(f"GeoIP failed: {geo.get('message', 'unknown')}")
        return
    info("Country",      geo.get("country", "N/A"))
    info("Region",       geo.get("regionName", "N/A"))
    info("City",         geo.get("city", "N/A"))
    info("ZIP",          geo.get("zip", "N/A"))
    info("Coordinates",  f"{geo.get('lat')}, {geo.get('lon')}")
    info("Timezone",     geo.get("timezone", "N/A"))
    info("ISP",          geo.get("isp", "N/A"), C.YELLOW)
    info("Organization", geo.get("org", "N/A"), C.YELLOW)
    info("AS",           geo.get("as", "N/A"), C.YELLOW)
    flags = []
    if geo.get("proxy"): flags.append("PROXY")
    if geo.get("hosting"): flags.append("HOSTING/DC")
    if geo.get("mobile"): flags.append("MOBILE")
    if flags:
        info("Flags", " | ".join(flags), C.ORANGE)


def display_ports(ports: list):
    if not ports:
        warn("No open ports found")
        return
    for p in ports:
        color = C.RED if p["service"] in ("RDP","Telnet","FTP") else C.GREEN
        banner = p.get("banner", "")
        line = f"{p['port']}/tcp  →  {p['service']}"
        if banner:
            line += f"  [{C.DIM}{banner[:60]}{C.RESET}{color}]"
        info(str(p["port"]), f"{p['service']}", color)


def display_ssl(ssl_info: dict):
    if "error" in ssl_info:
        warn(f"SSL error: {ssl_info['error']}")
        return
    subj = ssl_info.get("subject", {})
    info("Common Name",  subj.get("commonName", "N/A"))
    iss  = ssl_info.get("issuer", {})
    info("Issuer",       iss.get("organizationName", "N/A"))
    info("Not Before",   ssl_info.get("not_before", "N/A"))
    info("Not After",    ssl_info.get("not_after", "N/A"), C.YELLOW)
    info("Protocol",     ssl_info.get("protocol", "N/A"))
    info("Cipher",       ssl_info.get("cipher", "N/A"))
    sans = ssl_info.get("san", [])
    if sans:
        info("SANs", f"{len(sans)} entries", C.CYAN)
        for s in sans[:8]:
            print(f"    {C.DIM}{s}{C.RESET}")
        if len(sans) > 8:
            print(f"    {C.DIM}... +{len(sans)-8} more{C.RESET}")


def display_http(http: dict):
    if "error" in http:
        warn(f"HTTP error: {http['error']}")
        return
    info("Status Code",  str(http.get("status", "N/A")),
         C.GREEN if http.get("status", 0) == 200 else C.YELLOW)
    if http.get("title"):
        info("Page Title",   http["title"])
    if http.get("redirect"):
        info("Redirect",     http["redirect"], C.YELLOW)
    if http.get("technologies"):
        info("Technologies", ", ".join(http["technologies"]), C.CYAN)
    sec_headers = ["Strict-Transport-Security","Content-Security-Policy",
                   "X-Frame-Options","X-XSS-Protection","X-Content-Type-Options",
                   "Referrer-Policy","Permissions-Policy"]
    found_sec = []
    for h in sec_headers:
        if h.lower() in {k.lower(): v for k,v in http.get("headers",{}).items()}:
            found_sec.append(h)
    missing = [h for h in sec_headers if h not in found_sec]
    if found_sec:
        info("Security Headers", f"{len(found_sec)}/{len(sec_headers)} present", C.GREEN)
    if missing:
        info("Missing Headers",  ", ".join(h.split("-")[-1] for h in missing[:3]), C.RED)
    interesting = ["Server","X-Powered-By","Via","CF-RAY","X-Amz-Cf-Id","X-Cache"]
    headers_lc = {k.lower(): v for k, v in http.get("headers", {}).items()}
    for h in interesting:
        val = headers_lc.get(h.lower())
        if val:
            info(h, val, C.ORANGE)
    # Meta
    for key in ["description","keywords","author","generator"]:
        val = http.get("meta", {}).get(key)
        if val:
            info(f"Meta:{key}", val[:100], C.GRAY)


def display_subdomains(subs: list):
    if not subs:
        warn("No subdomains discovered")
        return
    for s in subs:
        info(s["subdomain"], s["ip"], C.CYAN)


def display_usernames(results: list):
    found = [r for r in results if r["status"] == "FOUND"]
    other = [r for r in results if r["status"] != "FOUND"]
    for r in found:
        print(f"  {C.GREEN}✓{C.RESET}  {C.BOLD}{r['site']:<18}{C.RESET} {C.DIM}{r['url']}{C.RESET}")
    for r in other:
        color = C.GRAY
        sym = "✗"
        print(f"  {color}{sym}{C.RESET}  {C.GRAY}{r['site']:<18} {r['status']}{C.RESET}")


def display_dorks(dorks: list, limit=10):
    for d in dorks[:limit]:
        print(f"  {C.CYAN}❯{C.RESET}  {C.BOLD}{d['description']:<35}{C.RESET}")
        print(f"      {C.DIM}{d['dork']}{C.RESET}")
        print(f"      {C.BLUE}{d['url']}{C.RESET}")
        print()


# ─────────────────────────────────────────────
#  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────
def run_domain_recon(target_info: dict, report: dict, opts: dict):
    domain = target_info["value"]
    # Resolve IPs
    try:
        ips = socket.gethostbyname_ex(domain)[2]
    except Exception:
        ips = []
    if ips:
        section("IP Resolution")
        for ip in ips:
            info("Resolved IP", ip, C.GREEN)
        report["ips"] = ips
    primary_ip = ips[0] if ips else None

    # DNS
    section("DNS Enumeration")
    dns_data = spinner_task("Querying DNS records", full_dns_enum, domain)
    display_dns(dns_data)
    report["dns"] = dns_data

    # WHOIS
    section("WHOIS Lookup")
    whois_data = spinner_task("Fetching WHOIS", whois_lookup, domain)
    display_whois(whois_data)
    report["whois"] = whois_data["parsed"]

    # GeoIP
    if primary_ip:
        section("GeoIP Intelligence")
        geo = spinner_task(f"Geolocating {primary_ip}", geoip, primary_ip)
        display_geo(geo)
        report["geoip"] = geo

    # ASN
    if primary_ip:
        section("ASN / BGP")
        asn = spinner_task("ASN lookup", asn_lookup, primary_ip)
        if asn:
            for k, v in asn.items():
                info(k.upper(), v, C.YELLOW)
        report["asn"] = asn

    # Reverse IP
    if primary_ip and opts.get("reverse_ip"):
        section("Reverse IP Lookup")
        rev = spinner_task("Reverse IP", reverse_ip_lookup, primary_ip)
        info("Hosted domains", str(len(rev)))
        for d in rev[:15]:
            print(f"  {C.GRAY}  {d}{C.RESET}")
        report["reverse_ip"] = rev

    # SSL
    section("SSL / TLS Certificate")
    ssl_data = spinner_task("Fetching SSL cert", get_ssl_info, domain)
    display_ssl(ssl_data)
    report["ssl"] = ssl_data

    # HTTP
    section("HTTP Recon & Tech Stack")
    http_data = spinner_task("HTTP fingerprinting", http_recon, domain)
    display_http(http_data)
    report["http"] = http_data

    # Port scan
    if opts.get("portscan") and primary_ip:
        section("Port Scan (Top Ports)")
        open_ports = spinner_task("Scanning ports", port_scan, primary_ip)
        # Grab banners
        for p in open_ports:
            p["banner"] = grab_banner(primary_ip, p["port"])
        display_ports(open_ports)
        report["ports"] = open_ports

    # Subdomain enum
    if opts.get("subdomains"):
        section("Subdomain Enumeration")
        subs = spinner_task("Brute-forcing subdomains", subdomain_enum, domain)
        display_subdomains(subs)
        report["subdomains"] = subs

    # Google dorks
    section("Google Dorks")
    dorks = generate_dorks(domain, "domain")
    display_dorks(dorks)
    report["dorks"] = dorks


def run_ip_recon(target_info: dict, report: dict, opts: dict):
    ip = target_info["value"]

    section("IP Classification")
    info("Target", ip)
    info("Version", "IPv6" if target_info["type"] == "ipv6" else "IPv4")
    info("Private", str(target_info.get("is_private", False)),
         C.YELLOW if target_info.get("is_private") else C.GREEN)

    section("GeoIP Intelligence")
    geo = spinner_task("Geolocating IP", geoip, ip)
    display_geo(geo)
    report["geoip"] = geo

    section("ASN / BGP")
    asn = spinner_task("ASN lookup", asn_lookup, ip)
    if asn:
        for k, v in asn.items():
            info(k.upper(), v, C.YELLOW)
    report["asn"] = asn

    if opts.get("reverse_ip"):
        section("Reverse IP Lookup")
        rev = spinner_task("Reverse IP", reverse_ip_lookup, ip)
        info("Hosted domains", str(len(rev)))
        for d in rev[:20]:
            print(f"    {C.GRAY}{d}{C.RESET}")
        report["reverse_ip"] = rev

    if opts.get("portscan"):
        section("Port Scan")
        open_ports = spinner_task("Scanning ports", port_scan, ip)
        for p in open_ports:
            p["banner"] = grab_banner(ip, p["port"])
        display_ports(open_ports)
        report["ports"] = open_ports

    section("PTR / Reverse DNS")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        info("PTR Record", hostname)
        report["ptr"] = hostname
    except Exception:
        warn("No PTR record found")


def run_email_recon(target_info: dict, report: dict, opts: dict):
    email  = target_info["value"]
    domain = target_info["domain"]

    section("Email Analysis")
    info("Email",  email)
    info("Domain", domain)

    # Domain DNS / MX
    section("Mail Server DNS")
    dns_data = spinner_task("Querying MX / SPF / DMARC", lambda d: {
        "MX":  dns_query(d, "MX"),
        "SPF": [r for r in dns_query(d, "TXT") if "spf" in r.lower()],
        "DMARC": dns_query(f"_dmarc.{d}", "TXT"),
        "DKIM":  dns_query(f"default._domainkey.{d}", "TXT"),
    }, domain)

    for rtype, vals in dns_data.items():
        for v in vals:
            info(rtype, v[:100])
    report["mail_dns"] = dns_data

    # Email reputation
    section("Email Reputation")
    rep = spinner_task("Checking email reputation", check_email_hunter, email)
    if "error" not in rep:
        info("Reputation",    str(rep.get("reputation", "N/A")))
        info("Suspicious",    str(rep.get("suspicious", "N/A")),
             C.RED if rep.get("suspicious") else C.GREEN)
        info("References",    str(rep.get("references", 0)))
        details = rep.get("details", {})
        for k, v in details.items():
            info(k.replace("_", " ").title(), str(v))
    else:
        warn(rep["error"])
    report["email_reputation"] = rep

    # Dorks
    section("Google Dorks")
    dorks = generate_dorks(email, "email")
    display_dorks(dorks, limit=8)
    report["dorks"] = dorks


def run_username_recon(target_info: dict, report: dict, opts: dict):
    username = target_info["value"]

    section("Username Intelligence")
    info("Username", username)

    section("Social Media Presence")
    results = spinner_task("Checking platforms", username_search, username)
    display_usernames(results)
    report["username_results"] = results

    found = [r for r in results if r["status"] == "FOUND"]
    print(f"\n  {C.BOLD}{C.GREEN}{len(found)}{C.RESET} / {len(results)} platforms detected")

    section("Google Dorks")
    dorks = generate_dorks(username, "username")
    display_dorks(dorks, limit=6)
    report["dorks"] = dorks


# ─────────────────────────────────────────────
#  INTERACTIVE MENU
# ─────────────────────────────────────────────
def get_options() -> dict:
    print(f"\n{C.BOLD}{C.WHITE}  Scan Options:{C.RESET}")
    print(f"  {C.GRAY}[p]{C.RESET} Port Scan  "
          f"{C.GRAY}[s]{C.RESET} Subdomain Enum  "
          f"{C.GRAY}[r]{C.RESET} Reverse IP  "
          f"{C.GRAY}[a]{C.RESET} All")
    choice = input(f"\n  {C.CYAN}Options{C.RESET} {C.DIM}(default: basic){C.RESET} > ").strip().lower()
    return {
        "portscan":   "p" in choice or "a" in choice,
        "subdomains": "s" in choice or "a" in choice,
        "reverse_ip": "r" in choice or "a" in choice,
    }


def main():
    banner()

    # Disclaimer
    print(f"{C.RED}{C.BOLD}  ⚠  LEGAL NOTICE{C.RESET}")
    print(f"  {C.DIM}This tool is for authorized security testing and research only.")
    print(f"  Unauthorized use against systems you do not own is illegal.{C.RESET}\n")

    while True:
        target_raw = input(f"  {C.CYAN}Target{C.RESET} {C.DIM}(domain/IP/email/username){C.RESET} > ").strip()
        if not target_raw:
            continue

        # Classify
        target_info = classify_target(target_raw)
        ttype = target_info["type"]

        print(f"\n  {C.BOLD}Target:{C.RESET} {C.YELLOW}{target_info['value']}{C.RESET}  "
              f"{C.DIM}[{ttype}]{C.RESET}")

        opts = get_options()

        report = {
            "target":      target_info["value"],
            "target_type": ttype,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "options":     opts,
        }

        start = time.time()

        try:
            if ttype in ("domain", "url"):
                run_domain_recon(target_info, report, opts)
            elif ttype in ("ip", "ipv6"):
                run_ip_recon(target_info, report, opts)
            elif ttype == "email":
                run_email_recon(target_info, report, opts)
            elif ttype == "username":
                run_username_recon(target_info, report, opts)
            elif ttype == "cidr":
                section("CIDR Info")
                info("Network",   target_info["network"])
                info("Addresses", str(target_info["num_hosts"]))
                warn("For full CIDR scan, use individual IPs from this range.")
            else:
                warn(f"Unsupported target type: {ttype}")
        except KeyboardInterrupt:
            print(f"\n  {C.YELLOW}Scan interrupted by user{C.RESET}")

        elapsed = time.time() - start
        section("Summary")
        info("Elapsed",   f"{elapsed:.1f}s")
        info("Target",    target_info["value"])
        info("Modules",   str(len([k for k in report if k not in ("target","target_type","timestamp","options")])))

        # Save report
        save_q = input(f"\n  {C.CYAN}Save report?{C.RESET} {C.DIM}[y/N]{C.RESET} > ").strip().lower()
        if save_q == "y":
            fname = save_report(report)
            ok(f"Report saved: {fname}")

        print()
        again = input(f"  {C.CYAN}New scan?{C.RESET} {C.DIM}[Y/n]{C.RESET} > ").strip().lower()
        if again == "n":
            break
        print()

    print(f"\n  {C.GRAY}Phantom OSINT — Session ended.{C.RESET}\n")


if __name__ == "__main__":
    # Suppress SSL warnings
    import warnings
    warnings.filterwarnings("ignore")
    try:
        import urllib3
        urllib3.disable_warnings()
    except ImportError:
        pass
    main()
