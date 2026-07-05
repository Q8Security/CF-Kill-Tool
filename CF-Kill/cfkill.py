#!/usr/bin/env python3
"""
CloudFlare Real IP Extractor
Made by Q8 - Security
"""

import argparse, asyncio, ipaddress, json, re, signal, sys, time
from dataclasses import dataclass, field
from enum import Enum
from typing import List

try:
    import aiohttp, dns.resolver
except ImportError:
    print("[!] pip3 install aiohttp dnspython colorama")
    sys.exit(1)

from colorama import init, Fore, Style
init(autoreset=True)

# ==================== BANNER ====================
BANNER = r"""
  ░██████  ░██████████        ░██     ░██ ░██░██ ░██ 
 ░██   ░██ ░██                ░██    ░██     ░██ ░██ 
░██        ░██                ░██   ░██   ░██░██ ░██ 
░██        ░█████████ ░██████ ░███████    ░██░██ ░██ 
░██        ░██                ░██   ░██   ░██░██ ░██ 
 ░██   ░██ ░██                ░██    ░██  ░██░██ ░██ 
  ░██████  ░██                ░██     ░██ ░██░██ ░██ 
                                                                                                                                                                                             
# By : Q8 - Security 
# Check Cloud Flare
# Extract IP's with 18 way  
# Verfiy Real IP 
# Mail : LS@Hotmail.com
"""

# ==================== FILTERS ====================
PRIVATE_CF = [
    ipaddress.IPv4Network(n) for n in [
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
        '169.254.0.0/16', '100.64.0.0/10',
        '104.16.0.0/12', '172.64.0.0/13', '188.114.96.0/20', '162.158.0.0/15',
        '173.245.48.0/20', '141.101.64.0/18', '198.41.128.0/17', '108.162.192.0/18'
    ]
]

def is_valid_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        if addr.compressed.startswith("1."):
            return False
        return not any(addr in net for net in PRIVATE_CF)
    except:
        return False

class Confidence(Enum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1

@dataclass
class Finding:
    ip: str
    sources: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW

    def merge(self, source: str, conf: Confidence):
        if source not in self.sources:
            self.sources.append(source)
        if conf.value > self.confidence.value:
            self.confidence = conf

# ==================== RESOLVER + HTTP ====================
class ResolverPool:
    def __init__(self):
        self.pool = []
        prov = [['8.8.8.8', '8.8.4.4'], ['1.1.1.1', '1.0.0.1'], ['9.9.9.9']]
        for i in range(18):
            r = dns.resolver.Resolver()
            r.nameservers = prov[i % 3]
            r.timeout = 1.6
            r.lifetime = 2.2
            self.pool.append(r)
        self.idx = 0

    async def resolve(self, name, rdtype):
        for _ in range(2):
            r = self.pool[self.idx % len(self.pool)]
            self.idx += 1
            try:
                ans = await asyncio.get_running_loop().run_in_executor(None, r.resolve, name, rdtype)
                return [str(x) for x in ans]
            except:
                await asyncio.sleep(0.08)
        return []

class HTTP:
    def __init__(self):
        self._session = None
        self.sem = asyncio.Semaphore(70)

    async def get_session(self):
        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=14),
                connector=aiohttp.TCPConnector(limit=70, ssl=False),
                headers={"User-Agent": "Mozilla/5.0"}
            )
        return self._session

    async def get(self, url, headers=None):
        async with self.sem:
            try:
                sess = await self.get_session()
                return await sess.get(url, headers=headers or {})
            except:
                return None

    async def close(self):
        if self._session:
            await self._session.close()

# ==================== CLOUD FLARE CHECK ====================
async def is_behind_cloudflare(domain):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as s:
            async with s.get(f"https://{domain}", ssl=False) as r:
                h = r.headers
                return "CF-Ray" in h or "CF-Cache-Status" in h or "cloudflare" in h.get("Server", "").lower()
    except:
        return True

# ==================== VERIFICATION ====================
async def verify_ip(ip, domain, http):
    result = {"ip": ip, "is_real": False, "reason": "No strong indicator"}
    resp = await http.get(f"http://{ip}", headers={"Host": domain})
    if not resp:
        result["reason"] = "No response"
        return result

    server = resp.headers.get("Server", "").lower()
    if resp.headers.get("CF-Ray") or resp.headers.get("CF-Cache-Status") or "cloudflare" in server:
        result["reason"] = "Still behind Cloudflare"
        return result

    if any(x in server for x in ["nginx", "apache", "litespeed", "openresty", "caddy"]):
        result["is_real"] = True
        result["reason"] = f"Server: {server}"
        return result

    try:
        content = await resp.text()
        if len(content) > 950:
            result["is_real"] = True
            result["reason"] = "Large content response"
    except:
        pass
    return result

# ==================== METHODS ====================

# HIGH CONFIDENCE
async def spf(domain, res):
    out = []
    for txt in await res.resolve(domain, "TXT"):
        if "v=spf1" not in txt: continue
        for m in re.finditer(r"ip4:(\S+)", txt):
            ip = m.group(1).split("/")[0]
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=["SPF"], confidence=Confidence.HIGH))
    return out

async def mx(domain, res):
    out = []
    for mx in await res.resolve(domain, "MX"):
        host = mx.split()[-1].rstrip(".")
        for ip in await res.resolve(host, "A"):
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=["MX"], confidence=Confidence.HIGH))
    return out

async def direct_a(domain, res):
    out = []
    for ip in await res.resolve(domain, "A"):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["Direct A"], confidence=Confidence.HIGH))
    return out

# MEDIUM CONFIDENCE
async def crtsh(domain, res, http):
    out = []
    resp = await http.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not resp: return out
    try:
        data = json.loads(await resp.text())
        subs = {n.strip().lstrip("*.").lower() for e in data for n in (e.get("name_value", "") or "").split("\n") if n.endswith(domain)}
        for sub in list(subs)[:60]:
            for ip in await res.resolve(sub, "A"):
                if is_valid_ip(ip):
                    out.append(Finding(ip=ip, sources=["crt.sh"], confidence=Confidence.MEDIUM))
    except: pass
    return out

async def rapiddns(domain, http):
    out = []
    resp = await http.get(f"https://rapiddns.io/subdomain/{domain}?full=1")
    if not resp: return out
    for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+)', await resp.text()):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["RapidDNS"], confidence=Confidence.MEDIUM))
    return out

async def hackertarget(domain, http):
    out = []
    resp = await http.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not resp: return out
    for line in (await resp.text()).splitlines():
        if "," in line:
            ip = line.split(",")[1].strip()
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=["HackerTarget"], confidence=Confidence.MEDIUM))
    return out

async def viewdns(domain, http):
    out = []
    resp = await http.get(f"https://viewdns.info/reverseip/?host={domain}&t=1")
    if not resp: return out
    for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+)', await resp.text()):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["ViewDNS"], confidence=Confidence.MEDIUM))
    return out

async def securitytrails(domain, http):
    out = []
    resp = await http.get(f"https://securitytrails.com/domain/{domain}/dns/history/a")
    if not resp: return out
    for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+)', await resp.text()):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["SecurityTrails"], confidence=Confidence.MEDIUM))
    return out

async def alienvault(domain, http):
    out = []
    resp = await http.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    if not resp: return out
    try:
        data = json.loads(await resp.text())
        for r in data.get("passive_dns", []):
            ip = r.get("address", "")
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=["AlienVault"], confidence=Confidence.MEDIUM))
    except: pass
    return out

async def threatcrowd(domain, http):
    out = []
    resp = await http.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report?domain={domain}")
    if not resp: return out
    try:
        data = json.loads(await resp.text())
        for r in data.get("resolutions", []):
            ip = r.get("ip_address", "")
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=["ThreatCrowd"], confidence=Confidence.MEDIUM))
    except: pass
    return out

async def dnsdumpster(domain, http):
    out = []
    resp = await http.get("https://dnsdumpster.com/")
    if not resp: return out
    for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+)', await resp.text()):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["DNSDumpster"], confidence=Confidence.MEDIUM))
    return out

async def urlscan(domain, http):
    out = []
    resp = await http.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
    if not resp: return out
    try:
        data = json.loads(await resp.text())
        for r in data.get("results", []):
            ip = r.get("page", {}).get("ip", "")
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=["URLScan"], confidence=Confidence.MEDIUM))
    except: pass
    return out

# LOW CONFIDENCE
async def subdomain_brute(domain, res):
    out = []
    subs = ["mail", "direct", "origin", "cpanel", "whm", "webmail", "ftp", "dev", "staging", "ns1", "ns2", "api", "cdn"]
    for sub in subs:
        for ip in await res.resolve(f"{sub}.{domain}", "A"):
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=[f"Sub:{sub}"], confidence=Confidence.LOW))
    return out

async def wayback(domain, http):
    out = []
    resp = await http.get(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&limit=40")
    if not resp: return out
    for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+)', await resp.text()):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["Wayback"], confidence=Confidence.LOW))
    return out

async def dnshistory(domain, http):
    out = []
    resp = await http.get(f"https://dnshistory.org/dns-records/{domain}")
    if not resp: return out
    for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+)', await resp.text()):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["DNSHistory"], confidence=Confidence.LOW))
    return out

async def ns_records(domain, res):
    out = []
    for ns in await res.resolve(domain, "NS"):
        for ip in await res.resolve(ns.rstrip("."), "A"):
            if is_valid_ip(ip):
                out.append(Finding(ip=ip, sources=["NS Record"], confidence=Confidence.LOW))
    return out

async def robtex(domain, http):
    out = []
    resp = await http.get(f"https://www.robtex.com/dns-lookup/{domain}")
    if not resp: return out
    for ip in re.findall(r'(\d+\.\d+\.\d+\.\d+)', await resp.text()):
        if is_valid_ip(ip):
            out.append(Finding(ip=ip, sources=["Robtex"], confidence=Confidence.LOW))
    return out

# ==================== ENGINE ====================
async def discover(domain):
    resolver = ResolverPool()
    http = HTTP()

    methods = [
        spf(domain, resolver), mx(domain, resolver), direct_a(domain, resolver),
        crtsh(domain, resolver, http), rapiddns(domain, http), hackertarget(domain, http),
        viewdns(domain, http), securitytrails(domain, http), alienvault(domain, http),
        threatcrowd(domain, http), dnsdumpster(domain, http), urlscan(domain, http),
        subdomain_brute(domain, resolver), wayback(domain, http), dnshistory(domain, http),
        ns_records(domain, resolver), robtex(domain, http),
    ]

    results = await asyncio.gather(*methods, return_exceptions=True)
    await http.close()

    findings = {}
    for res in results:
        if isinstance(res, list):
            for f in res:
                if f.ip not in findings:
                    findings[f.ip] = f
                else:
                    for src in f.sources:
                        findings[f.ip].merge(src, f.confidence)
    return findings

# ==================== OUTPUT ====================
def print_results(findings, domain, elapsed):
    print(f"\n{Fore.CYAN}┌──── CloudFlare IP Extractor v12.3 ───────────────┐")
    print(f"│ Domain : {domain:<40}│")
    print(f"│ Time   : {elapsed:.2f}s{' ' * 36}│")
    print(f"│ Found  : {len(findings)} IP(s){' ' * 36}│")
    print(f"└────────────────────────────────────────────────────┘\n")

    high = [f for f in findings.values() if f.confidence == Confidence.HIGH]
    medium = [f for f in findings.values() if f.confidence == Confidence.MEDIUM]
    low = [f for f in findings.values() if f.confidence == Confidence.LOW]

    if high:
        print(f"{Fore.GREEN}HIGH CONFIDENCE ({len(high)}):{Style.RESET_ALL}")
        for f in high:
            print(f"  {Fore.GREEN}►{Style.RESET_ALL} {f.ip}  ({len(f.sources)} sources)")

    if medium:
        print(f"\n{Fore.YELLOW}MEDIUM CONFIDENCE ({len(medium)}):{Style.RESET_ALL}")
        for f in medium:
            print(f"  {f.ip}  ({len(f.sources)} sources)")

    if low:
        print(f"\n{Fore.MAGENTA}LOW CONFIDENCE ({len(low)}):{Style.RESET_ALL}")
        for f in low:
            print(f"  {f.ip}")

    return sorted(findings.values(), key=lambda x: -len(x.sources))

# ==================== MAIN ====================
async def main():
    print(Fore.RED + BANNER + Style.RESET_ALL)

    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?", default=None)
    args = parser.parse_args()

    if not args.domain:
        print(f"{Fore.RED}Usage: python3 cfkill.py http://domain.com{Style.RESET_ALL}")
        sys.exit(1)

    domain = re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0]

    if not await is_behind_cloudflare(domain):
        print(f"{Fore.GREEN}This site is NOT behind Cloudflare.{Style.RESET_ALL}")
        return

    start = time.time()
    findings = await discover(domain)
    elapsed = time.time() - start

    sorted_findings = print_results(findings, domain, elapsed)

    choice = input(f"\n{Fore.YELLOW}Run verification on ALL IPs? (Y/n): {Style.RESET_ALL}").strip().lower()
    if choice in ["n", "no"]:
        return

    http = HTTP()
    real = []
    for f in sorted_findings:
        r = await verify_ip(f.ip, domain, http)
        if r["is_real"]:
            print(f"{Fore.GREEN}✓ REAL IP → {f.ip}   ({r['reason']}){Style.RESET_ALL}")
            real.append(f.ip)
        else:
            print(f"{Fore.RED}✗ {f.ip} → {r['reason']}{Style.RESET_ALL}")
    await http.close()

    if real:
        print(f"\n{Fore.GREEN}=== Confirmed Real Origin IPs ==={Style.RESET_ALL}")
        for ip in real:
            print(f"  {Fore.GREEN}►{Style.RESET_ALL} {ip}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(1))
    asyncio.run(main())