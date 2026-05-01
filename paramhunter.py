#!/usr/bin/env python3
"""
ParamHunter - Parameter Discovery Tool
By: @cybermindspace
Purpose: Bug bounty recon - find hidden parameters on web targets
"""

import argparse
import requests
import threading
import sys
import time
import json
import re
import random
from queue import Queue
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
G  = "\033[92m"   # green
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
C  = "\033[96m"   # cyan
M  = "\033[95m"   # magenta
W  = "\033[97m"   # white
DIM= "\033[2m"
RST= "\033[0m"
B  = "\033[1m"

BANNER = f"""
{C}╔═══════════════════════════════════════════════════════╗
║  {G}{B}██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗{C}         ║
║  {G}{B}██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║{C}         ║
║  {G}{B}██████╔╝███████║██████╔╝███████║██╔████╔██║{C}         ║
║  {G}{B}██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║{C}         ║
║  {G}{B}██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║{C}         ║
║  {G}{B}╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝{C}         ║
║        {Y}H U N T E R  —  Parameter Discovery{C}         ║
║        {DIM}@cybermindspace · Bug Bounty Recon{C}            ║
╚═══════════════════════════════════════════════════════╝{RST}
"""

# ─── Built-in Parameter Wordlist ──────────────────────────────────────────────
BUILTIN_PARAMS = [
    # Common
    "id","page","query","search","q","s","url","path","file","dir","folder",
    "name","user","username","email","token","key","api_key","apikey","secret",
    "password","pass","pwd","auth","access_token","refresh_token","session",
    "csrf","nonce","hash","sig","signature","redirect","return","next","back",
    "callback","format","type","action","method","cmd","command","exec","run",
    "debug","test","dev","admin","config","conf","setting","settings","option",
    "lang","locale","language","country","region","currency","timezone",
    # File/Path
    "file","filename","filepath","path","dir","folder","document","doc","pdf",
    "image","img","photo","pic","video","media","download","upload","source",
    "src","dest","destination","target","output","input","data","content",
    # Network
    "host","hostname","ip","domain","port","server","proxy","endpoint","uri",
    "link","href","ref","referrer","origin","site","web","www",
    # Pagination
    "page","p","pg","limit","offset","start","end","from","to","size","per_page",
    "count","num","number","total","max","min","sort","order","orderby","asc","desc",
    # API
    "api","version","v","ver","app","appid","app_id","client","client_id",
    "scope","grant_type","response_type","state","code","error","message",
    # Misc
    "date","time","timestamp","created","updated","expires","ttl","cache",
    "category","tag","label","group","parent","child","level","depth","mode",
    "view","template","theme","layout","style","skin","color","size","width",
    "height","verbose","log","trace","profile","report","export","import",
    "backup","restore","reset","reload","refresh","flush","clear","purge",
    "ping","check","status","health","info","about","help","docs","ref",
    "preview","draft","publish","archive","delete","remove","update","create",
    "add","edit","modify","save","submit","send","post","get","put","patch",
    "payload","body","raw","json","xml","csv","text","html","output","result",
    # Security testing relevant
    "returnUrl","redirectUrl","next_url","forward","location","goto","jump",
    "include","require","load","fetch","request","response","param","args",
    "argv","arg","value","val","var","variable","field","column","row","entry",
]

# ─── User Agents ─────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
]

# ─── Result Storage ───────────────────────────────────────────────────────────
found_params   = []
results_lock   = threading.Lock()
request_count  = 0
req_lock       = threading.Lock()

def log(level, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {
        "FOUND": f"{G}[FOUND]{RST}",
        "INFO" : f"{C}[INFO]{RST}",
        "WARN" : f"{Y}[WARN]{RST}",
        "ERROR": f"{R}[ERROR]{RST}",
        "SCAN" : f"{M}[SCAN]{RST}",
    }.get(level, f"[{level}]")
    print(f"{DIM}{ts}{RST} {prefix} {msg}")

def make_session(delay=0):
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    return s

def increment_req():
    global request_count
    with req_lock:
        request_count += 1

# ─── Extract params from HTML response ────────────────────────────────────────
def extract_params_from_html(html):
    params = set()
    # input name attributes
    params.update(re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I))
    # form action params
    for url in re.findall(r'action=["\']([^"\']+)["\']', html, re.I):
        parsed = urlparse(url)
        params.update(parse_qs(parsed.query).keys())
    # anchor href params
    for url in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
        try:
            parsed = urlparse(url)
            params.update(parse_qs(parsed.query).keys())
        except:
            pass
    # JavaScript variable names / fetch calls
    params.update(re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', html))
    # JSON keys
    params.update(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})":\s*["\d\[{]', html))
    return {p for p in params if 2 <= len(p) <= 40}

# ─── Baseline request ─────────────────────────────────────────────────────────
def get_baseline(session, url, method, timeout):
    try:
        if method == "GET":
            r = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
        else:
            r = session.post(url, timeout=timeout, allow_redirects=True, verify=False)
        increment_req()
        return r.status_code, len(r.text), r.text
    except Exception as e:
        return None, None, None

# ─── Single param probe ───────────────────────────────────────────────────────
def probe_param(session, url, param, method, baseline_len, baseline_status, timeout, delay, fuzz_value):
    try:
        if delay > 0:
            time.sleep(delay)
        
        test_value = fuzz_value or f"paramhunter_{param}_test"
        
        if method == "GET":
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={test_value}"
            r = session.get(test_url, timeout=timeout, allow_redirects=True, verify=False)
        else:
            r = session.post(url, data={param: test_value}, timeout=timeout,
                           allow_redirects=True, verify=False)
        
        increment_req()
        
        resp_len    = len(r.text)
        status      = r.status_code
        len_diff    = abs(resp_len - baseline_len)
        status_diff = (status != baseline_status)
        
        # Detection heuristics
        is_interesting = False
        reason = []
        
        # Response length changed significantly
        if len_diff > 50:
            is_interesting = True
            reason.append(f"len_diff={len_diff}")
        
        # Status code changed
        if status_diff and status not in [404, 400]:
            is_interesting = True
            reason.append(f"status={baseline_status}→{status}")
        
        # Param name reflected in response
        if param in r.text and param not in url:
            is_interesting = True
            reason.append("reflected")
        
        # Value reflected
        if test_value in r.text:
            is_interesting = True
            reason.append("value_reflected")
        
        # Error keywords — param might be valid but erroring
        error_keywords = ["invalid", "required", "missing", "expected", "parameter",
                         "field", "cannot be empty", "is required", "not found"]
        if any(kw in r.text.lower() for kw in error_keywords):
            is_interesting = True
            reason.append("error_keyword")
        
        if is_interesting:
            return param, status, resp_len, ", ".join(reason)
        
        return None, None, None, None

    except requests.exceptions.Timeout:
        return None, None, None, None
    except Exception:
        return None, None, None, None

# ─── JS file param extractor ──────────────────────────────────────────────────
def extract_from_js(session, base_url, timeout):
    js_params = set()
    try:
        r = session.get(base_url, timeout=timeout, verify=False)
        increment_req()
        
        # Find JS file URLs
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I)
        
        for js_path in js_urls[:10]:  # limit to 10 JS files
            try:
                if js_path.startswith("http"):
                    js_url = js_path
                else:
                    js_url = urljoin(base_url, js_path)
                
                js_r = session.get(js_url, timeout=timeout, verify=False)
                increment_req()
                
                # Extract param patterns from JS
                js_params.update(re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', js_r.text))
                js_params.update(re.findall(r'params\[["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']\]', js_r.text))
                js_params.update(re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]{1,30})\s*=\s*["\']', js_r.text))
                js_params.update(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})":\s*(?:true|false|null|\d)', js_r.text))
                
            except:
                continue
    except:
        pass
    
    return {p for p in js_params if 2 <= len(p) <= 40}

# ─── Main scan ────────────────────────────────────────────────────────────────
def run_scan(args):
    requests.packages.urllib3.disable_warnings()
    
    print(BANNER)
    
    target = args.url
    if not target.startswith("http"):
        target = "https://" + target
    
    method    = args.method.upper()
    threads   = args.threads
    timeout   = args.timeout
    delay     = args.delay
    out_file  = args.output
    
    # Load wordlist
    wordlist = list(set(BUILTIN_PARAMS))
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                custom = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            wordlist = list(set(wordlist + custom))
            log("INFO", f"Loaded custom wordlist: {len(custom)} params merged → total {len(wordlist)}")
        except Exception as e:
            log("ERROR", f"Could not load wordlist: {e}")
    
    log("INFO", f"Target    : {C}{target}{RST}")
    log("INFO", f"Method    : {Y}{method}{RST}")
    log("INFO", f"Threads   : {threads}")
    log("INFO", f"Wordlist  : {len(wordlist)} parameters")
    log("INFO", f"Timeout   : {timeout}s  |  Delay: {delay}s")
    print()
    
    session = make_session(delay)
    
    # Step 1: Baseline
    log("SCAN", "Getting baseline response...")
    b_status, b_len, b_html = get_baseline(session, target, method, timeout)
    
    if b_status is None:
        log("ERROR", f"Could not reach target: {target}")
        sys.exit(1)
    
    log("INFO", f"Baseline → status={G}{b_status}{RST} len={G}{b_len}{RST}")
    
    # Step 2: Extract params from HTML
    log("SCAN", "Extracting params from HTML response...")
    html_params = extract_params_from_html(b_html)
    if html_params:
        log("INFO", f"Found {G}{len(html_params)}{RST} params in HTML: {C}{', '.join(list(html_params)[:10])}{RST}{'...' if len(html_params)>10 else ''}")
        wordlist = list(set(wordlist + list(html_params)))
    
    # Step 3: Extract from JS files
    if not args.no_js:
        log("SCAN", "Extracting params from JavaScript files...")
        js_params = extract_from_js(session, target, timeout)
        if js_params:
            log("INFO", f"Found {G}{len(js_params)}{RST} params in JS files")
            wordlist = list(set(wordlist + list(js_params)))
    
    log("INFO", f"Final wordlist size: {G}{len(wordlist)}{RST} parameters\n")
    
    # Step 4: Fuzz
    log("SCAN", f"Starting parameter fuzzing with {threads} threads...\n")
    
    start_time = time.time()
    
    def fuzz_worker(param):
        p, status, length, reason = probe_param(
            session, target, param, method,
            b_len, b_status, timeout, delay, args.fuzz_value
        )
        if p:
            with results_lock:
                found_params.append({
                    "param": p,
                    "status": status,
                    "length": length,
                    "reason": reason,
                    "url": target
                })
            log("FOUND", f"{G}{B}{p}{RST} → status={Y}{status}{RST} len={Y}{length}{RST} [{M}{reason}{RST}]")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(fuzz_worker, param): param for param in wordlist}
        
        completed = 0
        total = len(wordlist)
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0 or completed == total:
                pct = int((completed / total) * 100)
                bar = ("█" * (pct // 5)).ljust(20)
                print(f"\r  {C}[{bar}]{RST} {pct}% ({completed}/{total}) | found={G}{len(found_params)}{RST} | reqs={request_count}", end="", flush=True)
    
    print("\n")
    elapsed = time.time() - start_time
    
    # ─── Results Summary ─────────────────────────────────────────────────────
    print(f"{C}{'═'*60}{RST}")
    print(f"{B}{G}  SCAN COMPLETE{RST}")
    print(f"{C}{'═'*60}{RST}")
    print(f"  Target      : {target}")
    print(f"  Duration    : {elapsed:.1f}s")
    print(f"  Requests    : {request_count}")
    print(f"  Tested      : {len(wordlist)} params")
    print(f"  {G}Found       : {len(found_params)} interesting params{RST}")
    print(f"{C}{'═'*60}{RST}\n")
    
    if found_params:
        print(f"{B}  INTERESTING PARAMETERS:{RST}\n")
        for i, r in enumerate(found_params, 1):
            print(f"  {G}{i:02d}.{RST} {B}{r['param']}{RST}")
            print(f"      Status: {r['status']}  |  Length: {r['length']}")
            print(f"      Reason: {M}{r['reason']}{RST}")
            print(f"      URL   : {C}{r['url']}?{r['param']}=VALUE{RST}\n")
    
    # ─── Save Output ─────────────────────────────────────────────────────────
    if out_file:
        output_data = {
            "target": target,
            "method": method,
            "scan_time": datetime.now().isoformat(),
            "duration_seconds": round(elapsed, 2),
            "total_requests": request_count,
            "params_tested": len(wordlist),
            "found_params": found_params
        }
        with open(out_file, "w") as f:
            json.dump(output_data, f, indent=2)
        log("INFO", f"Results saved → {G}{out_file}{RST}")
    
    return found_params

# ─── Entry Point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ParamHunter — Parameter Discovery Tool by @cybermindspace",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 paramhunter.py -u https://target.com/page
  python3 paramhunter.py -u https://target.com/api -m POST -t 30
  python3 paramhunter.py -u https://target.com -w myparams.txt -o results.json
  python3 paramhunter.py -u https://target.com --delay 0.5 --no-js
        """
    )
    
    parser.add_argument("-u", "--url",        required=True,  help="Target URL")
    parser.add_argument("-m", "--method",     default="GET",  help="HTTP method: GET or POST (default: GET)")
    parser.add_argument("-t", "--threads",    type=int, default=20, help="Threads (default: 20)")
    parser.add_argument("-w", "--wordlist",   help="Custom wordlist file (merged with built-in)")
    parser.add_argument("-o", "--output",     help="Save results to JSON file")
    parser.add_argument("--timeout",          type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--delay",            type=float, default=0, help="Delay between requests (default: 0)")
    parser.add_argument("--fuzz-value",       default="", help="Custom fuzz value to send (default: auto)")
    parser.add_argument("--no-js",            action="store_true", help="Skip JavaScript file analysis")
    
    args = parser.parse_args()
    
    try:
        run_scan(args)
    except KeyboardInterrupt:
        print(f"\n\n{Y}[!] Scan interrupted by user{RST}")
        if found_params:
            print(f"{G}[+] Found {len(found_params)} params before stopping:{RST}")
            for r in found_params:
                print(f"    → {r['param']}")
        sys.exit(0)

if __name__ == "__main__":
    main()
