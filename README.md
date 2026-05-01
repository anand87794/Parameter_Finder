🔍 ParamHunter

Automated Parameter Discovery Tool for Web Application Recon
Built for Bug Bounty Hunters & Penetration Testers

██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║
██████╔╝███████║██████╔╝███████║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
         H U N T E R  —  Parameter Discovery
         @cybermindspace · Bug Bounty Recon
Show Image
Show Image
Show Image
Show Image

📌 What is ParamHunter?
ParamHunter is a fast, multi-threaded Python tool that discovers hidden and interesting parameters on web application endpoints. It combines:

Built-in parameter wordlist (200+ common params)
HTML response parsing (forms, inputs, anchor hrefs)
JavaScript file analysis (fetch calls, JSON keys, URL patterns)
Smart detection heuristics (length diff, status change, reflection, error keywords)

Use it during recon to find parameters that might be vulnerable to IDOR, SSRF, open redirect, XSS, SQLi, and more.

⚙️ Features
FeatureDetails🔤 Built-in Wordlist200+ common web parameters🌐 HTML ExtractionParses forms, inputs, links from response📜 JS File AnalysisExtracts params from JavaScript files⚡ Multi-threadedConfigurable thread count (default: 20)🎯 Smart DetectionLength diff, status change, reflection, error keywords📁 JSON OutputSave results for further processing🔀 Custom WordlistMerge your own list with built-in⏱️ Rate LimitingConfigurable delay between requests🔁 GET & POSTSupports both HTTP methods

🛠️ Installation
Requirements

Python 3.8+
Kali Linux / Any Linux distro

Setup
bash# 1. Clone the repo
git clone https://github.com/cybermindspace/paramhunter.git
cd paramhunter

# 2. Install dependency
pip3 install requests --break-system-packages

# 3. Make executable
chmod +x paramhunter.py

# 4. Verify
python3 paramhunter.py --help
Optional — Add as alias (Kali Linux)
bashecho "alias paramhunter='python3 $(pwd)/paramhunter.py'" >> ~/.bashrc
source ~/.bashrc

# Now run from anywhere:
paramhunter -u https://target.com

🚀 Usage
Basic Syntax
bashpython3 paramhunter.py -u <URL> [options]
Options
  -u, --url         Target URL (required)
  -m, --method      HTTP method: GET or POST (default: GET)
  -t, --threads     Number of threads (default: 20)
  -w, --wordlist    Custom wordlist file (merged with built-in)
  -o, --output      Save results to JSON file
  --timeout         Request timeout in seconds (default: 8)
  --delay           Delay between requests in seconds (default: 0)
  --fuzz-value      Custom value to send as param value
  --no-js           Skip JavaScript file analysis

📖 Examples
bash# Basic GET scan
python3 paramhunter.py -u https://target.com/page

# POST endpoint (login, API)
python3 paramhunter.py -u https://target.com/api/login -m POST

# More threads + save to JSON
python3 paramhunter.py -u https://target.com -t 30 -o results.json

# Use SecLists wordlist (Kali)
python3 paramhunter.py -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -o output.json

# Slow scan with delay (avoid rate limiting)
python3 paramhunter.py -u https://target.com --delay 1 -t 10

# Skip JS analysis for faster scan
python3 paramhunter.py -u https://target.com --no-js -t 50

📊 Sample Output
09:42:11 [INFO]  Target    : https://target.com/page
09:42:11 [INFO]  Method    : GET
09:42:11 [INFO]  Threads   : 20
09:42:11 [INFO]  Wordlist  : 248 parameters
09:42:12 [SCAN]  Getting baseline response...
09:42:12 [INFO]  Baseline → status=200 len=4821
09:42:12 [SCAN]  Extracting params from HTML response...
09:42:12 [INFO]  Found 12 params in HTML: id, user, token, page...
09:42:13 [SCAN]  Extracting params from JavaScript files...
09:42:13 [INFO]  Found 8 params in JS files
09:42:13 [INFO]  Final wordlist size: 268 parameters

09:42:15 [FOUND] id       → status=200 len=5162 [len_diff=341, reflected]
09:42:16 [FOUND] user     → status=200 len=5890 [value_reflected]
09:42:17 [FOUND] redirect → status=302 len=0    [status=200→302]
09:42:19 [FOUND] debug    → status=200 len=7201 [len_diff=2380, error_keyword]

══════════════════════════════════════════════════════════
  SCAN COMPLETE
══════════════════════════════════════════════════════════
  Target      : https://target.com/page
  Duration    : 18.4s
  Requests    : 281
  Tested      : 268 params
  Found       : 4 interesting params
══════════════════════════════════════════════════════════

🔗 Recommended Workflow
subfinder -d target.com | httpx -silent
        ↓
paramhunter.py -u https://target.com/endpoint
        ↓
Investigate found params in Burp Suite
        ↓
Test for IDOR / SSRF / Redirect / SQLi / XSS
Combine with other tools
bash# Use gau to find endpoints, then paramhunter on each
gau target.com | grep "?" | cut -d"?" -f1 | sort -u | while read url; do
  python3 paramhunter.py -u "$url" -o "results_$(date +%s).json"
done

# Pipe found params into ffuf for value fuzzing
python3 paramhunter.py -u https://target.com -o params.json
cat params.json | jq -r '.found_params[].param'

📁 JSON Output Format
json{
  "target": "https://target.com/page",
  "method": "GET",
  "scan_time": "2025-01-15T09:42:11",
  "duration_seconds": 18.4,
  "total_requests": 281,
  "params_tested": 268,
  "found_params": [
    {
      "param": "id",
      "status": 200,
      "length": 5162,
      "reason": "len_diff=341, reflected",
      "url": "https://target.com/page"
    }
  ]
}

⚠️ Legal Disclaimer

This tool is intended for authorized security testing and bug bounty programs only.
Only use on targets you have explicit written permission to test.
The author is not responsible for any misuse or damage caused by this tool.
Always follow responsible disclosure guidelines.


👤 Author
Anand Prajapati
🐦 @anand87794
🔒 Security Researcher · Bug Bounty Hunter

📄 License
MIT License — see LICENSE for details.

⭐ If this tool helped you find a bug, drop a star!Share
