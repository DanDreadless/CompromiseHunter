import re
import os
import requests
import argparse
import pandas as pd
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from urllib.parse import urljoin, urlparse
from requests.exceptions import RequestException, Timeout

# Load environment variables from .env file
load_dotenv()

# API keys from environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

# Function to validate if the URL is well-formed and uses HTTP/HTTPS
def is_valid_url(url):
    if not url.startswith(('http://', 'https://')):
        print(f"Invalid URL protocol. Only HTTP/HTTPS allowed: {url}")
        return False
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"Invalid URL: {url}")
        return False
    return True

# Function to check against Google Safe Browsing
def check_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {
            "clientId": "websiteScanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        data = response.json()
        return data.get("matches", [])
    except RequestException as e:
        print(f"Error checking Safe Browsing for {url}: {e}")
        return []

# Function to check against Abuse.ch
def check_abuse_ch(url):
    api_url = f"https://urlhaus-api.abuse.ch/v1/url/"
    header = {"Auth-Key": ABUSE_API_KEY}
    params = {"url": url}
    try:
        response = requests.get(api_url, headers=header, params=params)
        response.raise_for_status()
        data = response.json()
        return data.get("result", "")
    except RequestException as e:
        print(f"Error checking Abuse.ch for {url}: {e}")
        return ""

# Function to fetch page content and extract JavaScript links
def fetch_page(url):
    try:
        url = url if url.startswith(('http://', 'https://')) else f"https://{url}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        js_links = []
        for script in soup.find_all('script', src=True):
            js_links.append(urljoin(url, script['src']))
        return soup, js_links
    except (RequestException, Timeout) as e:
        print(f"Error fetching page {url}: {e}")
        return None, None

# Function to scan HTML for malicious content
def scan_html_for_malicious_content(soup):
    malicious_patterns = [
        r"eval\(",  # usage of eval (can be exploited for malicious JavaScript)
        r"document\.cookie",  # accessing document cookies
        r"document\.location",  # location manipulation for malicious redirects
        r"base64,",  # base64 encoded payloads
        r"src\s*=\s*['\"](javascript|data|vbscript):",  # suspicious src attributes (JS, data URLs)
        r"window\.open",  # window.open could be used for malicious redirection
    ]
    
    malicious_code_found = []
    html_content = soup.prettify()  # Get prettified HTML content

    for pattern in malicious_patterns:
        if re.search(pattern, html_content):
            malicious_code_found.append(pattern)

    return malicious_code_found

# Check if the page contains suspicious redirects
def check_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        if len(response.history) > 1:
            return True  # Redirect chain detected
        return False
    except RequestException:
        return False

# Function to check HTTP headers for misconfigurations
def check_http_headers(url):
    headers_to_check = ['X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
    misconfigurations = []
    try:
        response = requests.head(url, timeout=10)
        headers = response.headers
        for header in headers_to_check:
            if header not in headers:
                misconfigurations.append(f"Missing header: {header}")
        return misconfigurations
    except RequestException as e:
        print(f"Error checking headers for {url}: {e}")
        return []

# Function to scan the website for malicious content
def scan_website(url):
    if not is_valid_url(url):
        return None

    # Fetch the page content and JavaScript links
    soup, js_links = fetch_page(url)
    if soup is None:
        return None

    # Check Safe Browsing and Abuse.ch for the website URL
    safe_browsing_matches = check_safe_browsing(url)
    abuse_ch_result = check_abuse_ch(url)

    # Scan the HTML for any malicious content patterns
    malicious_html_content = scan_html_for_malicious_content(soup)

    # Check each external JS link for threats
    js_threats = []
    for js_url in js_links:
        js_safe_browsing = check_safe_browsing(js_url)
        js_abuse_ch = check_abuse_ch(js_url)
        js_threats.append({
            'url': js_url,
            'safe_browsing': js_safe_browsing,
            'abuse_ch': js_abuse_ch
        })

    # Check for suspicious redirects
    redirects_detected = check_redirects(url)

    # Check for HTTP header misconfigurations
    header_issues = check_http_headers(url)

    # Prepare result data
    result = {
        'url': url,
        'safe_browsing': safe_browsing_matches,
        'abuse_ch': abuse_ch_result,
        'malicious_html': malicious_html_content,
        'js_threats': js_threats,
        'redirects': redirects_detected,
        'header_issues': header_issues
    }

    return result

# Function to display the results
def display_results(result):
    print(f"Scanning {result['url']}...")

    # Safe Browsing
    if result['safe_browsing']:
        print(f"Google Safe Browsing: MALICIOUS FOUND")
    else:
        print(f"Google Safe Browsing: CLEAN")

    # Abuse.ch
    if result['abuse_ch']:
        print(f"Abuse.ch: {result['abuse_ch']}")

    # Malicious HTML Content
    if result['malicious_html']:
        print(f"Malicious HTML Content Detected: ")
        for pattern in result['malicious_html']:
            print(f"  Pattern found: {pattern}")

    # JavaScript Threats
    if result['js_threats']:
        for js in result['js_threats']:
            if js['safe_browsing'] or js['abuse_ch']:
                print(f"JavaScript URL: {js['url']}")
                print(f"  Safe Browsing: {js['safe_browsing']}")
                print(f"  Abuse.ch: {js['abuse_ch']}")

    # Redirects
    if result['redirects']:
        print(f"Suspicious Redirects Detected")

    # Header Issues
    if result['header_issues']:
        print(f"HTTP Header Misconfigurations: ")
        for issue in result['header_issues']:
            print(f"  {issue}")
    else:
        print("No HTTP header issues found.")

# Function to save results to CSV
def save_to_csv(results, filename):
    df = pd.DataFrame(results)
    df.to_csv(filename, index=False)
    print(f"Results saved to {filename}")

# Command-line argument parsing
def parse_args():
    parser = argparse.ArgumentParser(description="Website Malicious Content Scanner")
    parser.add_argument("url", help="URL to scan")
    parser.add_argument("--csv", help="Save the output to a CSV file", action="store_true")
    return parser.parse_args()

# Main function
def main():
    args = parse_args()

    # Scan the website
    result = scan_website(args.url)

    if result:
        # Display results
        display_results(result)

        # Save to CSV if requested
        if args.csv:
            save_to_csv([result], "scan_results.csv")
    else:
        print("Scan failed or invalid URL.")

if __name__ == "__main__":
    main()
