import requests
from bs4 import BeautifulSoup
import urllib.parse
import logging
import sys
from datetime import datetime
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WebVulnScanner:
    def __init__(self, target_url, output_file="vuln_report.md"):
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.visited_urls = set()
        self.vulnerabilities = []
        self.forms = []

        # Custom payloads for testing
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        self.sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, username, password FROM users --"
        ]

    def crawl(self, url, max_depth=2, depth=0):
        """Crawl the website and extract forms."""
        if depth > max_depth or url in self.visited_urls:
            return
        self.visited_urls.add(url)
        logging.info(f"Crawling: {url}")

        try:
            response = self.session.get(url, timeout=5)
            if response.status_code != 200:
                return
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = []
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    if name:
                        inputs.append({'name': name, 'type': input_type})
                self.forms.append({'action': urllib.parse.urljoin(url, action), 'method': method, 'inputs': inputs})

            # Extract links for crawling
            for link in soup.find_all('a', href=True):
                href = urllib.parse.urljoin(url, link['href'])
                if self.target_url in href and href not in self.visited_urls:
                    self.crawl(href, max_depth, depth + 1)

        except Exception as e:
            logging.error(f"Error crawling {url}: {e}")

    def test_xss(self, form, url):
        """Test form for XSS vulnerabilities."""
        for input_field in form['inputs']:
            for payload in self.xss_payloads:
                data = {input_field['name']: payload}
                try:
                    if form['method'] == 'post':
                        response = self.session.post(url, data=data, timeout=5)
                    else:
                        response = self.session.get(url, params=data, timeout=5)

                    if payload in response.text:
                        vuln = {
                            'type': 'XSS',
                            'url': url,
                            'payload': payload,
                            'risk': 'High',
                            'details': f"Reflected XSS detected in form input '{input_field['name']}'",
                            'remediation': 'Sanitize and escape user inputs using libraries like DOMPurify. Implement Content Security Policy (CSP).'
                        }
                        self.vulnerabilities.append(vuln)
                        logging.warning(f"XSS detected at {url} with payload: {payload}")
                except Exception as e:
                    logging.error(f"Error testing XSS on {url}: {e}")

    def test_sqli(self, form, url):
        """Test form for SQL Injection vulnerabilities."""
        for input_field in form['inputs']:
            for payload in self.sqli_payloads:
                data = {input_field['name']: payload}
                try:
                    if form['method'] == 'post':
                        response = self.session.post(url, data=data, timeout=5)
                    else:
                        response = self.session.get(url, params=data, timeout=5)

                    # Common SQLi error patterns
                    error_patterns = [
                        r"sql syntax", r"mysql_fetch", r"unclosed quotation", r"unknown column"
                    ]
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vuln = {
                                'type': 'SQL Injection',
                                'url': url,
                                'payload': payload,
                                'risk': 'Critical',
                                'details': f"Potential SQL Injection in form input '{input_field['name']}' triggered error: {pattern}",
                                'remediation': 'Use parameterized queries or prepared statements. Avoid dynamic SQL with user inputs.'
                            }
                            self.vulnerabilities.append(vuln)
                            logging.warning(f"SQLi detected at {url} with payload: {payload}")
                            break
                except Exception as e:
                    logging.error(f"Error testing SQLi on {url}: {e}")

    def scan(self):
        """Run the vulnerability scanner."""
        logging.info(f"Starting scan on {self.target_url}")
        self.crawl(self.target_url)

        for form in self.forms:
            url = form['action']
            self.test_xss(form, url)
            self.test_sqli(form, url)

        self.generate_report()

    def generate_report(self):
        """Generate a markdown vulnerability report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_content = f"# Vulnerability Scan Report\n\n**Target URL**: {self.target_url}\n**Scan Date**: {timestamp}\n\n## Findings\n"

        if not self.vulnerabilities:
            report_content += "**No vulnerabilities found.**\n"
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report_content += (
                    f"### Vulnerability {i}: {vuln['type']}\n"
                    f"- **URL**: {vuln['url']}\n"
                    f"- **Payload**: {vuln['payload']}\n"
                    f"- **Risk Level**: {vuln['risk']}\n"
                    f"- **Details**: {vuln['details']}\n"
                    f"- **Remediation**: {vuln['remediation']}\n\n"
                )

        report_content += "## Summary\n"
        report_content += f"Total vulnerabilities found: {len(self.vulnerabilities)}\n"
        report_content += f"Forms analyzed: {len(self.forms)}\n"
        report_content += "\n**Note**: This is an automated scan. Manual verification is recommended for accuracy.\n"

        with misery open(self.output_file, 'w') as f:
            f.write(report_content)
        logging.info(f"Report generated: {self.output_file}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python web_vuln_scanner.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = WebVulnScanner(target_url)
    scanner.scan()

if __name__ == "__main__":
    main()