#!/usr/bin/env python3
"""
CORS Security Checker - CLI Tool
Tests websites for CORS misconfigurations and vulnerabilities

Usage:
    python cors_checker.py https://api.example.com
    python cors_checker.py https://api.example.com -v
    python cors_checker.py https://api.example.com --json results.json

Requirements:
    pip install requests colorama
"""

import requests
import argparse
import sys
import json
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # Fallback for no colorama
    class Fore:
        CYAN = RED = GREEN = YELLOW = WHITE = LIGHTBLACK_EX = LIGHTRED_EX = ''
    class Style:
        RESET_ALL = ''


class CORSChecker:
    """Main CORS vulnerability checker class"""
    
    TESTS = [
        {
            'name': 'Wildcard Origin (*)',
            'origin': '*',
            'description': 'Tests if server accepts requests from any origin',
            'severity': 'CRITICAL',
            'cwe': 'CWE-942'
        },
        {
            'name': 'Null Origin',
            'origin': 'null',
            'description': 'Tests if server accepts null origin (sandbox/file://)',
            'severity': 'HIGH',
            'cwe': 'CWE-942'
        },
        {
            'name': 'Reflected Origin',
            'origin': 'https://evil.com',
            'description': 'Tests if server reflects arbitrary origins',
            'severity': 'CRITICAL',
            'cwe': 'CWE-942'
        },
        {
            'name': 'Subdomain Wildcard',
            'origin': 'https://attacker.example.com',
            'description': 'Tests if server trusts all subdomains without validation',
            'severity': 'HIGH',
            'cwe': 'CWE-942'
        },
        {
            'name': 'Pre-domain Bypass',
            'origin': 'https://evil.com.example.com',
            'description': 'Tests weak regex validation (prefix matching)',
            'severity': 'MEDIUM',
            'cwe': 'CWE-185'
        },
        {
            'name': 'Post-domain Bypass',
            'origin': 'https://example.com.evil.com',
            'description': 'Tests weak regex validation (suffix matching)',
            'severity': 'MEDIUM',
            'cwe': 'CWE-185'
        },
        {
            'name': 'Insecure Protocol',
            'origin': 'http://evil.com',
            'description': 'Tests if server accepts HTTP origins',
            'severity': 'MEDIUM',
            'cwe': 'CWE-319'
        }
    ]
    
    def __init__(self, url: str, timeout: int = 10, user_agent: Optional[str] = None):
        """Initialize CORS checker"""
        self.url = url
        self.timeout = timeout
        self.user_agent = user_agent or "CORS-Checker/1.0"
        self.vulnerabilities: List[Dict[str, Any]] = []
    
    def check_cors(self, origin: str) -> Dict[str, Any]:
        """Perform CORS check with given origin"""
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'content-type',
            'User-Agent': self.user_agent
        }
        
        try:
            response = requests.options(
                self.url, 
                headers=headers, 
                timeout=self.timeout, 
                allow_redirects=False
            )
            
            cors_headers = {
                'allow_origin': response.headers.get('Access-Control-Allow-Origin'),
                'allow_credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'allow_methods': response.headers.get('Access-Control-Allow-Methods'),
                'allow_headers': response.headers.get('Access-Control-Allow-Headers'),
                'expose_headers': response.headers.get('Access-Control-Expose-Headers'),
                'max_age': response.headers.get('Access-Control-Max-Age')
            }
            
            return {
                'success': True,
                'status': response.status_code,
                'headers': cors_headers
            }
            
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timeout'}
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Connection error'}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}
    
    def analyze_result(self, test: Dict[str, str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze test result for vulnerabilities"""
        vulnerable = False
        details = []
        
        if not result['success']:
            details.append(f"Error: {result['error']}")
            return {
                'test': test,
                'vulnerable': vulnerable,
                'details': details,
                'result': result
            }
        
        allow_origin = result['headers']['allow_origin']
        allow_creds = result['headers']['allow_credentials']
        
        if not allow_origin:
            details.append("Origin blocked (secure)")
            return {
                'test': test,
                'vulnerable': vulnerable,
                'details': details,
                'result': result
            }
        
        # Check for vulnerabilities
        if test['origin'] == '*' and allow_origin == '*':
            vulnerable = True
            details.append("Server accepts requests from ANY origin")
        elif allow_origin == test['origin']:
            vulnerable = True
            details.append(f"Server reflects origin: {test['origin']}")
        
        # Check credentials
        if allow_creds and allow_creds.lower() == 'true':
            if vulnerable:
                details.append("⚠️ CRITICAL: Credentials allowed with vulnerable origin!")
                self.vulnerabilities.append({
                    'test': test['name'],
                    'severity': 'CRITICAL',
                    'cwe': test['cwe'],
                    'issue': 'Credentials enabled with insecure CORS policy',
                    'origin': test['origin']
                })
            else:
                details.append("Credentials allowed")
        
        # Add methods if available
        if result['headers']['allow_methods']:
            details.append(f"Methods: {result['headers']['allow_methods']}")
        
        if vulnerable:
            self.vulnerabilities.append({
                'test': test['name'],
                'severity': test['severity'],
                'cwe': test['cwe'],
                'issue': f"Accepts origin: {allow_origin}",
                'origin': test['origin']
            })
        
        return {
            'test': test,
            'vulnerable': vulnerable,
            'details': details,
            'result': result
        }
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all CORS tests"""
        results = []
        self.vulnerabilities = []
        
        for test in self.TESTS:
            result = self.check_cors(test['origin'])
            analysis = self.analyze_result(test, result)
            results.append(analysis)
        
        return results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of scan results"""
        return {
            'url': self.url,
            'total_tests': len(self.TESTS),
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'passed': len(self.TESTS) - len(self.vulnerabilities)
        }


class CLIFormatter:
    """Handles CLI output formatting"""
    
    @staticmethod
    def print_header(url: str):
        """Print tool header"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}  CORS Security Checker v1.0")
        print(f"{Fore.CYAN}  Testing: {Fore.WHITE}{url}")
        print(f"{Fore.CYAN}{'='*70}\n")
    
    @staticmethod
    def print_severity(severity: str) -> str:
        """Return colored severity string"""
        colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.LIGHTRED_EX,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN,
            'INFO': Fore.CYAN
        }
        return f"{colors.get(severity, Fore.WHITE)}[{severity}]{Style.RESET_ALL}"
    
    @staticmethod
    def print_test_result(test_num: int, total: int, analysis: dict, verbose: bool):
        """Print individual test result"""
        test = analysis['test']
        vulnerable = analysis['vulnerable']
        details = analysis['details']
        
        print(f"{Fore.CYAN}[{test_num}/{total}] {Fore.WHITE}{test['name']}")
        print(f"    {Fore.LIGHTBLACK_EX}{test['description']}")
        print(f"    Testing with origin: {Fore.YELLOW}{test['origin']}")
        
        if vulnerable:
            print(f"    {Fore.RED}✗ VULNERABLE {CLIFormatter.print_severity(test['severity'])}")
        else:
            print(f"    {Fore.GREEN}✓ SECURE")
        
        if verbose and details:
            for detail in details:
                print(f"      {Fore.LIGHTBLACK_EX}• {detail}")
        
        print()
    
    @staticmethod
    def print_summary(summary: dict):
        """Print scan summary"""
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}  SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        vuln_count = summary['vulnerabilities_found']
        total = summary['total_tests']
        
        if vuln_count == 0:
            print(f"{Fore.GREEN}✓ No CORS vulnerabilities detected!")
            print(f"{Fore.GREEN}  All {total} tests passed.\n")
        else:
            print(f"{Fore.RED}✗ Found {vuln_count} vulnerability(ies)")
            print(f"{Fore.YELLOW}  {summary['passed']}/{total} tests passed\n")
            
            print(f"{Fore.CYAN}Vulnerabilities Found:")
            print(f"{Fore.CYAN}{'-'*70}\n")
            
            for vuln in summary['vulnerabilities']:
                print(f"{CLIFormatter.print_severity(vuln['severity'])} {vuln['test']}")
                print(f"    {Fore.LIGHTBLACK_EX}CWE: {vuln['cwe']}")
                print(f"    {Fore.LIGHTBLACK_EX}{vuln['issue']}\n")
            
            CLIFormatter.print_recommendations()
    
    @staticmethod
    def print_recommendations():
        """Print security recommendations"""
        print(f"\n{Fore.CYAN}Security Recommendations:")
        print(f"{Fore.CYAN}{'-'*70}")
        print(f"{Fore.YELLOW}• Use specific allowed origins instead of wildcards")
        print(f"{Fore.YELLOW}• Never use Access-Control-Allow-Origin: * with credentials")
        print(f"{Fore.YELLOW}• Implement strict origin validation with whitelist")
        print(f"{Fore.YELLOW}• Avoid null origin unless absolutely necessary")
        print(f"{Fore.YELLOW}• Validate the entire origin string, not just substrings")
        print(f"{Fore.YELLOW}• Use HTTPS for all allowed origins\n")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='CORS Security Checker - Test websites for CORS misconfigurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://api.example.com
  %(prog)s https://api.example.com -v
  %(prog)s -f urls.txt
  %(prog)s -f urls.txt --json results.json
  %(prog)s https://api.example.com --timeout 15

Requirements:
  pip install requests colorama
        """
    )
    
    parser.add_argument('url', nargs='?', help='Target URL to test')
    parser.add_argument('-f', '--file', metavar='FILE', dest='url_file',
                       help='Read URLs from a text file (one URL per line)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output with detailed information')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--json', metavar='FILE', dest='json_file',
                       help='Save results to JSON file')
    parser.add_argument('--user-agent', metavar='UA',
                       help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    # Determine URLs to scan
    urls = []
    if args.url_file:
        try:
            with open(args.url_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if not urls:
                print(f"{Fore.RED}Error: No valid URLs found in file {args.url_file}")
                sys.exit(1)
            print(f"{Fore.CYAN}Loaded {len(urls)} URL(s) from {args.url_file}\n")
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found: {args.url_file}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}Error reading file: {e}")
            sys.exit(1)
    elif args.url:
        urls = [args.url]
    else:
        print(f"{Fore.RED}Error: Please provide a URL or use --file to specify a file")
        parser.print_help()
        sys.exit(1)
    
    # Validate URLs
    for url in urls:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            print(f"{Fore.RED}Error: Invalid URL '{url}'. URLs must include scheme (e.g., https://example.com)")
            sys.exit(1)
    
    # Check for colorama
    if not HAS_COLOR:
        print("Warning: colorama not installed. Install with: pip install colorama")
        print("Continuing without colors...\n")
    
    # Store all results for multiple URLs
    all_results = []
    total_vulnerabilities = 0
    
    # Scan each URL
    for idx, url in enumerate(urls, 1):
        if len(urls) > 1:
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.CYAN}  Scanning URL {idx}/{len(urls)}")
            print(f"{Fore.CYAN}{'='*70}")
        
        # Create checker instance
        checker = CORSChecker(
            url=url,
            timeout=args.timeout,
            user_agent=args.user_agent
        )
        
        # Print header
        CLIFormatter.print_header(url)
        
        # Run tests
        print(f"{Fore.CYAN}Running {len(CORSChecker.TESTS)} tests...\n")
        results = checker.run_all_tests()
        
        # Print results
        for i, analysis in enumerate(results, 1):
            CLIFormatter.print_test_result(i, len(results), analysis, args.verbose)
        
        # Get and print summary
        summary = checker.get_summary()
        CLIFormatter.print_summary(summary)
        
        # Store results
        all_results.append({
            'url': url,
            'summary': summary,
            'results': results
        })
        total_vulnerabilities += len(checker.vulnerabilities)
    
    # Print overall summary for multiple URLs
    if len(urls) > 1:
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}  OVERALL SUMMARY")
        print(f"{Fore.CYAN}{'='*70}\n")
        print(f"{Fore.WHITE}Total URLs scanned: {Fore.CYAN}{len(urls)}")
        print(f"{Fore.WHITE}Total vulnerabilities found: {Fore.RED if total_vulnerabilities > 0 else Fore.GREEN}{total_vulnerabilities}\n")
        
        for result in all_results:
            vuln_count = result['summary']['vulnerabilities_found']
            color = Fore.RED if vuln_count > 0 else Fore.GREEN
            status = "VULNERABLE" if vuln_count > 0 else "SECURE"
            print(f"{color}{status:12} {Fore.WHITE}{result['url']} {color}({vuln_count} issues)")
        print()
    
    # Save JSON if requested
    if args.json_file:
        output = {
            'scan_summary': {
                'total_urls': len(urls),
                'total_vulnerabilities': total_vulnerabilities,
                'scanned_at': None  # You can add timestamp if needed
            },
            'results': all_results
        }
        try:
            with open(args.json_file, 'w') as f:
                json.dump(output, f, indent=2, default=str)
            print(f"{Fore.GREEN}Results saved to: {args.json_file}\n")
        except Exception as e:
            print(f"{Fore.RED}Error saving JSON: {e}\n")
    
    # Exit with error code if vulnerabilities found
    sys.exit(min(total_vulnerabilities, 255))  # Cap at 255 for valid exit code


if __name__ == '__main__':
    main()
