"""Review saved HTTP response headers for missing or weak browser security controls without making network requests."""
import argparse
import json
from pathlib import Path
import re

def audit(headers):
    if not isinstance(headers, dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in headers.items()):
        raise ValueError('headers must be a JSON object of strings')
    h = {key.lower():value.strip() for key,value in headers.items()}
    findings = []
    def add(rule, message): findings.append(dict(rule=rule, message=message))
    hsts = h.get('strict-transport-security','')
    age = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)', hsts, re.I)
    if not age or int(age[1]) < 31536000:
        add('hsts', 'Review HSTS: max-age is missing or below the project policy of 31536000 seconds.')
    csp = h.get('content-security-policy','')
    directives = {part.strip().split()[0].lower():part.strip().split()[1:] for part in csp.split(';') if part.strip()}
    if not csp:
        add('csp', 'Content-Security-Policy is missing.')
    elif "'unsafe-inline'" in directives.get('script-src', directives.get('default-src',[])) or '*' in directives.get('script-src', directives.get('default-src',[])):
        add('csp_script', 'Script policy contains unsafe-inline or a wildcard; review application needs.')
    if h.get('x-content-type-options','').lower() != 'nosniff':
        add('nosniff', 'X-Content-Type-Options should be nosniff under this policy.')
    if h.get('x-frame-options','').upper() not in {'DENY','SAMEORIGIN'} and not directives.get('frame-ancestors'):
        add('framing', 'No recognized frame restriction found.')
    if h.get('referrer-policy','').lower() not in {'no-referrer','same-origin','strict-origin','strict-origin-when-cross-origin'}:
        add('referrer', 'Review missing or permissive Referrer-Policy.')
    return findings

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(audit(json.loads(args.input.read_text(encoding='utf-8'))), indent=2))
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f'error: {exc}\n')

if __name__ == '__main__': main()
