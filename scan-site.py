import httpx
import sys
import ssl
import socket
import time
import webtech
from difflib import SequenceMatcher
from playwright.sync_api import sync_playwright

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

# check if host is up
def check_host(h):
    try:
        httpx.get(h)
        status = True
    except Exception as e:
        print(e)
        status = False
    finally:
        return status

# get IP address of the server from domain
def get_ip(domain):
    ip = socket.gethostbyname(domain.split('://')[1])
    return ip

def get_ip_info(ip):
    r = httpx.get(f"http://ip-api.com/json/{ip}")
    return r.json()

def get_ssl_info(domain):
    if domain[:5] != 'https':
        return {'issued_to': 'not https', 'issued_by': 'not https'}

    hostname = domain.split('://')[1]
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        cert = s.getpeercert()
    subject = dict(x[0] for x in cert['subject'])
    issued_to = subject['commonName']
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer['commonName']
    not_before = cert['notBefore']
    not_after = cert['notAfter']
    return {'issued_to': issued_to, 'issued_by': issued_by, 'not_before': not_before, 'not_after': not_after}

def check_cookies(domain):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        page.goto(domain)
        time.sleep(10)
        return context.cookies()
    
def check_webtech(domain):
    wt = webtech.WebTech()
    results = wt.start_from_url(domain, timeout=5)
    return results

def scan(domain):
    ip = get_ip(domain)
    ip_info = get_ip_info(ip)
    ssl_info = get_ssl_info(domain)
    cookies = check_cookies(domain)
    webtech = check_webtech(domain)
    return {
        'ip': ip,
        'ip_info': ip_info,
        'ssl_info': ssl_info,
        'cookies': cookies,
        'webtech': webtech
    }

def pretty_print_result(domain, result):
    print('='*80)
    print(domain)
    print('='*80)
    print(f"ip: {result['ip']}")
    print(f"country: {result['ip_info']['country']}")
    print(f"countryCode: {result['ip_info']['countryCode']}")
    print(f"region: {result['ip_info']['region']}")
    print(f"regionName: {result['ip_info']['regionName']}")
    print(f"city: {result['ip_info']['city']}")
    print(f"zip: {result['ip_info']['zip']}")
    print(f"lat: {result['ip_info']['lat']}")
    print(f"lon: {result['ip_info']['lon']}")
    print(f"timezone: {result['ip_info']['timezone']}")
    print(f"isp: {result['ip_info']['isp']}")
    print(f"org: {result['ip_info']['org']}")
    print(f"as: {result['ip_info']['as']}")
    print('='*80)
    print(f"certificate:")
    print(f"issued_to: {result['ssl_info']['issued_to']}")
    print(f"issued_by: {result['ssl_info']['issued_by']}")
    print(f"notBefore: {result['ssl_info']['not_before']}")
    print(f"notAfter: {result['ssl_info']['not_after']}")
    print('='*80)
    print(result['webtech'])
    print('='*80)
    print("cookies:")
    for c in result['cookies']:
        print(f"name: {c['name']} domain:{c['domain']} path:{c['path']} expires:{c['expires']}")
        print(f"httpOnly:{c['httpOnly']} secure:{c['secure']} sameSite:{c['sameSite']}")
        print(f"value: {c['value']}")
        print()
    print('='*80)


def usage():
    print("Usage:")
    print("python3 scan-site.py domain")

def main():
    if len(sys.argv) != 2:
        usage()
        sys.exit(0)

    domain = sys.argv[1]
    
    try:
        check_host(domain)
    except Exception as e:
        print(e)
        sys.exit(-1)

    domain_info = scan(domain)
    pretty_print_result(domain, domain_info)

if __name__ == "__main__":
    main()