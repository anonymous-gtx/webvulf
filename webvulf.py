import dns.resolver
import sys
import requests

def show_help():
    help_message = """
    Webvulf - A Web Vulnerability Tool

    Usage:
    python3 webvulf.py [OPTION] <domain> [wordlist]

    Options:
    -h, --help             Show this help message and exit.
    -c <domain>            Test CORS vulnerability for the given domain.
    -d <domain>            Perform DNS enumeration for the given domain.
    -s <domain> <wordlist> Perform subdomain enumeration using the given wordlist.

    Example:
    python3 webvulf.py -c example.com
    python3 webvulf.py -d example.com
    python3 webvulf.py -s example.com subdomains.txt
    """
    print(help_message)
    sys.exit()

def user_decide():
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
        show_help()

    option = sys.argv[1]
    if option == '-s':
        subdomain_enum()
    elif option == '-d':
        dns_enum()
    elif option == '-c':
        test_cors_vulnerability()
    else:
        print("Invalid option. Use '-h' for help.")
        sys.exit()

def subdomain_enum():
    try:
        domain = sys.argv[2]
        wordlist = sys.argv[3]
    except IndexError:
        print("Usage: python3 webvulf.py -s <domain> <wordlist>")
        sys.exit()

    subdomains = []
    try:
        with open(wordlist, 'r') as file:
            subdomains = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: Wordlist '{wordlist}' not found.")
        sys.exit()

    valid_subdomains = []
    for sub in subdomains:
        try:
            ip_value = dns.resolver.resolve(f'{sub}.{domain}', 'A')
            valid_subdomains.append(f'{sub}.{domain}')
            print(f"{sub}.{domain} is valid!")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            pass
        except KeyboardInterrupt:
            exit()
    with open('output_file.txt', 'w') as file:
        file.write("\n".join(valid_subdomains) + '\n')
    print("Output stored in 'output_file.txt'.")

def dns_enum():
    try:
        domain = sys.argv[2]
    except IndexError:
        print("Usage: python3 webvulf.py -d <domain>")
        sys.exit()

    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'SOA', 'TXT']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 10

    for record in record_types:
        try:
            answers = resolver.resolve(domain, record)
            print(f'{record} Records:')
            for answer in answers:
                print(answer.to_text())
        except dns.resolver.NoAnswer:
            print(f"No {record} record found.")
        except dns.resolver.LifetimeTimeout:
            print(f"Timeout while resolving {record} records for {domain}.")
        except KeyboardInterrupt:
            exit()
        except dns.resolver.NXDOMAIN:
            print(f'{domain} does not exist.')
            sys.exit()

def test_cors_vulnerability():
    try:
        domain = sys.argv[2]
    except IndexError:
        print("Usage: python3 webvulf.py -c <domain>")
        sys.exit()

    headers = {"User-Agent": "CORS-Checker"}
    default_origins = ["https://evil.com", "null"]

    for origin in default_origins:
        headers["Origin"] = origin
        urls = [f"http://{domain}", f"https://{domain}"]

        for url in urls:
            try:
                response = requests.get(url, headers=headers, timeout=10)
                if "Access-Control-Allow-Origin" in response.headers:
                    allowed_origin = response.headers["Access-Control-Allow-Origin"]
                    if allowed_origin == origin or allowed_origin == "*":
                        print(f"[!] Vulnerable! URL: {url} allows Origin: {allowed_origin}")
                    else:
                        print(f"[+] Safe! URL: {url} does not allow Origin: {origin}")
                else:
                    print(f"[+] No CORS headers found for URL: {url}")
            except requests.RequestException as e:
                print(f"[ERROR] Failed to connect to {url}: {e}")

if __name__ == "__main__":
    user_decide()
