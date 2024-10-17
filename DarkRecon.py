import requests
from bs4 import BeautifulSoup
import re
import click
import subprocess
import whois
import dns.resolver
from colorama import init, Fore, Style
import json
import socket


# Print large ASCII Art Text
def print_large_ascii():
    ascii_art = r"""
██████╗░██╗██╗░░░██╗░█████╗░██████╗░██╗░░██╗  ░█████╗░██╗░░░░░░██████╗░██╗░░██╗████████╗░█████╗░███╗░░██╗██╗
██╔══██╗██║╚██╗░██╔╝██╔══██╗██╔══██╗██║░░██║  ██╔══██╗██║░░░░░██╔═══██╗██║░░██║╚══██╔══╝██╔══██╗████╗░██║██║
██████╔╝██║░╚████╔╝░███████║██║░░██║███████║  ███████║██║░░░░░██║██╗██║███████║░░░██║░░░███████║██╔██╗██║██║
██╔══██╗██║░░╚██╔╝░░██╔══██║██║░░██║██╔══██║  ██╔══██║██║░░░░░╚██████╔╝██╔══██║░░░██║░░░██╔══██║██║╚████║██║
██║░░██║██║░░░██║░░░██║░░██║██████╔╝██║░░██║  ██║░░██║███████╗░╚═██╔═╝░██║░░██║░░░██║░░░██║░░██║██║░╚███║██║
╚═╝░░╚═╝╚═╝░░░╚═╝░░░╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝  ╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝
    """
    print(Fore.GREEN + ascii_art)

# Call the print function at the start of the script
print_large_ascii()

# The rest of your tool...
# [Add the rest of your previously provided code here]


# Initialize colorama for colored terminal output
init(autoreset=True)

# Define Google Dorks for information gathering
dorks = {
    "files": "site:{} filetype:pdf OR filetype:docx OR filetype:txt",
    "directories": "intitle:index.of site:{}",
    "admin": "site:{} inurl:admin",
    "emails": "site:{} intext:@",
}

# Function to send Google search queries using Dorks
def google_search(query, verbose=False):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36'
    }
    url = f"https://www.google.com/search?q={query}"
    response = requests.get(url, headers=headers)

    if verbose:
        click.echo(Fore.YELLOW + f"[+] Request URL: {url}")
        click.echo(Fore.YELLOW + f"[+] Status Code: {response.status_code}")

    return response.text

# Function to parse Google search results
def parse_results(html, verbose=False):
    soup = BeautifulSoup(html, 'html.parser')
    results = []

    for link in soup.find_all('a', href=True):
        href = link['href']
        if "url?q=" in href and "webcache" not in href:
            match = re.search(r"url\?q=(https?://[^&]+)&", href)
            if match:
                url = match.group(1)
                results.append(url)
                if verbose:
                    click.echo(Fore.GREEN + f"[+] Found URL: {url}")

    return results

# Function to run Nmap with all HTTP scripts
def nmap_http_scan(domain, verbose=False):
    click.echo(Fore.CYAN + "[+] Starting Nmap HTTP Script Scan...")
    nmap_command = ['nmap', '-p', '80,443', '--script', 'http-*', domain]
    result = subprocess.run(nmap_command, capture_output=True, text=True)

    if verbose:
        click.echo(Fore.YELLOW + f"[+] Nmap Command: {' '.join(nmap_command)}")

    click.echo(Fore.MAGENTA + "[+] Nmap HTTP Script Results:")
    click.echo(Fore.GREEN + result.stdout)

# Function to run Gobuster for directory bruteforcing (filtering 403, 200, 302)
def gobuster_scan(domain, wordlist, verbose=False):
    click.echo(Fore.CYAN + "[+] Starting Gobuster Directory Scan...")
    gobuster_command = ['gobuster', 'dir', '-u', domain, '-w', wordlist, '-q']
    result = subprocess.run(gobuster_command, capture_output=True, text=True)

    if verbose:
        click.echo(Fore.YELLOW + f"[+] Gobuster Command: {' '.join(gobuster_command)}")

    click.echo(Fore.MAGENTA + "[+] Gobuster Results:")
    for line in result.stdout.splitlines():
        if any(code in line for code in ['200', '403', '302']):
            click.echo(Fore.GREEN + line)

# Function to perform WHOIS lookup
def whois_lookup(domain, verbose=False):
    click.echo(Fore.CYAN + "[+] Performing WHOIS Lookup...")
    try:
        domain_info = whois.whois(domain)
        click.echo(Fore.GREEN + str(domain_info))
    except Exception as e:
        click.echo(Fore.RED + f"[!] WHOIS Lookup Failed: {e}")

# Function to perform DNS lookup (trying all DNS record types)
def dns_lookup(domain, verbose=False):
    click.echo(Fore.CYAN + "[+] Performing DNS Lookup...")
    resolver = dns.resolver.Resolver()
    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME', 'AAAA', 'SOA', 'SRV']
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            click.echo(Fore.GREEN + f"[+] {record_type} Records:")
            for answer in answers:
                click.echo(Fore.GREEN + f"    {answer}")
        except dns.resolver.NoAnswer:
            click.echo(Fore.RED + f"[!] No {record_type} Records Found.")
        except dns.resolver.NXDOMAIN:
            click.echo(Fore.RED + f"[!] {domain} does not exist.")
        except dns.exception.Timeout:
            click.echo(Fore.RED + f"[!] Timeout occurred while querying {record_type} records.")
        except Exception as e:
            click.echo(Fore.RED + f"[!] Error querying {record_type} records: {e}")

# Function to find the real IP address by using different techniques (bypass CDN)
def find_real_ip(domain, verbose=False):
    click.echo(Fore.CYAN + "[+] Attempting to Find the Real IP Address...")
    
    try:
        # Using DNS resolvers to find real IP
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']  # Cloudflare, Google, Quad9 DNS
        answers = resolver.resolve(domain, 'A')
        
        for answer in answers:
            ip = answer.to_text()
            click.echo(Fore.GREEN + f"[+] DNS Resolved IP: {ip}")
        
        # Attempting Shodan API Lookup (replace with real API key if available)
        # Example: `https://api.shodan.io/dns/resolve?hostnames={domain}&key=API_KEY`
        shodan_url = f"https://internetdb.shodan.io/{domain}"
        response = requests.get(shodan_url)
        
        if response.status_code == 200:
            shodan_data = response.json()
            if "ip" in shodan_data:
                click.echo(Fore.GREEN + f"[+] Real IP from Shodan: {shodan_data['ip']}")
        else:
            click.echo(Fore.RED + "[!] Shodan Lookup Failed.")
        
    except Exception as e:
        click.echo(Fore.RED + f"[!] Failed to find real IP: {e}")

# Main function for the tool
@click.command()
@click.option('--domain', prompt='Enter the domain', help='Domain to gather information about')
@click.option('--wordlist', default='/usr/share/wordlists/dirb/common.txt', help='Wordlist for directory brute-forcing')
@click.option('--verbose', is_flag=True, help='Enable verbose mode')
def gather_info(domain, wordlist, verbose):
    click.echo(Fore.CYAN + "[+] Starting Information Gathering...")
    
    # Resolve domain to IP
    try:
        ip = dns.resolver.resolve(domain, 'A')[0].to_text()
        click.echo(Fore.CYAN + f"[+] Resolved IP: {ip}")
    except Exception as e:
        click.echo(Fore.RED + f"[!] Failed to resolve IP: {e}")

    # Passive Gathering: Google Dorking and WHOIS Lookup
    click.echo(Fore.CYAN + "[+] Passive Scanning (Google Dorks, WHOIS, DNS)...")

    # Google Dorks
    for dork_name, dork_query in dorks.items():
        query = dork_query.format(domain)
        click.echo(Fore.YELLOW + f"[+] Running Google Dork: {dork_name}")
        html = google_search(query, verbose)
        results = parse_results(html, verbose)
        for result in results:
            click.echo(Fore.GREEN + f"[+] {result}")

    # WHOIS Lookup
    whois_lookup(domain, verbose)

    # DNS Lookup
    dns_lookup(domain, verbose)

    # Active Gathering: Nmap, Gobuster
    click.echo(Fore.CYAN + "[+] Active Scanning (Nmap, Gobuster)...")
    
    # Nmap HTTP Script Scan
    nmap_http_scan(domain, verbose)
    
    # Gobuster Scan
    gobuster_scan(domain, wordlist, verbose)
    
    # Attempt to find real IP address
    find_real_ip(domain, verbose)

if __name__ == "__main__":
    gather_info()
