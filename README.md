# DarkRecon
Overview: DarkRecon is a powerful information-gathering tool designed for cybersecurity professionals, ethical hackers, and penetration testers. It automates the process of collecting critical information about a target domain, utilizing a combination of passive and active scanning techniques to unveil hidden data, vulnerabilities, and insights.

Key Features:

Domain Resolution: Automatically resolves the target domain to its corresponding IP address, allowing for accurate mapping of the target.

Google Dorking: Leverages popular Google Dorks to uncover sensitive files, directories, admin pages, and email addresses associated with the target domain.

WHOIS Lookup: Retrieves registration details for the target domain, providing information about the owner, registrar, and contact details.

Comprehensive DNS Lookup: Performs extensive DNS queries across multiple record types (A, MX, NS, TXT, CNAME, AAAA, SOA, SRV) to gather information about the domain's DNS setup.

Nmap HTTP Script Scanning: Executes an advanced Nmap scan using all available HTTP-related scripts to extract detailed service information, potential vulnerabilities, and configuration issues from web servers.

Gobuster Directory Scanning: Uses Gobuster for directory brute-forcing, filtering results to display relevant HTTP status codes (200, 302, 403) for easy identification of accessible resources.

Real IP Address Discovery: Attempts to find the real IP address of the target domain, bypassing proxies or CDNs (such as Cloudflare) using multiple DNS resolvers and external services like Shodan.

Verbose Mode: Offers a verbose mode for detailed output, helping users to understand the processes and results better.

Use Cases:

Ideal for ethical hackers and security professionals conducting penetration tests.
Useful for bug bounty hunters looking to gather information on targets.
Beneficial for security researchers analyzing the exposure of web applications.
Installation Requirements:

Python 3.x
Required libraries: requests, beautifulsoup4, dnspython, click, whois, colorama, etc.
External tools: Nmap, Gobuster.
