dnscan
======

dnscan is a python wordlist-based DNS subdomain scanner.

The script will first try to perform a zone transfer using each of the target domain's nameservers.

If this fails, it will lookup TXT and MX records for the domain, and then perform a recursive subudomain scan using the supplied wordlist.

Usage
-----

dnscan.py -d \<domain\> [OPTIONS]

#### Mandatory Arguments
    -d  --domain                              Target domain 
    
#### Optional Arguments
    -w --wordlist <wordlist>                  Wordlist of subdomains to use
    -t --threads <threadcount>                Threads (1 - 32), default 8
    -6 --ipv6                                 Scan for IPv6 records (AAAA)
    -v --verbose                              Verbose output
    -h --help                                 Display help text
