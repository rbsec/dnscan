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

Wordlists
---------

Five wordlists are supplied with dnscan.

The first three (**subdomains-100.txt**, **subdomains-500.txt**, **subdomains-1000.txt** and **subdomains-10000.txt**) were created by analysing the most commonly occuring subomdains in approximately 86,000 zone files that were transferred as part of a separate research project. These wordlists are sorted by the popularity of the subdomains (more strictly by the percentage of zones that contained them in the dataset).

The final (and default) wordlist (**subdomains.txt**) is based on the top 500 subdomains by popularity, but has had a number of manual additions made based on domains identified during testing.

This list is sorted alphabetically and currently contains approximately **700** entries.
