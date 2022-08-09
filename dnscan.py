#!/usr/bin/env python3
#
# dnscan copyright (C) 2013-2014 rbsec
# Licensed under GPLv3, see LICENSE for details
#
from __future__ import print_function
import packaging.version

import os
import platform
import re
import sys
import threading
import time

try:    # Ugly hack because Python3 decided to rename Queue to queue
    import Queue
except ImportError:
    import queue as Queue

try:    # Python2 and Python3 have different IP address libraries
        from ipaddress import ip_address as ipaddr
except ImportError:
    try:
        from netaddr import IPAddress as ipaddr
    except ImportError:
        if sys.version_info[0] == 2:
            print("FATAL: dnscan requires either the netaddr (python-netaddr) or ipaddress (python-ipaddress) modules.")
        else:
            print("FATAL: dnscan requires either the netaddr (python3-netaddr) or ipaddress (standard library) modules.")
        sys.exit(1)

try:
    import argparse
except:
    print("FATAL: Module argparse missing (python-argparse)")
    sys.exit(1)

try:
    import dns.query
    import dns.resolver
    import dns.zone
    import dns.dnssec
except:
    print("FATAL: Module dnspython missing (python-dnspython)")
    sys.exit(1)

if (packaging.version.parse(dns.__version__) < packaging.version.Version("2.0.0")):
    print("dnscan requires dnspython 2.0.0 or greater.\nYou can install it with `pip install -r requirements.txt`")
    sys.exit(1)

# Usage: dnscan.py -d <domain name>

class scanner(threading.Thread):
    def __init__(self, queue):
        global wildcard
        threading.Thread.__init__(self)
        self.queue = queue

    def get_name(self, domain):
            global wildcard, addresses
            try:
                if sys.stdout.isatty():     # Don't spam output if redirected
                    print(domain + '\033[K\r', end='')

                res = lookup(domain, recordtype)
                if args.tld and res:
                    nameservers = sorted(list(res))
                    ns0 = str(nameservers[0])[:-1]  # First nameserver
                    print('\033[K\r', end='')
                    print(domain + " - " + col.brown + ns0 + col.end)
                    if outfile:
                        print(ns0 + " - " + domain, file=outfile)
                if args.tld:
                    if res:
                        print('\033[K\r', end='')
                        print(domain + " - " + res)
                    return
                for rdata in res:
                    address = rdata.address
                    if wildcard:
                        for wildcard_ip in wildcard:
                            if address == wildcard_ip:
                                return
                    print('\033[K\r', end='')
                    if args.no_ip:
                        print(col.brown + domain + col.end)
                        break
                    elif args.domain_first:
                        print(domain + " - " + col.brown + address + col.end)
                    else:
                        print(address + " - " + col.brown + domain + col.end)
                    if outfile:
                        if args.domain_first:
                            print(domain + " - " + address, file=outfile)
                        else:
                            print(address + " - " + domain, file=outfile)
                    try:
                        addresses.add(ipaddr(unicode(address)))
                    except NameError:
                        addresses.add(ipaddr(str(address)))

                if ( domain != target and \
                     args.recurse and \
                     domain.count('.') - target.count('.') <= args.maxdepth
                     ):
                    # Check if subdomain is wildcard so can filter false positives in the recursive scan
                    wildcard = get_wildcard(domain)
                    for wildcard_ip in wildcard:
                        try:
                            addresses.add(ipaddr(unicode(wildcard_ip)))
                        except NameError:
                            addresses.add(ipaddr(str(wildcard_ip)))
                    if args.recurse_wildcards or not wildcard:
                        add_target(domain)  # Recursively scan subdomains
            except:
                pass

    def run(self):
        while True:
            try:
                domain = self.queue.get(timeout=1)
            except:
                return
            self.get_name(domain)
            self.queue.task_done()


class output:
    def status(self, message):
        print(col.blue + "[*] " + col.end + message)
        if outfile and not args.quick:
            print("[*] " + message, file=outfile)

    def good(self, message):
        print(col.green + "[+] " + col.end + message)
        if outfile and not args.quick:
            print("[+] " + message, file=outfile)

    def verbose(self, message):
        if args.verbose:
            print(col.brown + "[v] " + col.end + message)
            if outfile and not args.quick:
                print("[v] " + message, file=outfile)

    def warn(self, message):
        print(col.red + "[-] " + col.end + message)
        if outfile and not args.quick:
            print("[-] " + message, file=outfile)

    def fatal(self, message):
        print("\n" + col.red + "FATAL: " + message + col.end)
        if outfile and not args.quick:
            print("FATAL " + message, file=outfile)


class col:
    if sys.stdout.isatty() and platform.system() != "Windows":
        green = '\033[32m'
        blue = '\033[94m'
        red = '\033[31m'
        brown = '\033[33m'
        end = '\033[0m'
    else:   # Colours mess up redirected output, disable them
        green = ""
        blue = ""
        red = ""
        brown = ""
        end = ""


def lookup(domain, recordtype):
    try:
        res = resolver.resolve(domain, recordtype)
        return res
    except:
        return

def get_wildcard(target):

    # List of IP's for wildcard DNS
    wildcards = []
    # Use current unix time as a test subdomain
    epochtime = str(int(time.time()))
    # Prepend a letter to work around incompetent companies like CableOne
    # and their stupid attempts at DNS hijacking
    res = lookup("a" + epochtime + "." + target, recordtype)
    if res:
        for res_data in res:
            address = res_data.address
            wildcards.append(address)
            out.warn("Wildcard domain found - " + col.brown + "*." + target + col.end + " (" + address + ")")
    else:
        out.verbose("No wildcard domain found")
    return wildcards

def get_nameservers(target):
    try:
        ns = resolver.resolve(target, 'NS')
        return ns
    except:
        return

def get_v6(target):
    out.verbose("Getting IPv6 (AAAA) records")
    try:
        res = lookup(target, "AAAA")
        if res:
            out.good("IPv6 (AAAA) records found. Try running dnscan with the "+ col.green + "-6 " + col.end + "option.")
        for v6 in res:
            print(str(v6) + "\n")
            if outfile:
                print(v6, file=outfile)
    except:
        return

def get_txt(target):
    out.verbose("Getting TXT records")
    try:
        res = lookup(target, "TXT")
        if res:
            out.good("TXT records found")
        for txt in res:
            print(txt)
            if outfile:
                print(txt, file=outfile)
        print("")
    except:
        return

def get_dmarc(target):
    out.verbose("Getting DMARC records")
    try:
        res = lookup("_dmarc." + target, "TXT")
        if res:
            out.good("DMARC records found")
        for dmarc in res:
            print(dmarc)
            if outfile:
                print(dmarc, file=outfile)
        print("")
    except:
        return

def get_dnssec(target, nameserver):
    out.verbose("Checking DNSSEC")
    request = dns.message.make_query(target, dns.rdatatype.DNSKEY, want_dnssec=True)
    response = dns.query.udp(request, nameserver, timeout=1)
    if response.rcode() != 0:
        out.warn("DNSKEY lookup returned error code " + dns.rcode.to_text(response.rcode()) + "\n")
    else:
        answer = response.answer
        if len(answer) == 0:
            out.warn("DNSSEC not supported\n")
        elif len(answer) != 2:
            out.warn("Invalid DNSKEY record length\n")
        else:
            name = dns.name.from_text(target)
            try:
                dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
            except dns.dnssec.ValidationFailure:
                out.warn("DNSSEC key validation failed\n")
            else:
                out.good("DNSSEC enabled and validated")
                dnssec_values = str(answer[0][0]).split(' ')
                algorithm_int = int(dnssec_values[2])
                algorithm_str = dns.dnssec.algorithm_to_text(algorithm_int)
                print("Algorithm = " + algorithm_str + " (" + str(algorithm_int) + ")\n")

def get_mx(target):
    out.verbose("Getting MX records")
    try:
        res = lookup(target, "MX")
    except:
        return
    # Return if we don't get any MX records back
    if not res:
        return
    out.good("MX records found, added to target list")
    for mx in res:
        print(mx.to_text())
        if outfile:
            print(mx.to_text(), file=outfile)
        mxsub = re.search("([a-z0-9\.\-]+)\."+target, mx.to_text(), re.IGNORECASE)
        try:
            if mxsub.group(1) and mxsub.group(1) not in wordlist:
                queue.put(mxsub.group(1) + "." + target)
        except AttributeError:
            pass
    print("")

def zone_transfer(domain, ns, nsip):
    out.verbose("Trying zone transfer against " + str(ns))
    try:
        print(str(domain))
        zone = dns.zone.from_xfr(dns.query.xfr(str(nsip), domain, relativize=False, timeout=3),
                                 relativize=False)
        out.good("Zone transfer sucessful using nameserver " + col.brown + str(ns) + col.end)
        names = list(zone.nodes.keys())
        names.sort()
        for n in names:
            print(zone[n].to_text(n))    # Print raw zone
            if outfile:
                print(zone[n].to_text(n), file=outfile)
        sys.exit(0)
    except Exception:
        pass

def add_target(domain):
    for word in wordlist:
        patterns = [word]
        if args.alt:
            probes = ["dev", "prod", "stg", "qa", "uat", "api", "alpha", "beta",
                      "cms", "test", "internal", "staging", "origin", "stage"]
            for probe in probes:
                if probe not in word: # Reduce alterations that most likely don't exist (e.i. dev-dev.domain.com)
                    patterns.append(probe + word)
                    patterns.append(word + probe)
                    patterns.append(probe + "-" + word)
                    patterns.append(word + "-" + probe)
            if not word[-1].isdigit(): # If the subdomain has already had a number as the suffix
                for n in range(1, 6):
                    patterns.append(word + str(n))
                    patterns.append(word + "0" + str(n))
        for pattern in patterns:
            if '%%' in domain:
                queue.put(domain.replace(r'%%', pattern))
            else:
                queue.put(pattern + "." + domain)

def add_tlds(domain):
    for tld in wordlist:
        queue.put(domain + "." + tld)

def get_args():
    global args
    
    parser = argparse.ArgumentParser('dnscan.py', formatter_class=lambda prog:argparse.HelpFormatter(prog,max_help_position=40),
            epilog="Specify a custom insertion point with %% in the domain name, such as: dnscan.py -d dev-%%.example.org")
    target = parser.add_mutually_exclusive_group(required=True) # Allow a user to specify a list of target domains
    target.add_argument('-d', '--domain', help='Target domains (separated by commas)', dest='domain', required=False)
    target.add_argument('-l', '--list', help='File containing list of target domains', dest='domain_list', required=False)
    parser.add_argument('-w', '--wordlist', help='Wordlist', dest='wordlist', required=False)
    parser.add_argument('-t', '--threads', help='Number of threads', dest='threads', required=False, type=int, default=8)
    parser.add_argument('-6', '--ipv6', action="store_true", help='Scan for AAAA records', dest='ipv6')
    parser.add_argument('-z', '--zonetransfer', action="store_true", help='Only perform zone transfers', dest='zonetransfer')
    parser.add_argument('-r', '--recursive', action="store_true", help="Recursively scan subdomains", dest='recurse')
    parser.add_argument('--recurse-wildcards', action="store_true", help="Recursively scan wildcards (slow)", dest='recurse_wildcards')
    parser.add_argument('-m', '--maxdepth', help='Maximal recursion depth (for brute-forcing)', dest='maxdepth', required=False, type=int, default=5)
    parser.add_argument('-a', '--alterations', action="store_true", help='Scan for alterations of subdomains (slow)', dest='alt')
    parser.add_argument('-R', '--resolver', help="Use the specified resolvers (separated by commas)", dest='resolvers', required=False)
    parser.add_argument('-L', '--resolver-list', help="File containing list of resolvers", dest='resolver_list', required=False)
    parser.add_argument('-T', '--tld', action="store_true", help="Scan for TLDs", dest='tld')
    parser.add_argument('-o', '--output', help="Write output to a file", dest='output_filename', required=False)
    parser.add_argument('-i', '--output-ips', help="Write discovered IP addresses to a file", dest='output_ips', required=False)
    parser.add_argument('-D', '--domain-first', action="store_true", help='Output domain first, rather than IP address', dest='domain_first')
    parser.add_argument('-N', '--no-ip', action="store_true", help='Don\'t print IP addresses in the output', dest='no_ip')
    parser.add_argument('-v', '--verbose', action="store_true", help='Verbose mode', dest='verbose')
    parser.add_argument('-n', '--nocheck', action="store_true", help='Don\'t check nameservers before scanning', dest='nocheck')
    parser.add_argument('-q', '--quick', action="store_true", help='Only perform zone transfer and subdomains scan, with minimal output to file', dest='quick')
    args = parser.parse_args()

def setup():
    global targets, wordlist, queue, resolver, recordtype, outfile, outfile_ips
    if args.domain:
        targets = args.domain.split(",")
    if args.tld and not args.wordlist:
        args.wordlist = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tlds.txt")
    else:
        if not args.wordlist:   # Try to use default wordlist if non specified
            args.wordlist = os.path.join(os.path.dirname(os.path.realpath(__file__)), "subdomains.txt")

    # Open file handle for output
    try:
        outfile = open(args.output_filename, "w")
    except TypeError:
        outfile = None
    except IOError:
        out.fatal("Could not open output file: " + args.output_filename)
        sys.exit(1)
    if args.output_ips:
        outfile_ips = open(args.output_ips, "w")
    else:
        outfile_ips = None

    try:
        wordlist = open(args.wordlist).read().splitlines()
    except:
        out.fatal("Could not open wordlist " + args.wordlist)
        sys.exit(1)
    # Number of threads should be between 1 and 32
    if args.threads < 1:
        args.threads = 1
    elif args.threads > 32:
        args.threads = 32
    queue = Queue.Queue()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    if args.resolver_list:
        try:
            resolver.nameservers = open(args.resolver_list, 'r').read().splitlines()
        except FileNotFoundError:
            out.fatal("Could not open file containing resolvers: " + args.resolver_list)
            sys.exit(1)
    elif args.resolvers:
        resolver.nameservers = args.resolvers.split(",")

    # Record type
    if args.ipv6:
        recordtype = 'AAAA'
    elif args.tld:
        recordtype = 'NS'
    else:
        recordtype = 'A'


if __name__ == "__main__":
    global wildcard, addresses, outfile_ips
    addresses = set([])
    out = output()
    get_args()
    setup()
    if args.nocheck == False:
        try:
            resolver.resolve('.', 'NS')
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            out.warn("Failed to resolve '.' - server may be buggy. Continuing anyway....")
            pass
        except:
            out.fatal("No valid DNS resolver. This can occur when the server only resolves internal zones")
            out.fatal("Set a custom resolver with -R <resolver>")
            out.fatal("Ignore this warning with -n --nocheck\n")
            sys.exit(1)

    if args.domain_list:
        out.verbose("Domain list provided, will parse {} for domains.".format(args.domain_list))
        if not os.path.isfile(args.domain_list):
            out.fatal("Domain list {} doesn't exist!".format(args.domain_list))
            sys.exit(1)
        with open(args.domain_list, 'r') as domain_list:
            try:
                targets = list(filter(bool, domain_list.read().split('\n')))
            except Exception as e:
                out.fatal("Couldn't read {}, {}".format(args.domain_list, e))
                sys.exit(1)
    for subtarget in targets:
        global target
        target = subtarget
        out.status("Processing domain {}".format(target))
        if args.resolver_list:
            out.status("Using resolvers from: {}".format(args.resolver_list))
        elif args.resolvers:
            out.status("Using specified resolvers: {}".format(args.resolvers))
        else:
            out.status("Using system resolvers: {}".format(",".join(resolver.nameservers)))
        if args.tld and not '%%' in target:
            if "." in target:
                out.warn("Warning: TLD scanning works best with just the domain root")
            out.good("TLD Scan")
            add_tlds(target)
        else:
            queue.put(target)   # Add actual domain as well as subdomains

            # These checks will all fail if we have a custom injection point, so skip them
            if not '%%' in target:
                nameservers = get_nameservers(target)
                out.good("Getting nameservers")
                targetns = []       # NS servers for target
                nsip = None
                try:    # Subdomains often don't have NS recoards..
                    for ns in nameservers:
                        ns = str(ns)[:-1]   # Removed trailing dot
                        res = lookup(ns, "A")
                        for rdata in res:
                            targetns.append(rdata.address)
                            nsip = rdata.address
                            print(nsip + " - " + col.brown + ns + col.end)
                            if not args.quick:
                                if outfile:
                                    print(nsip + " - " + ns, file=outfile)
                        zone_transfer(target, ns, nsip)
                except SystemExit:
                    sys.exit(0)
                except:
                    out.warn("Getting nameservers failed")
                out.warn("Zone transfer failed\n")
                if args.zonetransfer:
                    sys.exit(0)

                if not args.quick:
                    get_v6(target)
                    get_txt(target)
                    get_dmarc(target)

                    # These checks need a proper nameserver, the systemd stub doesn't work
                    if nsip:
                        get_dnssec(target, nsip)
                    else:
                        get_dnssec(target, resolver.nameservers[0])
                    get_mx(target)
            wildcard = get_wildcard(target)
            for wildcard_ip in wildcard:
                try:
                    addresses.add(ipaddr(unicode(wildcard_ip)))
                except NameError:
                    addresses.add(ipaddr(str(wildcard_ip)))
            out.status("Scanning " + target + " for " + recordtype + " records")
            add_target(target)

        for i in range(args.threads):
            t = scanner(queue)
            t.daemon = True
            t.start()
        try:
            for i in range(args.threads):
                t.join(1024)       # Timeout needed or threads ignore exceptions
        except KeyboardInterrupt:
            out.fatal("Caught KeyboardInterrupt, quitting...")
            if outfile:
                outfile.close()
            sys.exit(1)
        print("                                        ")
        if outfile_ips:
            for address in sorted(addresses):
                print(address, file=outfile_ips)
    if outfile:
        outfile.close()
    if outfile_ips:
        outfile_ips.close()
