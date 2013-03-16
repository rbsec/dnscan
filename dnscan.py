#!/usr/bin/env python
import dns.query
import dns.resolver
import dns.zone
import Queue
import sys
import threading

# Usage: dnscan.py <domain name> <wordlist>

class scanner(threading.Thread):
    def __init__(self, queue):
        global wildcard
        threading.Thread.__init__(self)
        self.queue = queue

    def get_name(self, domain):
            global wildcard
            try:
                sys.stdout.write(domain + "                              \r")
                sys.stdout.flush()
                res = lookup(domain)
                for rdata in res:
                    if wildcard:
                        if rdata.address == wildcard:
                            return
                    print rdata.address + " - " + domain
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


def add_target(domain):
    for word in wordlist:
        queue.put(word + "." + domain)

def get_args():
    global target,wordlist
    target = sys.argv[1]
    wordlist = open(sys.argv[2]).read().splitlines()

def lookup(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    try:
        res = resolver.query(domain, 'A')
        return res
    except:
        return

def get_wildcard(target):
    res = lookup("nonexistantdomain" + "." + target)
    if res:
        print "[+] Wildcard domain found - " + res[0].address
        return res[0].address
    else:
        print "[+] No wildcard domain found"

def get_nameservers(target):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    try:
        ns = resolver.query(target, 'NS')
        return ns
    except:
        return

def zone_transfer(domain, ns):
    print "[*] Trying zone transfer against " + str(ns)
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, relativize=False),
                                 relativize=False)
        print "[+] Zone transfer sucessful"
        names = zone.nodes.keys()
        names.sort()
        for n in names:
            print zone[n].to_text(n)    # Print raw zone
        sys.exit()
    except Exception, e:
        pass

if __name__ == "__main__":
    global wildcard, queue
    num_threads = 8
    queue = Queue.Queue()
    get_args()
    nameservers = get_nameservers(target)
    for ns in nameservers:
        zone_transfer(target, ns)
    print "[-] Zone transfer failed"
    wildcard = get_wildcard(target)
    print "[*] Scanning " + target
    add_target(target)

    for i in range(num_threads):
        t = scanner(queue)
        t.setDaemon(True)
        t.start()
    try:
        for i in range(num_threads):
            t.join(1024)       # Timeout needed or threads ignore exceptions
    except KeyboardInterrupt:
        print "[-] Quitting..."
