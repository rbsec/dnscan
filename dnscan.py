#!/usr/bin/env python
import Queue
import threading
import dns.resolver
import sys

# Usage: dnscan.py <domain name> <wordlist>

class queue_manager(threading.Thread):
    global wildcard
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def get_name(self, domain):
            global wildcard
            try:
                sys.stdout.write(domain + "                              \r")
                res = lookup(domain)
                for rdata in res:
                    if wildcard:
                        if rdata.address == wildcard:
                            return
                    print rdata.address + " - " + domain
                    add_target(domain)
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
    # Opens wordlist, read and strip carriage returns
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
        print "[+] Wildcard IP found - " + res[0].address
        return res[0].address

def main():
    global wildcard
    get_args()
    wildcard = get_wildcard(target)
    for i in range(8):      # Number of threads
        t = queue_manager(queue)
        t.setDaemon(True)
        t.start()
    add_target(target)
    queue.join()

queue = Queue.Queue()
main()
