#!/usr/bin/env python
import Queue
import threading
import dns.resolver
import sys
from time import sleep

# Usage: dnscan.py <domain name> <wordlist>

class queue_manager(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def get_name(self, domain):
            try:
                sys.stdout.write(domain + "                              \r")
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                res = resolver.query(domain, 'A')
                for rdata in res:
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

def main():
    get_args()
    for i in range(8):      # Number of threads
        t = queue_manager(queue)
        t.setDaemon(True)
        t.start()
    add_target(target)
    queue.join()

queue = Queue.Queue()
main()
