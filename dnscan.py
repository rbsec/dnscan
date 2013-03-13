#!/usr/bin/env python
import Queue
import threading
import socket
import sys
from time import sleep

# Usage: dnscan.py <domain name> <wordlist>

target = sys.argv[1]

# Opens wordlist, read and strip carriage returns
wordlist = open(sys.argv[2]).read().splitlines()

queue = Queue.Queue()
          
class queue_manager(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def get_name(self, word):
            try:
                sys.stdout.write(word + "                              \r")
                socket.setdefaulttimeout(1)
                ip = socket.gethostbyname(word + "." + target)
            except socket.gaierror, socket.timeout:
                pass
            else:       # 200
                print ip + " - " + word + "." + target

    def run(self):
        while True:
            try:
                word = self.queue.get(timeout=2)
            except:
                return
            self.get_name(word)
            self.queue.task_done()


def main():
    for i in range(32):      # Number of threads
        t = queue_manager(queue)
        t.setDaemon(True)
        t.start()

    for word in wordlist:
        queue.put(word)

    queue.join()

main()
