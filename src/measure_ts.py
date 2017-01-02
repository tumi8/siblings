#!/usr/bin/env python3
'''
Conducts TCP TS measurements towards a target list (option 1) on a specific
interface (option 2).
Exports result as a .pcap file by calling tcpdump.
Concept is to create a number of processes, which in turn fire up thousands
of threads. These conduct the measurements.
Threads receive measurement jobs via a queue.
# flake8: ignore=E501
'''
import sys
import subprocess as sp
import time
import datetime
from threading import Thread
import csv
import socket
import urllib3
from multiprocessing import Process  # noqa: F401 (module needed, but use not picked up)
import concurrent.futures
import multiprocessing
import string
import random
import logging


input_csv = ""  # sys.argv[1]
capture_if = ""  # sys.argv[2]


def start_capture():
    """ calls tcpdump to capture packets """
    now = datetime.datetime.now()
    date = datetime.date.today()
    pcapfile = "sibling-measurement-" + str(date.year) + str(date.month).zfill(2) + \
        str(date.day).zfill(2) + "-" + str(now.hour).zfill(2) + str(now.minute).zfill(2) + ".pcap"
    pcapfile = sys.argv[1] + "-" + pcapfile
    try:
        f_tcpdump = open(pcapfile + ".pcaplog", "w")
    except:
        sys.stderr.write("log file opening failed\n")
        sys.exit()

    sys.stderr.write("capturing to file: " + str(pcapfile) + "\n")
    # -C 2014 to rotate after every 1GB of capture '-C 1024'
    tcpdumpprocesslocal = sp.Popen(['/usr/sbin/tcpdump', '-ni', capture_if, 'tcp', '-w', pcapfile], stdout=f_tcpdump, stderr=f_tcpdump)
    time.sleep(2)  # to allow for tcpdump startup before sending first packet
    returncode = tcpdumpprocesslocal.poll()
    if returncode:
        sys.stderr.write("tcpdump failed!\n")
        sys.exit()
    return tcpdumpprocesslocal


class Consumer(multiprocessing.Process):
    """ Measurement class, consumes tasks from queues"""
    # inspired by : https://pymotw.com/2/multiprocessing/communication.html
    def __init__(self, task_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.threads = []

    def run(self):
        # proc_name = self.name  # TODO: test removing this
        while True:
            next_task = self.task_queue.get()
            self.task_queue.task_done()
            if next_task is None:
                continue
            t = Thread(target=next_task)
            self.threads.append(t)
            while True:
                try:
                    t.start()
                except:
                    time.sleep(0.2)
                    continue
                break

    def __exit__(self):
        for t in self.threads:
            t.join()


def randurl(size=10, chars=string.ascii_uppercase + string.digits):
    """ creates a random URL to query to avoid caching"""
    return ''.join(random.choice(chars) for _ in range(size))


class DummyMsrIPPort(object):
    """ measurement class for ip and port"""
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def __call__(self):
        logging.debug("DummyMsrIPPort: not connecting to IP {} on port {}".format(self.ip, self.port))
        if ':' in self.ip:  # simplistic IPv6 detection
            url = 'http://[' + self.ip + ']:' + self.port
            # conn = urllib3.connection_from_url('http://['+ip+']:'+port, retries=0, socket_options=socket_options)
        else:  # IPv4
            url = 'http://' + self.ip + ':' + self.port
            # conn = urllib3.connection_from_url('http://'+ip+':'+port, retries=0, socket_options=socket_options)
        logging.debug("url: {}".format(url))
        time.sleep(10)


class MsrIPPort(object):
    """ measurement class for ip and port """
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def __call__(self):
        ip = self.ip
        port = self.port
        # wait random time before starting measurement to better spread measurements within each minute
        time.sleep(random.randint(0, 60))
        self.start_time = time.time()
        self.end_time = self.start_time + 60 * 60 * 10  # measure for 10h

        # set TCP keepalive as socket option: if not closed by server, we can
        # collect timestamps without a new connection
        socket_options = urllib3.connection.HTTPConnection.default_socket_options + [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1), ]
        if ':' in ip:  # simplistic IPv6 detection
            url = 'http://[' + ip + ']:' + port
        else:  # IPv4
            url = 'http://' + ip + ':' + port
        logging.debug("url: {}".format(url))
        conn = urllib3.connection_from_url(url, retries=0, socket_options=socket_options)
        conn.headers = urllib3.make_headers(keep_alive=True, user_agent="python-urllib3/0.6__research_scan")
        self.i = 0
        while time.time() < self.end_time:
            logging.debug("making connection #" + str(self.i) + " to " + str(self.ip) + " on port " + str(self.port))
            try:
                conn.request('GET', '/research_scan_' + randurl(), timeout=urllib3.util.timeout.Timeout(10))
            except urllib3.exceptions.MaxRetryError as e:
                logging.debug("MaxRetryError on IP: " + str(self.i) + " to " + str(self.ip) + "on port " + str(self.port) + " exception: " + str(e.args))
                pass
            except urllib3.exceptions.TimeoutError as e:
                print("TimeoutError on IP: " + str(self.i) + " to " + str(self.ip) + " exception: " + str(e.args))
                logging.warning("TimeoutError on IP: " + str(self.i) + " to " + str(self.ip) + " on port " + str(self.port) + " exception: " + str(e.args))
                break
            time.sleep(60)
            self.i += 1
        conn.close()


def set_sys_settings():
    """
    set linux system settings to optimize TS collection.
    Please note that these settings are not sane defaults
    and should only be used during the measurement on a specific machine.
    Obviously, restore to values before running this application would be
    a good improvement here.
    """
    # these also apply to IPv6: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
    f = open('/proc/sys/net/ipv4/tcp_keepalive_time', 'w')  # Start TCP keepalive after 10s
    f.write('10')
    f.close()
    f = open('/proc/sys/net/ipv4/tcp_keepalive_intvl', 'w')  # sesnd TCP keepalive packet every 10s
    f.write('10')
    f.close()
    f = open('/proc/sys/net/core/wmem_max', 'w')  # use a lot of buffer
    f.write('212992000')
    f.close()
    f = open('/proc/sys/net/core/wmem_default', 'w')  # use a lot of buffer
    f.write('212992000')
    f.close()
    f = open('/proc/sys/kernel/pid_max', 'w')  # allow a lot of PIDs for a great many threads
    f.write('327680')
    f.close()
    f = open('/proc/sys/kernel/threads-max', 'w')  # see above
    f.write('1283200')
    f.close()
    f = open('/proc/sys/vm/overcommit_ratio', 'w')  # python parallelism seems to require a lot of VM, which we can overcommit without problems
    f.write('5000')
    f.close()
    f = open('/proc/sys/vm/overcommit_memory', 'w')  # make sure vm overcommitting is active
    f.write('1')
    f.close()


def unset_sys_settings():
    """ reset TCP Keepalive to default"""
    f = open('/proc/sys/net/ipv4/tcp_keepalive_time', 'w')
    f.write('7200')
    f.close()
    f = open('/proc/sys/net/ipv4/tcp_keepalive_intvl', 'w')
    f.write('60')
    f.close()


def main(argv):
    dryrun = True
    global input_csv
    global capture_if
    input_csv = sys.argv[1]
    capture_if = sys.argv[2]
    try:
        if sys.argv[3] == "dryrun":
            pass
        elif sys.argv[3] == "measure":
            dryrun = False
    except:
        pass

    print("DRYRUN: {}".format(dryrun))

    if not dryrun:
        set_sys_settings()  # configure tcp keepalive system-wide settings
        tcpdumpprocess = start_capture()  # start tcpdump capture

    format = '%(asctime)s - %(levelname)-7s - %(message)s'
    now = datetime.datetime.now()
    date = datetime.date.today()
    logfilename = "sibling-measurement-" + str(date.year) + str(date.month).zfill(2) + \
        str(date.day).zfill(2) + "-" + str(now.hour).zfill(2) + str(now.minute).zfill(2) + ".log"
    logging.basicConfig(filename=input_csv + "-" + logfilename, level=logging.DEBUG, format=format, filemode='w')

    starttime = time.time()

    tasks = multiprocessing.JoinableQueue()
    num_consumers = multiprocessing.cpu_count() - 1
    sys.stderr.write('Creating %d consumers.\n' % num_consumers)
    consumers = [Consumer(tasks) for i in range(num_consumers)]
    for w in consumers:
        w.start()

    with open(sys.argv[1]) as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            # for i in row[1:]: # this is for reading format domain,ip6,ip4
            logging.debug("DEBUG: row len is {}, row: {}".format(len(row), row))
            # this reads a line format of RA_6211;109.70.107.25;2001:4130:107::25;80;ripeatlas
            if len(row) == 5:
                hn = row[0]  # hostname not currently used # noqa: F841
                ip4 = row[1]
                ip6 = row[2]
                port = row[3]
                if sys.platform != "darwin":  # function is not implemented on macOS
                    while tasks.qsize() > num_consumers:
                        time.sleep(0.0001)  # sleep a bit to avoid flooding the queue
                logging.debug("feeding IPs+Port into task queue: {} {} {}".format(ip4, ip6, port))
                assert 0 < int(port) < 2**16
                if not dryrun:
                    tasks.put(MsrIPPort(ip4, port))
                    tasks.put(MsrIPPort(ip6, port))
                else:
                    tasks.put(DummyMsrIPPort(ip4, port))
                    tasks.put(DummyMsrIPPort(ip6, port))
            else:
                for i in row:  # this is for format <ip,>*n (ip1, ip2, ip3)
                    if i:
                        if sys.platform != "darwin":  # function is not implemented on macOS
                            while tasks.qsize() > num_consumers:
                                time.sleep(0.0001)  # sleep a bit to avoid flooding the queue
                        logging.debug("feeding IP into task queue: " + str(i))
                        if not dryrun:
                            tasks.put(MsrIPPort(i, "80"))
                        else:
                            tasks.put(DummyMsrIPPort(i, "80"))

    sys.stderr.write("all threads started after seconds: " + str(time.time() - starttime) + "\n")
    logging.info("all threads started after seconds: " + str(time.time() - starttime))
    if not dryrun:
        time.sleep(60 * 60 * 10)  # sleep main process for 10 hours
    else:
        time.sleep(30)  # just sleep a bit so all the processes can exit

    for w in consumers:
        w.terminate()

    if not dryrun:
        tcpdumpprocess.terminate()  # important to 'terminate' so pcap file is written out nicely
        time.sleep(60)
        unset_sys_settings()
        time.sleep(1)


if __name__ == ("__main__"):
    main(sys.argv)
