#!/usr/bin/env python3
'''
Conducts TCP TS measurements towards a target list (option 1) on a specific
interface (option 2).
Exports result as a .pcap file by calling tcpdump.
Concept is to create a number of processes, which in turn fire up thousands
of threads. These conduct the measurements.
Threads receive measurement jobs via a queue.
'''
import sys
import subprocess as sp
import time, datetime
from threading import Thread
import csv
import socket
import urllib3
from multiprocessing import Process
import concurrent.futures
import multiprocessing
import string
import random
import gc

input_csv = sys.argv[1]
capture_if = sys.argv[2]

def start_capture():
""" calls tcpdump to capture packets """
	now=datetime.datetime.now()
	date=datetime.date.today()
	pcapfile="sibling-measurement-"+str(date.year)+str(date.month).zfill(2)+ \
		str(date.day).zfill(2)+"-"+str(now.hour).zfill(2)+str(now.minute).zfill(2)+".pcap"
	pcapfile=sys.argv[1]+"-"+pcapfile
	try:
		f_tcpdump = open(pcapfile+".pcaplog","w")
	except:
		sys.stderr.write("log file opening failed\n")
		sys.exit()

	sys.stderr.write("capturing to file: " + str(pcapfile) + "\n")
	# -C 2014 to rotate after every 1GB of capture '-C 1024'
	tcpdumpprocesslocal = sp.Popen(['/usr/sbin/tcpdump', '-ni', capture_if, 'tcp', '-w', pcapfile], stdout = f_tcpdump, stderr= f_tcpdump)
	time.sleep(2) #to allow for tcpdump startup before sending first packet
	returncode=tcpdumpprocesslocal.poll()
	if(returncode):
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
		proc_name = self.name
		while True:
			next_task = self.task_queue.get()
			#print("Got element, queue size: " + str(self.task_queue.qsize()) + "\n")
			self.task_queue.task_done()
			if next_task is None:
                #if(random.randint(0,100) == 0):
                #gc.collect()
			    continue
			t = Thread(target=next_task)
			self.threads.append(t)
			while True:
				try:
					t.start()
				except:
					time.sleep(0.2)
					continue
				break;

	def __exit__ (self):
		for t in self.threads:
			t.join()

def randurl(size=10, chars=string.ascii_uppercase + string.digits):
""" creates a random URL to query to avoid caching"""
	return ''.join(random.choice(chars) for _ in range(size))


class dummy_mkget(object):
""" dummy class for debugging"""
	def __init__(self, ip):
		self.ip = ip
	def __call__(self):
		print("not really making connection to " + str(self.ip))
		time.sleep(10)

class rl_mkget(object):
""" measurement class"""
	def __init__(self, ip):
		self.ip = ip
	def __call__(self):
		ip=self.ip
		# wait random time before starting measurement to better spread measurements within each minute
		time.sleep(random.randint(0,60))
		self.start_time = time.time()
		self.end_time = self.start_time + 60*60*10 # measure for 10h

		# set TCP keepalive as socket option: if not closed by server, we can
		# collect timestamps without a new connection
		socket_options = urllib3.connection.HTTPConnection.default_socket_options + [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1), ]
		if ':' in ip: # simplistic IPv6 detection
			conn = urllib3.connection_from_url('http://['+ip+']:80', retries=0, socket_options=socket_options)
		else: # IPv4
			conn = urllib3.connection_from_url('http://'+ip+':80', retries=0, socket_options=socket_options)

		conn.headers = urllib3.make_headers(keep_alive=True,user_agent="python-urllib3/0.6__research_scan")
		self.i=0
		while time.time() < self.end_time:
			print("making connection #" + str(self.i) + " to " +str(self.ip))
			try:
				conn.request('GET','/research_scan_'+randurl(), timeout=urllib3.util.timeout.Timeout(10))
			except urllib3.exceptions.MaxRetryError as e:
				print("MaxRetryError on IP: " + str(self.i) + " to " +str(self.ip) + " exception: " + str(e.args))
				pass
			except urllib3.exceptions.TimeoutError as e:
				print("TimeoutError on IP: " + str(self.i) + " to " +str(self.ip) + " exception: " + str(e.args))
				break;
			time.sleep(60)
			self.i+=1
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
	f=open('/proc/sys/net/ipv4/tcp_keepalive_time','w') # Start TCP keepalive after 10s
	f.write('10')
	f.close()
	f=open('/proc/sys/net/ipv4/tcp_keepalive_intvl','w') # sesnd TCP keepalive packet every 10s
	f.write('10')
	f.close()
	f=open('/proc/sys/net/core/wmem_max','w') # use a lot of buffer
	f.write('212992000')
	f.close()
	f=open('/proc/sys/net/core/wmem_default','w') # use a lot of buffer
	f.write('212992000')
	f.close()
	f=open('/proc/sys/kernel/pid_max','w') # allow a lot of PIDs for a great many threads
	f.write('327680')
	f.close()
	f=open('/proc/sys/kernel/threads-max','w') # see above
	f.write('1283200')
	f.close()
	f=open('/proc/sys/vm/overcommit_ratio','w') # python parallelism seems to require a lot of VM, which we can overcommit without problems
	f.write('5000')
	f.close()
	f=open('/proc/sys/vm/overcommit_memory','w') # make sure vm overcommitting is active
	f.write('1')
	f.close()

def unset_sys_settings():
""" reset TCP Keepalive to default"""
	f=open('/proc/sys/net/ipv4/tcp_keepalive_time','w')
	f.write('7200')
	f.close()
	f=open('/proc/sys/net/ipv4/tcp_keepalive_intvl','w')
	f.write('60')
	f.close()


if __name__ == ("__main__"):
	set_sys_settings() # configure tcp keepalive system-wide settings
	tcpdumpprocess = start_capture() # start tcpdump capture
	starttime=time.time()

	tasks = multiprocessing.JoinableQueue()
	num_consumers = multiprocessing.cpu_count() -1
	sys.stderr.write('Creating %d consumers.\n' % num_consumers)
	consumers = [Consumer(tasks) for i in range(num_consumers)]
	for w in consumers:
		w.start()

	with open( sys.argv[1]) as csvfile:
		csvreader=csv.reader(csvfile)
		for row in csvreader:
			#for i in row[1:]: # this is for reading format domain,ip6,ip4
			for i in row: # this is for format <ip,>*n
				if i:
					while(tasks.qsize() > num_consumers):
						time.sleep(0.0001) # sleep a bit to avoid flooding the queue
					print("feeding IP into task queue: " + str(i))
					tasks.put(rl_mkget(i))

	sys.stderr.write("all threads started after seconds: "+str(time.time()-starttime)+"\n")
	time.sleep(60*60*10) # sleep main process for 10 hours
	for w in consumers:
		w.terminate()

	tcpdumpprocess.terminate() # important to 'terminate' so pcap file is written out nicely
	time.sleep(60)
	unset_sys_settings()
	time.sleep(1)
