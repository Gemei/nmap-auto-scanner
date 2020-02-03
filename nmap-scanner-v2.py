#!/usr/bin/python
#Version 2.0.4
import os, sys, subprocess, multiprocessing, curses, time
from multiprocessing.pool import ThreadPool
from progress.bar import IncrementalBar
from termcolor import colored

if len(sys.argv) < 4:
	print(colored('[*] Usage:	python nmap-scanner-v2.py <File with list of hosts> (UDP|TCP|UDP-Full|TCP-Full|Athena|Circe|Zeus) <number of threads> (<= 10) True|False\n','blue'))
	print('[*] UDP: 	UDP default ports scan\n'+
		  '[*] TCP: 	TCP default ports scan\n'+
		  '[*] UDP-Full:	UDP all ports scan\n'+
		  '[*] TCP-Full:	TCP all ports scan\n'+
		  '[*] Athena:	TCP & UDP default ports scan\n'+
		  '[*] Crice:	TCP full & UDP default ports scan\n'+
		  '[*] Zeus:	TCP & UDP full ports scan\n')
	print('[*] Optional Extra Options: True|False 	(-A -sV --script=default,vuln) # Default is False\n')
	print(colored('[*] Example:	python nmap-scanner-v2.py hosts.txt Circe 5','red'))
	exit()


scan_type = sys.argv[2]
nthreades = int(sys.argv[3])
if len(sys.argv) < 5:
	extra_options = "False"
else:
	extra_options = sys.argv[4]
print_counter = 2

def get_hosts_list():
	with open(sys.argv[1]) as file:
		hosts = file.readlines()
	return hosts

def udp():
	print("UDP Default Scan")
	scans = []
	extras = ""

	if "True" in extra_options:
		extras="-sV -A --script=default,vuln"
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sU -Pn %s %s -oA ./%s/%s-UDP-DEFAULT"%(extras,host,host,host))

	run_threads(scans)

def tcp():
	print("TCP Default Scan")
	scans = []
	extras = ""

	if "True" in extra_options:
		extras="-sV -A --script=default,vuln"
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sS -Pn %s %s -oA ./%s/%ss-TCP-DEFAULT"%(extras,host,host,host))

	run_threads(scans)

def udp_full():
	print("UDP Full Ports Scan")
	scans = []
	extras = ""

	if "True" in extra_options:
		extras="-sV -A --script=default,vuln"
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sU -Pn -p- %s %s -oA ./%s/%s-UDP-FULL"%(extras,host,host,host))

	run_threads(scans)

def tcp_full():
	print("TCP Full Ports Scan")
	scans = []
	extras = ""

	if "True" in extra_options:
		extras="-sV -A --script=default,vuln"
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sS -Pn -p- %s %s -oA ./%s/%s-TCP-FULL"%(extras,host,host,host))

	run_threads(scans)

def athena():
	print("All Default Ports Scan")
	scans = []
	extras = ""

	if "True" in extra_options:
		extras="-sV -A --script=default,vuln"
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sS -Pn %s %s -oA ./%s/%s-TCP-DEFAULT"%(extras,host,host,host))
		scans.append("nmap -vv -sU -Pn %s %s -oA ./%s/%s-UDP-DEFAULT"%(extras,host,host,host))

	run_threads(scans)

def zeus():
	print("All Full Ports Scan")
	scans = []
	extras = ""

	if "True" in extra_options:
		extras="-sV -A --script=default,vuln"	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sS -Pn -p- %s %s -oA ./%s/%s-TCP-FULL"%(extras,host,host,host))
		scans.append("nmap -vv -sU -Pn -p- %s %s -oA ./%s/%s-UDP-FULL"%(extras,host,host,host))

	run_threads(scans)
	
def crice():
	print("TCP Full Ports Scan With Default Ports For UDP")
	scans = []
	extras = ""

	if "True" in extra_options:
		extras="-sV -A --script=default,vuln"
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sS -Pn -p- %s %s -oA ./%s/%s-TCP-FULL"%(extras,host,host,host))
		scans.append("nmap -vv -sU -Pn %s %s -oA ./%s/%s-UDP-DEFAULT"%(extras,host,host,host))
		#scans.append("ping -c 10 %s"%(host))
		#scans.append("ping -c 20 %s"%(host))

	run_threads(scans)
	
def make_dir(host):
	if not os.path.isdir(host):
		subprocess.call(["mkdir", str(host)])

def create_process(scan):
	global print_counter

	proc = subprocess.Popen(scan, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

	stdout, stderr = proc.communicate()
	update_progress_bar()
	if stderr:
		print_there(print_counter+1,0,colored("\n[X] Error: "+stderr,'red'))
		print_counter += 1
	if stdout:
		for line in stdout.splitlines():
		    if "Discovered" in line:
		        print_there(print_counter+1,0,colored("\n[X] Open Port: "+line,'green'))
		        print_counter += 1
	print_counter += 1


def run_threads(scans):
	global pbar

	number_of_scans=len(scans)
	pbar = IncrementalBar('Scanning::', max=number_of_scans, suffix='%(index)d/%(max)d | %(percent).1f%% | %(elapsed)ds')
	animation = multiprocessing.Process(target=animation_start)
	animation.start()

	pool = ThreadPool(nthreades)
	pool.map(create_process, (scans))
	pool.close()
	pool.join()
	
	pbar.finish()
	print("\n"*print_counter)
	print(colored("All Scans Completed!\n\r", 'magenta'))
	animation.terminate()
	os.system('stty sane')		#Clean terminal after exit

def print_there(x, y, text):
     sys.stdout.write("\x1b7\x1b[%d;%df%s\x1b8" % (x, y, text))
     sys.stdout.flush()

def animation_start():
	counter = 0
	animation = "|/-\\"
	while True:
		time.sleep(0.1)
		print_there(3,0,animation[counter % len(animation)])
		print_there(3,2,animation[counter % len(animation)])
		print_there(3,3,animation[counter % len(animation)])
		counter += 1
		if counter == 100:
			counter = 0


def update_progress_bar():
	global pbar
	pbar.next()
	
def wrong_scan_type():
	print("Oops wrong scan type!")

def scan_types_switcher(scan_type):
    switcher = {
        "udp": udp,
        "tcp": tcp,
        "udp-full": udp_full,
        "tcp-full": tcp_full,
        "athena": athena,
        "zeus": zeus,
        "crice": crice
    }
    # Get the function from switcher dictionary
    func = switcher.get(scan_type)
    # Execute the function
    if str(func) == "None":
    	print('Oops wrong scan type!')
    else:
    	func()

def main():
	subprocess.call('clear',shell=True)
	scan_types_switcher(scan_type.lower())

main()