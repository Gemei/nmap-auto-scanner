#!/usr/bin/python
import os
import sys
import subprocess
from tqdm import tqdm
from termcolor import colored
from itertools import islice

if len(sys.argv) < 4:
	print('[*] Usage: python nmap-scanner-v2.py <File with list of hosts> (UDP|TCP|UDP-All|TCP-All|All-Default|All-Full|TCP-Full-UDP-Default) <number of threads> (<= 10)')
	print('[*] Example: python nmap-scanner-v2.py hosts.txt All-Full 5')
	exit()


scan_type = sys.argv[2]
nthreades = int(sys.argv[3])


def get_hosts_list():
	with open(sys.argv[1]) as file:
		hosts = file.readlines()
	return hosts

def udp():
	print("UDP Default Scan")
	scans = []
	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sU -sV -A -n --script=default,vuln --max-retries 1 %s -oA ./%s/%s-UDP-DEFAULT"%(host,host,host))

	run_threads(scans)

def tcp():
	print("TCP Default Scan")
	scans = []
	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sV -A -n --script=default,vuln %s -oA ./%s/%ss-TCP-DEFAULT"%(host,host,host))

	run_threads(scans)

def udp_full():
	print("UDP Full Ports Scan")
	scans = []

	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sU -sV -A -n --script=default,vuln -p- %s -oA ./%s/%s-TCP-FULL"%(host,host,host))

	run_threads(scans)

def tcp_full():
	print("TCP Full Ports Scan")
	scans = []

	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sV -A -n --script=default,vuln -p- %s -oA ./%s/%s-TCP-FULL"%(host,host,host))

	run_threads(scans)

def all_default():
	print("All Default Ports Scan")
	scans = []
	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sV -A -n --script=default,vuln %s -oA ./%s/%s-TCP-DEFAULT"%(host,host,host))
		scans.append("nmap -vv -sU -sV -n --script=default,vuln --max-retries 1 %s -oA ./%s/%s-UDP-DEFAULT"%(host,host,host))

	run_threads(scans)

def all_full():
	print("All Full Ports Scan")
	scans = []
	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sV -A -n --script=default,vuln -p- %s -oA ./%s/%s-TCP-FULL"%(host,host,host))
		scans.append("nmap -vv -sU -sV -n --script=default,vuln -p- --max-retries 1 %s -oA ./%s/%s-UDP-FULL"%(host,host,host))

	run_threads(scans)
	
def tcp_full_udp_default():
	print("TCP Full Ports Scan With Default Ports For UDP")
	scans = []

	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sS -sV -A -n --script=default,vuln -p- %s -oA ./%s/%s-TCP-FULL"%(host,host,host))
		scans.append("nmap -vv -sU -sV -n --script=default,vuln --max-retries 1 %s -oA ./%s/%s-UDP-DEFAULT"%(host,host,host))

	run_threads(scans)
	
def make_dir(host):
	if not os.path.isdir(host):
		subprocess.call(["mkdir", str(host)])

def run_threads(scans):
	number_of_scans=len(scans)
	
	processes = (subprocess.Popen(scan, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for scan in scans)
	running_processes = list(islice(processes, nthreades))
	with tqdm(total=number_of_scans) as pbar:
		while running_processes:
		    for i, process in enumerate(running_processes):
		    	if process.poll() is not None:  # the process has finished
		    		pbar.update(1)
		    		running_processes[i] = next(processes, None)  # start new process
		    		if running_processes[i] is None: # no new processes
			    		del running_processes[i]
			    		break
	print(colored("\rAll Scans Completed!\n\r", 'blue'))
	sys.stdout.flush()

def wrong_scan_type():
	print("Oops wrong scan type!")

def scan_types_switcher(scan_type):
    switcher = {
        "udp": udp,
        "tcp": tcp,
        "udp-full": udp_full,
        "tcp-full": tcp_full,
        "all-default": all_default,
        "all-full": all_full,
        "tcp-full-udp-default": tcp_full_udp_default
    }
    # Get the function from switcher dictionary
    func = switcher.get(scan_type)
    # Execute the function
    if str(func) == "None":
    	print('Oops wrong scan type!')
    else:
    	func()

def main():
	scan_types_switcher(scan_type.lower())

main()