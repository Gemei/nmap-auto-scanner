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
		scans.append("nmap -vv -sU -sV -n --max-retries 1 %s -oA %s-UDP-DEFAULT"%(host,host))

	run_threads(scans)

def tcp():
	print("TCP Default Scan")
	scans = []
	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sC -sV -A -n %s -oA %s-TCP-DEFAULT"%(host,host))

	run_threads(scans)

def udp_full():
	print("UDP Full Ports Scan")
	scans = []

	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sC -sV -A -n -p- %s -oA %s-TCP-FULL"%(host,host))

	run_threads(scans)

def tcp_full():
	print("TCP Full Ports Scan")
	scans = []

	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sC -sV -A -n -p- %s -oA %s-TCP-FULL"%(host,host))

	run_threads(scans)

def all_default():
	print("All Default Ports Scan")
	scans = []
	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sC -sV -A -n %s -oA %s-TCP-DEFAULT"%(host,host))
		scans.append("nmap -vv -sU -sV -n --max-retries 1 %s -oA %s-UDP-DEFAULT"%(host,host))

	run_threads(scans)

def all_full():
	print("All Full Ports Scan")
	scans = []
	
	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		scans.append("nmap -vv -sS -sC -sV -A -n -p- %s -oA %s-TCP-FULL"%(host,host))
		scans.append("nmap -vv -sU -sV -n -p- --max-retries 1 %s -oA %s-UDP-FULL"%(host,host))

	run_threads(scans)
	
def tcp_full_udp_default():
	print("TCP Full Ports Scan With Default Ports For UDP")
	scans = []

	hosts_list=get_hosts_list()
	hosts_list = map(lambda s: s.strip(), hosts_list)
	for host in hosts_list:
		make_dir(host)
		scans.append("nmap -vv -sS -sC -sV -A -n -p- %s -oA ./%s/%s-TCP-FULL"%(host,host,host))
		scans.append("nmap -vv -sU -sV -n --max-retries 1 %s -oA ./%s/%s-UDP-DEFAULT"%(host,host,host))
		#scans.append("ping -c 10 %s"%(host))
		#scans.append("ping -c 4 %s"%(host))

	run_threads(scans)
	
def make_dir(host):
	if not os.path.isdir(host):
		subprocess.call(["mkdir", str(host)])

def run_threads(scans):
	#processes = [subprocess.Popen(scan, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for scan in scans]
	
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
	#Get active processes
	#progress_counter = get_active_processes()
	#progress_bar(progress_counter)


'''
def get_active_processes():
	procs = subprocess.check_output(['ps', 'uaxw']).splitlines()
	scans_procs = []
	for proc in procs:
		if((proc.find('ping') != -1) and (proc.find('/bin/sh -c ping') > 0)):
			scans_procs.append(proc)
	processes_number = len(scans_procs)
	return(processes_number)


def progress_bar(count):
	prev_running_count = count
	with tqdm(total=count) as pbar:
		time.sleep(1)
		while True:
			current_running_count = get_active_processes()
			diff = prev_running_count-current_running_count
			if((diff) >= 0):
				prev_running_count-=diff
				pbar.update(diff)
				diff=0
			if(current_running_count == 0):
				pbar.update(count)
				break
	print(colored("\rAll Scans Completed!\n\r", 'blue'))
	sys.stdout.flush()
	exit()
'''


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