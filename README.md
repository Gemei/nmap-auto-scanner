##### Current Version: 2.0.4
##### Prequests
	pip install progress
------------
# nmap-auto-scanner
Python script to automate some nmap scans

- Usage:	__python nmap-scanner-v2.py <File with list of hosts> (UDP|TCP|UDP-All|TCP-All|Athena|Circe|Zeus) <number of threads> (<= 10) True|False__
  * __UDP__: 	UDP default ports scan
  * __TCP__: 	TCP default ports scan
  * __UDP-All__:	UDP all ports scan
  * __TCP-All__:	TCP all ports scan
  * __Athena__:	TCP & UDP default ports scan
  * __Crice__:	TCP full & UDP default ports scan
  * __Zeus__:	TCP & UDP full ports scan

- Optional Extra Options:	**True|False** # *Default is False* `(-A -sV --script=default,vuln)`

- Example:	__python nmap-scanner-v2.py hosts.txt Circe 5__

*Requires root privilages to run*

------------
##### FAQ
What happend to V1?

Dead! Yeah sad but true....
