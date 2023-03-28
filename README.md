# UDP Protocol Scanner

A python version of https://github.com/CiscoCXSecurity/udp-proto-scanner (which is written in Perl).

# Quick Start

udpy_proto_scanner scans by sending UDP probes (embedded in source code - no config file necessary)
to a list of targets:
```
$ udpy_proto_scanner.py -f ips.txt
$ udpy_proto_scanner.py -p ntp -f ips.txt
$ udpy_proto_scanner.py -p all -b 32k 10.0.0.0/16 10.1.0.0-10.1.1.9 192.168.0.1
```
List probe names using the -l option:
```
$ udpy_proto_scanner.py -l
The following probe names (-p argument) are available:
* ike
* rpc
* ntp
* snmp-public
* ms-sql
* ms-sql-slam
* netop
* tftp
* db2
* citrix
* echo
* chargen
* systat
* daytime
* time
* RPCCheck
* DNSStatusRequest
* DNSVersionBindReq
* NBTStat
* NTPRequest
* SNMPv3GetRequest
* xdmcp
* net-support
* gtpv1
* l2tp
```
Targets files can be in CIDR format, or a range of IP addresses separated by a hyphen:
```
$ cat ips.txt
# targets file can contain comments
# and blank lines

# and lines that contain only whitespace

# list IPs to scan.  Whitespace will be trimmed.
127.0.0.1
127.0.0.2
127.0.0.3

# IP ranges are supported if the whole start IP and end IP is given:
127.0.0.4-127.0.1.7

# CIDR notation is supported:
127.0.2.128/30
```

## What is udpy_proto_scan used for?

It's used in the host-discovery and service-discovery phases of a pentest.
It can be helpful if you need to discover hosts that only offer UDP services
and are otherwise well firewalled - e.g. if you want to find all the DNS
servers in a range of IP addresses.  Alternatively on a LAN, you might want
a quick way to find all the TFTP servers.

Not all UDP services can be discovered in this way (e.g. SNMPv1 won't respond
unless you know a valid community string).  However, many UDP services can be
discovered, e.g.:
* DNS
* TFTP
* NTP
* NBT
* SunRPC
* MS SQL
* DB2
* SNMPv3

It can sometimes be useful to upload udpy_proto_scanner.py to a compromised 
host and run scans from there.

## udpy_proto_scan is not a Port Scanner

It won't give you a list of open and closed ports for each host.  It's simply
looking for specific UDP services.

## Efficiency

It's most efficient to run udpy_proto_scanner against whole networks (e.g.
256 IPs or more).  If you run it against small numbers of hosts it will seem
quite slow because it waits for 1 second between each different type of probe.

## Usage Message
```
usage: ./udpy_proto_scanner.py [options] [ -p probe_name ] -f ipsfile
       ./udpy_proto_scanner.py [options] [ -p probe_name ] 10.0.0.0/16 10.1.0.0-10.1.1.9 192.168.0.1

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File of ips
  -p PROBE_NAME_STR_LIST, --probe_name PROBE_NAME_STR_LIST
                        Name of probe or all
  -l, --list_probes     List all available probe name then exit
  -b BANDWIDTH, --bandwidth BANDWIDTH
                        Bandwidth to use in bits/sec. Default 250k
  -P PACKETRATE, --packetrate PACKETRATE
                        Max packets/sec to send. Default unlimited
  -H PACKEHOSTTRATE, --packethostrate PACKEHOSTTRATE
                        Max packets/sec to each host. Default 2
  -R RTT, --rtt RTT     Max round trip time for probe. Default 1s
  -r RETRIES, --retries RETRIES
                        No of packets to sent to each host. Default 2
```

## Features and Design Goals

### Speed

While scanning speed is not the primary goal of udpy_proto_scanner, it is still important.  udpy_proto_scanner is designed to be fast as it could easily be made to be given that it's coded in python.

It's not as fast as nmap or massscan can be - but it IS designed to not make you wait too long for scan results.

### Big Scans

udpy_proto_scanner is designed to be able to scan large numbers of hosts - hundreds of thousands or even millions of hosts.

It will scan a Class B network with one probe with no retries in about 85 seconds.

### Safety

When pentesting badly configured networks or fragile hosts, scanning can sometimes cause outages.  This tends to be rare, but udpy_proto_scanner aims to give testers ways to manage the risk of outages:
* Specify maximum bandwidth in bits per section with -b or --bandwidth.  Example: `-b 1m` or `-b 32k`
* Sensible default of 250Kbit/sec for maximum bandwidth
* Specify maximum rate at which each host should be scanned in packets per second.  Example: `-H 5` will send up to 5 packets per second to each host.
* Cautious default of 2 packets per second per host.  This is not as slow as it might seem: if your host-list is long, you can scan a lot of other hosts in 0.5 seconds, so efficiency is still high for large scans.
* Option to specify the maximum packets per second the scanner will send.  Example `-P 3000` will send no more than 3000 pcakets per second.

If you choose to upload udpy_proto_scanner to a compromised host, so you can scan from there, the following may help to manage the risk of adversely affecting that host:
* The script doesn't use forking or threading, which helps to manage the risk of accidentally swamping the target with processes or threads.
* There is a maximum amount of memory that the script will use.  Even when hostlists are huge, the script will not read / generate the entire list in memory.  This helps to manage the risk that the script will consume all available memory.  udpy_proto_scanner will break scans up into chunks of around 100k hosts.
* The code attempts to be efficient to keep CPU utilisation low.  If CPU utilisation is too high for you (and it generally shouldn't be high with the default settings), try scanning at a slower speed.
* The program uses a single UDP socket to send all traffic from, so running the script should not exhaust the number of available sockets.
* No output is written to disk, so the script should not use up disk space unexpectedly.

### Verbose Output

To aid pentesters with record keeping and answering detailed questions about their scans, udpy_proto_scanner outputs verbose information about scan time, scan rates and configuration.  It doesn't output to a file, though, so it's recommended you use `script' or output redirection capture output.

### Portable

The script was designed to work with python2 and python3 (but so far has only been tested with 2.7.18 and 3.10.8) because you can't be sure how old a version of python you're going to find on a compromised host.

The script has no dependencies and should work with a base python install.

You should be able to copy-paste the .py file and run it.  All probe data is in the source code and no external configuration file is needed.

Note: No consideration is given to opsec.

Note: No testing has been carried out on Windows yet.  But apparently the implemention of select() differs on Windows, so this may stop it working.

### Reliability

Retries are supported and enabled by default in case any probes are dropped on their way to the target.  Example: `-r 2` will send a probe and then 2 retries (3 packets to each host in total).

Scanning time is predictable.  The time taken for scans should depend only on the paramaters used and the length of the host list.  If networks are congested or hosts are slow to responsd or there's some sort of a rate-limiting with replies, this will not affect scan time - although it could mean that you should scan at a lower rate.  This is a feature, not a bug so that pentesters are not left wondering if their scan their scan will ever finish.

Suitable for testing over slow links.  udpy_proto_scanner will wait 1 second by default for replies.  You can wait longer using RTT option: `-R 2.5`

## Risks: Beta quality code

Aside from the usual risks of scanning, the code was written around March 2023, so it will take a while to test thoroughly.  There might still be bugs that cause the scanner to behave badly.  

## Credits

The UDP probes are mainly taken from amap, nmap and ike-scan.
Inspiration for the scanning code was drawn from ike-scan.
Code is based on the original udp-proto-scanner with some small improvements.
