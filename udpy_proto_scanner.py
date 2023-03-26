#!/usr/bin/env python3
# udpy-proto-scanner - UDP Service Discovery Tool
# Copyright (C) 2023  Mark Lowe
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Max performance notes for python3:
# * 14 seconds, 100% CPU, 20Mbit/s, send errors: time python3 udp-proto-scanner.pl -p echo -r 2 -b 24m 127.0.0.1/13
# * 33 seconds, 8% CPU, 1Mbit/s, no send errors: time python3 /udpy-proto-scanner.py -p echo -r 1 -b 1m 127.0.0.1/16
# So for python3 1Mbit/s seems like a sensible maximum sending rate.  Default is 250Kbit/s.

import argparse
import sys
import os
import re
import time
import ipaddress
from collections import deque
from datetime import datetime, timedelta
import socket
from select import select # TODO not supported / doesn't work on windows?
from math import log10, floor

ip_regex = r"(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
cidr_regex = r"(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([0-9]{1,2})$"

probe_tuples_list = []

# from ike-scan
probe_tuples_list.append((500, 'ike', '5b5e64c03e99b51100000000000000000110020000000000000001500000013400000001000000010000012801010008030000240101'))

# These are some probes from amap 5.2
probe_tuples_list.append((111, 'rpc', '039b65420000000000000002000f4243000000000000000000000000000000000000000000000000'))
probe_tuples_list.append((123, 'ntp', 'cb0004fa000100000001000000000000000000000000000000000000000000000000000000000000bfbe7099cdb34000'))
probe_tuples_list.append((161, 'snmp-public', '3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500'))
probe_tuples_list.append((1434, 'ms-sql', '02'))
probe_tuples_list.append((1434, 'ms-sql-slam', '0a'))
probe_tuples_list.append((6502, 'netop', 'd6818152000000f3874e01023200a8c000000113c1d904dd037d00000d005448435448435448435448435448432020202020202020202020202020202020023200a8c00000000000000000000000000000000000000000000000000000000000000000000000000000000000'))
probe_tuples_list.append((69, 'tftp', '00012f6574632f706173737764006e6574617363696900'))
probe_tuples_list.append((523, 'db2', '444232474554414444520053514c3038303230'))
probe_tuples_list.append((1604, 'citrix', '1e00013002fda8e300000000000000000000000000000000000000000000'))

# small services
probe_tuples_list.append((7, 'echo', '313233'))
probe_tuples_list.append((19, 'chargen', '313233'))
probe_tuples_list.append((11, 'systat', '313233'))
probe_tuples_list.append((13, 'daytime', '313233'))
probe_tuples_list.append((37, 'time', '313233'))

# These are from nmap
probe_tuples_list.append((111, 'RPCCheck', '72fe1d130000000000000002000186a00001977c0000000000000000000000000000000000000000'))
probe_tuples_list.append((53, 'DNSStatusRequest', '000010000000000000000000'))
probe_tuples_list.append((53, 'DNSVersionBindReq', '0006010000010000000000000776657273696f6e0462696e640000100003'))
probe_tuples_list.append((137, 'NBTStat', '80f00010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001'))
probe_tuples_list.append((123, 'NTPRequest', 'e30004fa000100000001000000000000000000000000000000000000000000000000000000000000c54f234b71b152f3'))
probe_tuples_list.append((161, 'SNMPv3GetRequest', '303a020103300f02024a69020300ffe30401040201030410300e0400020100020100040004000400301204000400a00c020237f00201000201003000'))
probe_tuples_list.append((177, 'xdmcp', '0001000200010000'))

# misc
probe_tuples_list.append((5405, 'net-support', '01000000000000000000000000000000000080000000000000000000000000000000000000'))
probe_tuples_list.append((2123, 'gtpv1', '320100040000000050000000'))

# https://community.cisco.com/t5/vpn/problems-getting-l2tp-over-ipsec-on-ios/td-p/1438134
probe_tuples_list.append((1701, 'l2tp', 'c8020060000000000000000080080000000000018008000000020100800a0000000300000001800a00000004000000000008000000060500800900000007776655000f000000084d6963726f736f6674800800000009000180080000000a0008'))


class ProbeState:
    def __init__(self, target):
        self.target = target
        self.probe_sent_time = None
        self.probes_sent = 0

    def __repr__(self):
        return "%s(%s, %s, %s)" % (type(self).__name__, self.target, self.probe_sent_time, self.probes_sent)

class ScannerUDP:
    def __init__(self):
        self.bandwidth_bits_per_second = 32000
        self.max_probes = 3
        self.probes = (None, None, None) # Single probe as a tuple.  This is not a list of probes.  The scanner will only send a single probe type to all hosts.
        self.port = None
        self.payload_hex = None
        self.probe_name = None
        self.payload_bin = None
        self.payload_len_bytes = None
        self.probe_states_queue = deque()
        self.inter_packet_interval = None
        self.inter_packet_interval_per_host = None
        self.backoff = 1.5
        self.rtt = 1
        self.bytes_sent = 0
        self.resolve_names = False # TODO not implemented yet
        self.packet_overhead = 28 # 20 bytes IP + 8 bytes UDP
        self.target_source = None
        self.target_list_unprocessed = []
        self.target_filename = None
        self.host_count_high_water = 900000
        self.host_count_low_water = 100000
        self.scan_start_time = None
        self.host_count = 0
        self.probes_sent_count = 0
        self.replies = 0
        self.unexpected_replies = 0
        self.packet_rate = None
        self.packet_rate_per_host = None

    #
    # Setters
    #

    def set_rtt(self, rtt):
        self.rtt = float(rtt)

    def set_packet_rate(self, packet_rate):
        self.packet_rate = expand_number(packet_rate)

    def set_packet_rate_per_host(self, packet_rate_per_host):
        self.packet_rate_per_host = packet_rate_per_host
        self.inter_packet_interval_per_host = 1 / float(self.packet_rate_per_host)

    def set_probe(self, probe): # tuple of (port, probe_name, payload_hex)
        self.probe = probe
        self.port = probe[0]
        self.probe_name = probe[1]
        self.payload_hex = probe[2]

    # set bandwidth
    def set_bandwidth(self, bandwidth): # string like 250k, 1m, 1g
        self.bandwidth_bits_per_second = expand_number(bandwidth)

        if self.bandwidth_bits_per_second < 1:
            print("[E] Bandwidth %s is too low" % self.bandwidth_bits_per_second)
            sys.exit(0)

        if self.bandwidth_bits_per_second > 1000000:
            print("[W] Bandwidth %s is too high.  Continuing anyway..." % self.bandwidth_bits_per_second)

    # set max_probes
    def set_max_probes(self, n): # int
        self.max_probes = n

    def add_targets(self, targets): # list
        self.target_source = "list"
        self.target_list_unprocessed = targets

    def add_targets_from_file(self, file): # str
        self.target_source = "file"
        self.target_filename = file

    @property
    def bytes_sent_target(self):
        if self.scan_start_time:
            return self.bandwidth_bits_per_second * (time.time() - self.scan_start_time) / 8
        else:
            return 0

    @property
    def probes_sent_target(self):
        if self.scan_start_time:
            return self.packet_rate * (time.time() - self.scan_start_time)
        else:
            return 0

    def dump(self):
        print("")
        print_header("Sending %s probe" % self.probe_name)
        print("Probe name: .................. %s" % self.probe_name)
        print("Port: ........................ %s" % self.port)
        print("Payload: ..................... %s" % self.payload_hex)
        print("Max Probes: .................. %s" % self.max_probes)
        print("Bandwith: .................... %s bits/second" % self.bandwidth_bits_per_second)
        print("Packet rate: ................. %s packets/second" % self.packet_rate)
        print("RTT: ......................... %s seconds" % self.rtt)
        print("Interpacket Interval Per Host: %s seconds" % self.inter_packet_interval_per_host)
        print("Inter-packet interval: ....... %s seconds" % self.inter_packet_interval)
        # print("Backoff ratio: ............... %s" % self.backoff) # TODO
        # print("Resolve names: ............... %s" % self.resolve_names) # TODO
        print("Packet overhead: ............. %s" % self.packet_overhead)
        # Note that we can't print targets / target_count here because we'd drain the generator (which could contain millions of targets)
        print_footer()

    def start_scan(self):
        # Convert payload hex into binary; calculate inter-packet interval
        self.payload_bin = bytes(bytearray.fromhex(self.payload_hex))
        self.payload_len_bytes = len(self.payload_bin)
        self.inter_packet_interval = (self.payload_len_bytes * 8) / float(self.bandwidth_bits_per_second) # float needed for python2

        # Create socket to send packets from.  All probes sent from same source port.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Only generate targets from file / cidr / ranges as we need them - in case there are too many to fit in memory
        target_generator = None
        if self.target_source == "file":
            target_generator = TargetGenerator(filename=self.target_filename)
        elif self.target_source == "list":
            target_generator = TargetGenerator(list=self.target_list_unprocessed)
        else:
            print("[E] Unknown target source: %s.  Call add_targets_from_file() or add_targets() method before starting scan." % self.target_source)
            sys.exit(0)
        target_generator_function = target_generator.get_generator()

        # TODO
        # reply_callback
        # backoff
        # resolve_names

        self.dump()

        self.scan_start_time = time.time()
        scan_running = True
        more_hosts = True
        while scan_running:
            # if queue has capacity, create more probestate objects for up to host_count_high_water hosts; add them to queue
            if more_hosts and len(self.probe_states_queue) < self.host_count_low_water:
                for t in target_generator_function:
                    self.host_count += 1
                    self.probe_states_queue.append(ProbeState(t))
                    if len(self.probe_states_queue) >= self.host_count_high_water: # TODO may not be efficient to keep asking length of queue
                        break
                more_hosts = False

            # check if we've exceeded bandwidth or packet rate quotas
            bandwidth_quota_ok = True
            packet_rate_quota_ok = True
            if self.packet_rate and self.probes_sent_count > self.probes_sent_target:
                packet_rate_quota_ok = False
            if self.bandwidth_bits_per_second and self.bytes_sent > self.bytes_sent_target:
                bandwidth_quota_ok = False

            # if sending a packet now won't exceed quotas, send a packet
            if packet_rate_quota_ok and bandwidth_quota_ok:
                # if queue has items, pop one off
                if len(self.probe_states_queue) > 0:
                    ps = self.probe_states_queue.popleft()

                    # Check if we already sent all probes to this host + we're past the RTT window
                    if ps.probes_sent >= self.max_probes:
                        if time.time() > ps.probe_sent_time + self.rtt:
                            # We've sent max probes to this host and we're past the RTT window, so we're done with this host
                            pass  # we don't add this host back to the queue
                        else:
                            self.probe_states_queue.append(ps)  # add back to queue, but don't send more probes to this host

                    # We need to send a packet.  Also add back to queue so we can check for replies later
                    else:
                        self.probe_states_queue.append(ps)  # add back to queue

                        # Check if probe is due for this host: i.e. if we're past the inter-packet interval for this host; or we never sent a probe; or no inter-packet interval is configured
                        if (ps.probe_sent_time is None) or (self.packet_rate_per_host and (time.time() > ps.probe_sent_time + self.inter_packet_interval_per_host)):
                            # Send probe
                            sent = False
                            while not sent:
                                # At around 16Mbit/s we get occassional errors on sendto: PermissionError: [Errno 1] Operation not permitted
                                # so we catch these errors and retry
                                try:
                                    sock.sendto(self.payload_bin, (ps.target, self.port))
                                    sent = True
                                except socket.error as e:
                                    print("[E] Sending too fast? Error sending probe to %s:%s: %s" % (ps.target, self.port, e))

                            # Update stats
                            self.probes_sent_count += 1
                            ps.probes_sent += 1
                            ps.probe_sent_time = time.time()
                            self.bytes_sent += self.payload_len_bytes + self.packet_overhead

                else:
                    scan_running = False
            else:
                # sleep for self.inter_packet_interval seconds
                time.sleep(self.inter_packet_interval) # python might sleep for too long - e.g. minimum of 1-10ms.  That's OK, we'll be less likely to sleep next time round the loop.

            # recv some packets
            scan_running = self.receive_packets(sock)

        self.scan_duration = time.time() - self.scan_start_time
        self.scan_rate_bits_per_second = int(8 * self.bytes_sent / self.scan_duration)

    # returns True if we have more targets to probe; False if not
    def receive_packets(self, sock):
        # check if there are any packets to receive
        readable, _, _ = select([sock], [], [], 0)

        # recv if there are
        for s in readable:
            data, addr = s.recvfrom(1024)
            srcip = addr[0]
            srcport = addr[1]

            found = False
            # search for probe state
            for probe_state in self.probe_states_queue:
                if probe_state.target == srcip and self.port == srcport:
                    print("Received reply to probe %s (target port %s) from %s:%s: %s" % (self.probe_name, self.port, srcip, srcport, str_or_bytes_to_hex(data)))
                    self.probe_states_queue.remove(probe_state)
                    found = True
                    self.replies += 1
                    break
            if not found:
                print("[W] Received unexpected to probe %s (target port %s) reply from %s:%s: %s" % (self.probe_name, self.port, srcip, srcport, str_or_bytes_to_hex(data)))
                self.unexpected_replies += 1

        if len(self.probe_states_queue) == 0:
            return False
        return True

    def __repr__(self): # TODO
        return "%s()" % type(self).__name__

    def __str__(self): # TODO
        return "%s()" % type(self).__name__

class TargetGenerator:
    def __init__(self, list=None, filename=None):
        if list is None:
            list = []
        self.target_filename = filename
        self.target_list_unprocessed = list
        self.target_source = None
        if len(self.target_list_unprocessed) > 0:
            self.target_source = "list"
        elif self.target_filename:
            self.target_source = "file"
        else:
            print("[E] No target source set")
            sys.exit(0)

    def get_generator(self):
        return self._get_targets()

    # generator in case we are passed more hosts than we can fit in memory
    def _get_targets(self):
        if self.target_source == "list":
            for t in self._get_targets_from_list(self.target_list_unprocessed):
                yield t
        elif self.target_source == "file":
            for t in self._get_targets_from_file(self.target_filename):
                yield t
        else:
            print("[E] No target source set")
            sys.exit(0)

    # unexpanded list like [ 10.0.0.1, 10.0.0.10-10.0.0.20, 10.0.2.0/24 ]
    def _get_targets_from_list(self, targets): # list
        for target in targets:
            for t in self._get_targets_from_string(target):
                yield t

    def _get_targets_from_string(self, target): # str
        if re.match(r"^%s-%s$" % (ip_regex, ip_regex), target):
            for t in self._get_targets_from_ip_range(target):
                yield t

        elif re.match(r"^%s$" % ip_regex, target):
            yield target

        elif re.match(r"^%s$" % cidr_regex, target):
            for t in self._get_target_ips_from_cidr(target):
                yield t

        else:
            print("[E] %s is not a valid ip, ip range or cidr" % target)
            sys.exit(0)

    # add targets from file
    def _get_targets_from_file(self, file): # str
        if not os.path.isfile(file):
            print("[E] File %s does not exist" % file)
            sys.exit(0)
        with open(file, 'r') as f:
            for target in f:
                # strip leading/trailing whitespace
                target = target.strip()

                # ignore comments
                if target.startswith('#'):
                    continue

                # ignore empty lines
                if not target:
                    continue

                # ignore lines with only whitespace
                if re.match(r'^\s+$', target):
                    continue

                # yield from self._get_targets_from_string(target)
                for t in self._get_targets_from_string(target):
                    yield t

    # add targets from ip range like 10.0.0.1-10.0.0.10
    def _get_targets_from_ip_range(self, ip_range): # str
        # check ip_range is in the right format
        if not re.match(r"^%s-%s$" % (ip_regex, ip_regex), ip_range):
            print("[E] IP range %s is not in the right format" % ip_range)
            sys.exit(0)

        # get ip range
        ip_range = ip_range.split('-')

        # get ip range start and end
        start_ip = ip_range[0]
        if sys.version_info.major == 2:
            start_ip = start_ip.decode("utf8")

        end_ip = ip_range[1]
        if sys.version_info.major == 2:
            end_ip = end_ip.decode("utf8")

        ip_range_start = ipaddress.ip_address(start_ip)
        ip_range_end = ipaddress.ip_address(end_ip)

        # add targets
        for ip_int in range(int(ip_range_start), int(ip_range_end) + 1):
            yield str(ipaddress.ip_address(ip_int))

    def _get_target_ips_from_cidr (self, cidr): # str
        # check cidr is in the right format
        m = re.match(cidr_regex, cidr)
        if not m:
            print("[E] CIDR %s is not in the right format" % cidr)
            sys.exit(0)
        if int(m.group(1)) > 32:
            print("[E] Netmask for %s is > 32" % cidr)
            sys.exit(0)
        if int(m.group(1)) < 8:
            print("[E] Netmask for %s is < 8" % cidr)
            sys.exit(0)

        # if running python2, cidr must be unicode, not str
        if sys.version_info.major == 2:
            cidr = cidr.decode("utf8")

        ip_range = ipaddress.ip_network(cidr, False)
        # add targets
        for ip_int in range(int(ip_range.network_address), int(ip_range.broadcast_address) + 1):
            yield str(ipaddress.ip_address(ip_int))

#
# Helper functions
#

# recvfrom returns bytes in python3 and str in python3.  This function converts either to hex string
def str_or_bytes_to_hex(str_or_bytes):
    return "".join("{:02x}".format(c if type(c) is int else ord(c)) for c in str_or_bytes)

def get_time():
    return datetime.now().isoformat() # TODO tz

def round_pretty(x):
    if x <= 100:
        # round to 3 significant figures
        return round(x, 2-int(floor(log10(abs(x)))))
    else:
        # Otherwise, just covert to int
        return int(x)

def print_header(message, width=80):
    message_len = len(message) + 2 # a space either side
    pad_left = int((width - message_len) / 2)
    pad_right = width - message_len - pad_left
    print("%s %s %s" % ("=" * pad_left, message, "=" * pad_right))

def print_footer(width=80):
    print("=" * width)

# Convert a string to a number, with support for K, M, G suffixes
def expand_number(number): # int or str
    number_as_string = str(number)
    if number_as_string.lower().endswith('k'):
        return int(number_as_string[:-1]) * 1000
    elif number_as_string.lower().endswith('m'):
        return int(number_as_string[:-1]) * 1000000
    elif number_as_string.lower().endswith('g'):
        return int(number_as_string[:-1]) * 1000000000
    else:
        if not number_as_string.isdigit():
            print("[E] %s should be an integer or an integer with k, m or g suffix" % number_as_string)
            sys.exit(0)
        else:
            return int(number_as_string)

if __name__ == "__main__":
    VERSION = "0.7"

    # Defaults
    DEFAULT_MAX_PROBES = 2
    DEFAULT_BANDWIDTH = "250k"
    DEFAULT_PACKET_RATE = 0
    DEFAULT_PACKET_HOST_RATE = 2
    DEFAULT_RTT = 1

    # These get overriden later
    max_probes = DEFAULT_MAX_PROBES
    bandwidth = DEFAULT_BANDWIDTH
    packet_rate = DEFAULT_PACKET_RATE
    packet_rate_per_host = DEFAULT_PACKET_HOST_RATE
    rtt = DEFAULT_RTT

    probe_tuples_dict = {}  # parsed from config file
    probe_names = []        # from command line

    script_name = sys.argv[0]

    # parse command line options
    parser = argparse.ArgumentParser(usage='%s [options] [ -p probe_name ] -f ipsfile\n       %s [options] [ -p probe_name ] 10.0.0.0/16 10.1.0.0-10.1.1.9 192.168.0.1' % (script_name, script_name))

    parser.add_argument('-f', '--file', dest='file', help='File of ips')
    parser.add_argument('-p', '--probe_name', dest='probe_name_str_list', help='Name of probe or all')
    parser.add_argument('-l', '--list_probes', dest='list_probes', action="store_true", help='List all available probe name then exit')
    parser.add_argument('-b', '--bandwidth', dest='bandwidth', default=DEFAULT_BANDWIDTH, type=str, help='Bandwidth to use in bits/sec.  Default 250k')
    parser.add_argument('-P', '--packetrate', dest='packetrate', default=DEFAULT_PACKET_RATE, type=str, help='Max packets/sec to send.  Default unlimited')
    parser.add_argument('-H', '--packethostrate', dest='packehosttrate', default=DEFAULT_PACKET_HOST_RATE, type=int, help='Max packets/sec to each host.  Default %s' % (DEFAULT_PACKET_HOST_RATE))
    parser.add_argument('-R', '--rtt', dest='rtt', default=DEFAULT_RTT, type=str, help='Max round trip time for probe.  Default %ss' % (DEFAULT_RTT))
    parser.add_argument('-r', '--retries', dest='retries', default=DEFAULT_MAX_PROBES, type=int, help='No of packets to sent to each host.  Default %s' % (DEFAULT_MAX_PROBES))
    args, targets = parser.parse_known_args()

    #
    # Change defaults based on command line options
    #

    # set max_probes from retries
    if args.retries is not None:
        max_probes = args.retries + 1

    # set default bandwidth
    if args.bandwidth is not None:
        bandwidth = args.bandwidth

    # set default packet rate
    if args.packetrate is not None:
        packet_rate = args.packetrate

    # set default packet rate per host
    if args.packehosttrate is not None:
        packet_rate_per_host = args.packehosttrate

    # set default rtt
    if args.rtt is not None:
        rtt = args.rtt

    #
    # Parse probe data, probe options
    #

    # find directory this script is in
    script_dir = os.path.dirname(os.path.realpath(__file__))

    for probe_tuple in probe_tuples_list:
        probe_name = probe_tuple[1]
        probe_tuples_dict[probe_name] = probe_tuple
        probe_names.append(probe_name)

    # check probe_names are valid
    probes_names_to_use = []
    if args.probe_name_str_list == "all":
        probes_names_to_use = probe_names
    elif args.probe_name_str_list:
        for probe_name in args.probe_name_str_list.split(','):
            if probe_name not in probe_names:
                print("[E] Probe name %s (from -p) unknown.  Use -l to list valid names." % (probe_name))
                sys.exit(0)
            probes_names_to_use.append(probe_name)

    #
    # Check for illegal command line options
    #

    # error if any targets start with - or -- as this will be interpreted as an option
    for target in targets:
        if target.startswith('-'):
            print("[E] Target \"%s\" starts with - or -- which is interpreted as an option" % target)
            sys.exit(0)

    # if --list_probes is set, print out all the probe names like this
    if args.list_probes:
        print("The following probe names (-p argument) are available:")
        for probe_name in probe_names:
            print("* %s" % probe_name)
        sys.exit(0)

    # error if no targets were specified
    if not args.file and not targets:
        parser.print_help()
        sys.exit(0)

    # error if --file and targets were specified
    if args.file and targets:
        print("[E] You cannot specify both a file of targets and a list of targets")
        sys.exit(0)

    print("Starting udpy-proto-scanner v%s ( https://github.com/CiscoCXSecurity/udpy-proto-scanner ) at %s" % (VERSION, get_time()))
    print("")
    print_header("Scan Options")
    print("Bandwith: .................... %s bits/second" % args.bandwidth)
    print("Max Probes per host: ......... %s" % max_probes)
    print("Probes names: ................ %s" % ",".join(probes_names_to_use))
    print("Targets: ..................... %s" % ",".join(targets))
    print("Targets file: ................ %s" % args.file)
    print("=" * 80)
    print("")

    # Send each type of probe separately
    for probe in probes_names_to_use:
        scanner = ScannerUDP()

        # Set up options for scan
        if args.file:
            scanner.add_targets_from_file(args.file)
        else:
            scanner.add_targets(targets)

        scanner.set_bandwidth(bandwidth)
        scanner.set_max_probes(max_probes)
        scanner.set_rtt(rtt)
        scanner.set_packet_rate(packet_rate)
        scanner.set_packet_rate_per_host(packet_rate_per_host)
        scanner.set_probe(probe_tuples_dict[probe])

        # Start scan
        scanner.start_scan()

        # Print stats
        print("")
        print("Total replies: %s (+%s unexpected replies)" % (scanner.replies, scanner.unexpected_replies))
        print("Scan for probe %s complete at %s" % (probe, get_time()))
        print("Sent %s bytes (%s bits) in %s probes in %ss to %s hosts: %s bits/s, %s bytes/s, %s packets/s" % (scanner.bytes_sent, scanner.bytes_sent * 8, scanner.probes_sent_count, round_pretty(scanner.scan_duration), scanner.host_count, scanner.scan_rate_bits_per_second, round_pretty(scanner.bytes_sent / scanner.scan_duration), round_pretty(scanner.probes_sent_count / scanner.scan_duration)))
