#!/usr/bin/env python3
# udpy_proto_scanner - UDP Service Discovery Tool
# Copyright Cisco Systems, Inc. and its affiliates
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

import argparse
import collections
import ipaddress
import math
import os
import re
import select
import socket
import sys
import time

class ScannerBase(object):
    def __init__(self):
        self._sleep_total = 0
        self.header = "Starting Scan"
        self.sleep_multiplier = 1.87 # if we total up the time we sleep for, it doesn't match the time cProfile reports we spent in the sleep function, so we use this multiplier to adjust the estimate
        self.reply_callback_function = None
        self.bandwidth_bits_per_second = 32000
        self.max_probes = 3
        self.probes = [] # [(None, None, None),] # List of probe tuples
        self.inter_packet_interval = None
        self.inter_packet_interval_per_host = None
        self.backoff = 1.5
        self.rtt = 0.5 # https://www.nature.com/articles/s41598-019-46208-6
        self.bytes_sent = 0
        self.resolve_names = False # TODO not implemented yet
        self.target_source = None
        self.target_list_unprocessed = []
        self.target_filename = None
        self.scan_start_time_internal = None
        self.scan_start_time = None
        self.probes_sent_count = 0
        self.replies = 0
        self.packet_rate = None
        self.packet_rate_per_host = None
        self.probe_index_to_socket_dict = {}
        self.host_count = 0
        self.next_recv_time = time.time()
        self.recv_interval = 0.1
        self.debug = False
        self.log_reply_tuples = []
        self.debug_reply_log = "debug_reply_log.txt"
        self.blocklist = []
        self.count_in_queue = {} # how many probes are in the queue for each probe type
        self.sleep_reasons = {}

    #
    # Properties
    #

    @property
    def bytes_sent_target(self):
        if self.scan_start_time_internal:
            return self.bandwidth_bits_per_second * (time.time() - self.scan_start_time_internal) / 8
        else:
            return 0

    @property
    def probes_sent_target(self):
        if self.scan_start_time_internal:
            return self.packet_rate * (time.time() - self.scan_start_time_internal)
        else:
            return 0

    @property
    def sleep_total(self):
        return self._sleep_total * self.sleep_multiplier

    #
    # Setters
    #

    def set_reply_callback(self, reply_callback):
        self.reply_callback_function = reply_callback

    def set_debug(self, debug):
        self.debug = debug

    # set max_probes
    def set_max_probes(self, n): # int
        self.max_probes = int(n)

    def set_blocklist(self, blocklist_ips):
        # check ips are valid
        for ip in blocklist_ips:
            self.add_to_blocklist(ip)

    # set bandwidth
    def set_bandwidth(self, bandwidth): # string like 250k, 1m, 1g
        self.bandwidth_bits_per_second = expand_number(bandwidth)

        if self.bandwidth_bits_per_second < 1:
            print("[E] Bandwidth %s is too low" % self.bandwidth_bits_per_second)
            sys.exit(0)

        if self.bandwidth_bits_per_second > 1000000:
            print("[W] Bandwidth %s is too high.  Continuing anyway..." % self.bandwidth_bits_per_second)

        self.set_inter_packet_interval()

    def set_inter_packet_interval(self):
        if self.packet_overhead is None or self.packet_overhead == 0:
            print("[E] Code error: Packet overhead not set prior to calculating inter-packet interval")
            sys.exit(0)
        if self.bandwidth_bits_per_second is None or self.bandwidth_bits_per_second == 0:
            print("[E] Code error: Bandwidth not set not set prior to calculating inter-packet interval")
            sys.exit(0)
        self.inter_packet_interval = 8 * (self.payload_len_estimate + self.packet_overhead) / float(self.bandwidth_bits_per_second)

    def set_packet_rate(self, packet_rate):
        self.packet_rate = expand_number(packet_rate)

    def set_packet_rate_per_host(self, packet_rate_per_host):
        self.packet_rate_per_host = packet_rate_per_host
        self.inter_packet_interval_per_host = 1 / float(self.packet_rate_per_host)

    def set_header(self, header):
        self.header = header

    def add_targets(self, targets): # list
        self.target_source = "list"
        self.target_list_unprocessed = targets

    def add_targets_from_file(self, file): # str
        self.target_source = "file"
        self.target_filename = file

    #
    # Adders
    #

    def add_to_blocklist(self, ip):
        try:
            socket.inet_aton(ip)
        except socket.error:
            print("[E] Invalid IP address in blocklist: %s" % ip)
            sys.exit(1)
        if ip not in self.blocklist:
            self.blocklist.append(ip)

    #
    # Getters
    #

    def get_probe_port(self, probe_index):
        probe = self.probes[probe_index]
        return int(probe[0])

    def get_probe_payload_hex(self, probe_index):
        probe = self.probes[probe_index]
        return probe[2]

    def get_probe_payload_bin(self, probe_index):
        probe = self.probes[probe_index]
        return probe[3]

    def get_probe_name(self, probe_index):
        probe = self.probes[probe_index]
        return probe[1]

    def get_probe_index_from_socket(self, s):
        for probe_index, socket in self.probe_index_to_socket_dict.items():
            if s == socket:
                return probe_index
        return None

    def get_available_bandwidth_quota_packets(self):

        packet_quota_left = None
        # return 100 if there is no bandwidth quota
        if self.bandwidth_bits_per_second is None:
            packet_quota_left = 100
        else:
            # return 0 if we exceed our bandwidth quota
            bytes_left = self.bytes_sent_target - self.bytes_sent
            if bytes_left <= 0:
                packet_quota_left = 0
            else:
                packet_quota_left = int(8 * bytes_left / float(self.packet_overhead))

        # return the number of packets we can send
        return packet_quota_left

    def get_available_packet_rate_quota_packets(self):
        packet_quota_left = None
        # return 100 if there is no packet rate quota
        if self.packet_rate is None or self.packet_rate == 0: # TODO messy
            packet_quota_left = 100
        else:
            # return 0 if we exceed our packet rate quota
            packets_left = self.probes_sent_target - self.probes_sent_count
            if packets_left <= 0:
                packet_quota_left = 0
            else:
                packet_quota_left = packets_left

        # return the number of packets we can send
        return packet_quota_left

    def get_available_quota_packets(self):
        return int(min(self.get_available_bandwidth_quota_packets(), self.get_available_packet_rate_quota_packets()))

    #
    # Debug
    #

    # Note that recording results in memory could use too much memory for large scans
    # so is disabled by default.  This feature is used for automated testing.
    def debug_log_reply(self, probe_name, srcip, port, data):
        self.log_reply_tuples.append((probe_name, srcip, port, data))

    def debug_write_log(self):
        with open(self.debug_reply_log, "w") as f:
            for probe_name, srcip, port, data in self.log_reply_tuples:
                f.write("%s,%s,%s,%s\n" % (probe_name, srcip, port, str_or_bytes_to_hex(data)))
        print("[i] Wrote debug log to %s" % self.debug_reply_log)

    def __repr__(self): # TODO
        return "%s()" % type(self).__name__

    def __str__(self): # TODO
        return "%s()" % type(self).__name__

    #
    # Others
    #

    def wait_for_quotas(self):
        bandwidth_quota_ok = False
        packet_rate_quota_ok = False
        probe_send_ok = False
        bandwidth_quota_packets_left = 0
        packet_quota_packets_left = 0
        wait_time = 0
        while not (packet_rate_quota_ok and bandwidth_quota_ok and probe_send_ok):

            # check if we're within bandwidth quota
            force_bandwidth_quota_wait = True
            force_packet_quota_wait = True
            force_probe_state_wait = True
            bandwidth_quota_ok = False
            packet_rate_quota_ok = False
            probe_send_ok = False
            wait_time = 0
            bandwidth_quota_packets_left = self.get_available_bandwidth_quota_packets()
            if bandwidth_quota_packets_left > 0:
                bandwidth_quota_ok = True
                force_bandwidth_quota_wait = False

                # check if we're within packet rate quota
                force_packet_quota_wait = False
                packet_quota_packets_left = self.get_available_packet_rate_quota_packets()
                if packet_quota_packets_left > 0:
                    packet_rate_quota_ok = True
                    force_packet_quota_wait = False

                    # Check all of the probe states to see if any are ready to send
                    # This is expesnive, so we only do it if we're within the other quotas
                    # if self.probe_state_ready():
                    #     probe_send_ok = True
                    #     force_probe_state_wait = False
                    if self.get_queue_length() > 0:

                        next_probe_state = self.queue_peek_first()
                        last_probe_time = next_probe_state.probe_sent_time
                        now = time.time()

                        if last_probe_time is None or now > last_probe_time + self.inter_packet_interval_per_host:
                            probe_send_ok = True
                            force_probe_state_wait = False
                        else:
                            wait_time = last_probe_time + self.inter_packet_interval_per_host - now
                    else:
                        self.probe_state_ready_last_result = True
                        return self.probe_state_ready_last_result

            # update stats
            if force_bandwidth_quota_wait:
                self.sleep_reasons["bandwidth_quota"] += 1
            elif force_packet_quota_wait:
                self.sleep_reasons["packet_quota"] += 1
            elif force_probe_state_wait:
                self.sleep_reasons["port_states"] += 1

            if not (packet_rate_quota_ok and bandwidth_quota_ok and probe_send_ok):
                # sleep for self.inter_packet_interval seconds
                wait_time = max(self.inter_packet_interval, wait_time)

                # Do an extra receive if we have spare time
                # we must not sleep for more than the receive interval or we won't check for reponses when we're supposed to
                # Without this shorter sleep, very small scans tend to miss responses because they recv too quickly after sending and then wait for the next retry.  Then the same problem occurs.
                if wait_time > self.recv_interval:
                    self.receive_packets(self.get_socket_list())
                    self._sleep_total += self.recv_interval
                    time.sleep(self.recv_interval)
                else:
                    self._sleep_total += wait_time
                    time.sleep(wait_time)

    #
    # Abstract methods # TODO is abc module portable?
    #

    def dump(self):
        raise NotImplementedError

    def set_rtt(self, rtt):
        raise NotImplementedError

    def set_probes(self, probes):
        raise NotImplementedError

    def start_scan(self):
        raise NotImplementedError

    def receive_packets(self, socket_list):
        raise NotImplementedError

    def inform_starting_probe_type(self, probe_index):
        raise NotImplementedError

    def decrease_count_in_queue(self):
        raise NotImplementedError

    def get_queue_length(self):
        raise NotImplementedError

    def queue_peek_first(self):
        raise NotImplementedError

    def get_socket_list(self):
        raise NotImplementedError

ip_regex = r"(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
cidr_regex = r"(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([0-9]{1,2})$"

class TargetGenerator:
    def __init__(self, make_probe_state_callback, list=None, filename=None, custom=False):
        if list is None:
            list = []
        self.target_filename = filename
        self.target_list_unprocessed = list
        self.target_source = None
        self.custom = custom
        self.make_probe_state_callback = make_probe_state_callback
        if len(self.target_list_unprocessed) > 0:
            self.target_source = "list"
        elif self.target_filename:
            self.target_source = "file"
        elif custom:
            self.target_source = "custom"
        else:
            raise Exception("[E] __init__: No target source set")

    def get_probe_state_generator(self, probes):
        if self.custom: # format: (ip, port, name, payload_bin)
            probe_index = 0
            for probe_tuple in probes:
                ip = probe_tuple[0]
                port = probe_tuple[1]
                name = probe_tuple[2]
                payload_bin = probe_tuple[3]
                cps = self.make_probe_state_callback(ip, probes, probe_index)
                cps.payload_bin = payload_bin
                yield cps
        else:
            for probe_index in range(len(probes)):
                for target in self._get_targets():
                    yield self.make_probe_state_callback(target, probes, probe_index)

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
            raise Exception("[E] _get_targets: No target source set")

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

class ProbeStateUdp:
    def __init__(self, target, probe_index):
        self.target_ip = target
        self.probe_index = probe_index
        self.probe_sent_time = None
        self.probes_sent = 0

    def __repr__(self):
        return "%s(%s, %s, %s)" % (type(self).__name__, self.target_ip, self.probe_sent_time, self.probes_sent)

# Each probe state can have a different probe

class ProbeStateUdpCustom(ProbeStateUdp):
    def __init__(self, target, probe_index):
        super().__init__(target, probe_index)
        self.payload_bin = None

    def __repr__(self):
        return "%s(%s, %s, %s)" % (type(self).__name__, self.target, self.probe_sent_time, self.probes_sent)

class ScannerUDP(ScannerBase):
    def __init__(self):
        super(ScannerUDP, self).__init__()

        #
        # Specific to UDP
        #

        self.next_timer_adjust = None
        self.custom_probes = None
        self.probe_states_queue = collections.deque()
        self.unexpected_replies = 0
        self.send_buffer_warning_displayed = False

        #
        # Common to TCP and UDP, but set to different values
        #

        self.payload_len_estimate = 10 # a guess
        self.packet_overhead = 42 # 14 bytes for ethernet frame + 20 bytes IP header + 8 bytes UDP header
        self.host_count_high_water = 100000
        self.host_count_low_water = 90000

    #
    # Methods that are implemented differently for TCP and UDP Scanners
    #
    def dump(self):
        print("")
        print_header(self.header)
        if self.target_filename:
            print("Targets file: ................ %s" % self.target_filename)
        if self.target_list_unprocessed:
            print("Targets: ..................... %s" % ", ".join(self.target_list_unprocessed))
        if self.probes: # may not be used if caller is using custom probes
            print("Probes: ...................... %s Probes: %s" % (len(self.probes), ", ".join([p[1] for p in self.probes])))
        print("Retries: ..................... %s" % (self.max_probes - 1))
        print("Bandwidth: ................... %s bits/second" % self.bandwidth_bits_per_second)
        if self.packet_rate:
            print("Packet rate: ................. %s packets/second" % self.packet_rate)
        print("RTT: ......................... %s seconds" % self.rtt)
        print("Interpacket Interval Per Host: %s seconds" % self.inter_packet_interval_per_host)
        print("Inter-packet interval: ....... %s seconds" % self.inter_packet_interval)
        print("Packet overhead: ............. %s" % self.packet_overhead)
        # Note that we can't print targets / target_count here because we'd drain the generator (which could contain millions of targets)
        print_footer()

    def set_rtt(self, rtt):
        self.rtt = float(rtt)

    def set_probes(self, probes): # tuple of (port, probe_name, payload_hex)
        self.probes = []
        for probe in probes:
            probe_bin = None
            if probe[2] is not None:
                probe_bin = bytes(bytearray.fromhex(probe[2]))

            probe_with_bin = probe + (probe_bin,)
            self.probes.append(probe_with_bin)

    def start_scan(self):
        # check we have probes
        if not self.probes:
            print("[E] No probes set.  Call set_probes() method before starting scan.")
            sys.exit(0)

        # Convert payload hex into binary; calculate inter-packet interval
        self.inter_packet_interval = 8 * (self.packet_overhead + self.payload_len_estimate) / float(self.bandwidth_bits_per_second)

        def make_probe_state_callback(target, probes, probe_index):
            if self.custom_probes:
                return ProbeStateUdpCustom(target, probe_index)
            else :
                return ProbeStateUdp(target, probe_index)

        # Set up target generator
        target_generator = None
        if self.target_source == "file":
            target_generator = TargetGenerator(make_probe_state_callback, filename=self.target_filename)
        elif self.target_source == "list":
            target_generator = TargetGenerator(make_probe_state_callback, list=self.target_list_unprocessed)
        elif self.target_source == "custom":
            target_generator = TargetGenerator(make_probe_state_callback, custom=True)
        else:
            print("[E] Unknown target source: %s.  Call add_targets_from_file() or add_targets() method before starting scan." % self.target_source)
            sys.exit(0)
        probes_state_generator_function = None
        if self.target_source == "custom":
            probes_state_generator_function = target_generator.get_probe_state_generator(self.custom_probes)
        else:
            probes_state_generator_function = target_generator.get_probe_state_generator(self.probes)

        # Initialize stats for how many of each probe type are in the queue
        for probe_index in range(len(self.probes)):
            self.count_in_queue[probe_index] = 0

        last_send_time = None

        self.dump()

        self.scan_start_time_internal = time.time() # used for user-facing stats
        self.scan_start_time = time.time() # used for scanner timings only
        scan_running = True
        more_hosts = True
        highest_probe_index_seen = -1
        self.sleep_reasons["packet_quota"] = 0
        self.sleep_reasons["bandwidth_quota"] = 0
        self.sleep_reasons["port_states"] = 0
        while scan_running:
            #
            # add probes to queue
            #
            # if queue has capacity, create more probestate objects for up to host_count_high_water hosts; add them to queue
            if more_hosts and len(self.probe_states_queue) < self.host_count_low_water:
                more_hosts = False # if we complete the for loop, there are no more probes to add
                for ps in probes_state_generator_function:
                    # Don't add to queue if target is in blocklist
                    if ps.target_ip in self.blocklist:
                        print("[i] Skipping target %s because it is in the blocklist" % ps.target_ip)
                        continue

                    # Count the number of hosts we are scanning
                    if ps.probe_index == 0:
                        self.host_count += 1

                    # Inform user went we start scanning a new probe type
                    if ps.probe_index > highest_probe_index_seen:
                        self.inform_starting_probe_type(ps.probe_index)
                        highest_probe_index_seen = ps.probe_index

                    # Add to queue
                    self.probe_states_queue.append(ps)

                    # Increment count of probes of this type in queue
                    self.count_in_queue[ps.probe_index] += 1

                    # Create socket if needed
                    if ps.probe_index not in self.probe_index_to_socket_dict:
                        # Create socket to send packets from.  All probes of the same type are sent from same source port.
                        # We don't use the same source port for all probes because if we have two DNS probes (for example)
                        # it will be difficult to match the replies to the probe.
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.setblocking(False)

                        # This should set buffer to 425984, but maybe some OS's have larger buffers.
                        # A large buffer is important if users scan locally attached networks.  UDP packets
                        # will be buffered while ARP fails to resolve the MAC address of the target.
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(1000000))

                        # Allow sending to broadcast addresses
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                        self.probe_index_to_socket_dict[ps.probe_index] = sock

                    # If we've reached the high watermark, exit the for loop
                    if len(self.probe_states_queue) >= self.host_count_high_water:
                        # If we exit the for loop early, there are more probes to add
                        more_hosts = True
                        break

            # If we're not within quotas, wait until we are:
            # * bandwidth quota
            # * packet rate quota
            # * probe state < at least one probe state is ready to send
            self.wait_for_quotas() # TODO doesn't work properly unless inter_packet_interface_per_host is about 25% of rtt

            # if queue has items, pop one off
            packet_count_to_send = self.get_available_quota_packets()

            # if sending a packet now won't exceed quotas, send a packet
            for packet_counter in range(min(packet_count_to_send, len(self.probe_states_queue))):
                now = time.time()
                # if queue has items, pop one off
                if len(self.probe_states_queue) > 0:
                    send_buffer_full = False
                    ps = self.probe_states_queue.popleft()

                    # Check if we already sent all probes to this host + we're past the RTT window
                    if ps.probes_sent >= self.max_probes:
                        if time.time() > ps.probe_sent_time + self.rtt:
                            # We've sent max probes to this host and we're past the RTT window, so we're done with this host
                            # we don't add this host back to the queue

                            # Decrement count of probes of this type in queue
                            self.decrease_count_in_queue(ps.probe_index)

                        else:
                            self.probe_states_queue.append(ps)  # add back to queue, but don't send more probes to this host

                    # We need to send a packet.  Also add back to queue so we can check for replies later
                    else:
                        self.probe_states_queue.append(ps)  # add back to queue

                        # Check if probe is due for this host: i.e. if we're past the inter-packet interval for this host; or we never sent a probe; or no inter-packet interval is configured
                        if (ps.probe_sent_time is None) or (self.packet_rate_per_host and (time.time() > ps.probe_sent_time + self.inter_packet_interval_per_host)):
                            # Send probe
                            sent = False
                            remove_and_blacklist = False
                            payload_bin = self.get_probe_payload_bin(ps.probe_index)
                            if payload_bin is None: # It's a custom probe state
                                payload_bin = ps.payload_bin
                            while not sent and not remove_and_blacklist:
                                sock = self.probe_index_to_socket_dict[ps.probe_index]
                                port = self.get_probe_port(ps.probe_index)

                                # For the last few probes, start noting the time we send the last probe.  For the stats.
                                #if more_hosts == 0 and ps.probes_sent == self.max_probes - 1: # This doesn't work if we get a reply before we send the last probe
                                if not more_hosts:
                                    last_send_time = time.time()

                                # At around 16Mbit/s we get occassional errors on sendto: PermissionError: [Errno 1] Operation not permitted
                                # so we catch these errors and retry
                                try:
                                    sock.sendto(payload_bin, (ps.target_ip, port))
                                    sent = True
                                except socket.error as e:
                                    # check if we're running on windows
                                    if sys.platform == 'win32':
                                        # The socket will no longer be usable
                                        print("[E] %s: sending to %s:%s.  Use -B to blocklist.  Fatal error on Windows." % (e, ps.target_ip, port))
                                        sys.exit(1)
                                    else:
                                        if "Errno 13" in str(e):
                                            print("[W] %s: sending to %s:%s.  Use -B to blocklist.  Auto-adding to blocklist" % (e, ps.target_ip, port))
                                            remove_and_blacklist = True
                                        if "Errno 11" in str(e):
                                            if not self.send_buffer_warning_displayed:
                                                print("[W] %s: sending to %s:%s." % (e, ps.target_ip, port))
                                                print("[I] Errno 11 means send buffer is full (SO_SNDBUF).  This will slow the scan down.")
                                                print("""
    Cause: Scanning locally attached networks (i.e. not through a gateway).  Loopback is not affected by this problem.
           Buffers fill up while the kernel fails to resolve the MAC address of the target (using ARP).

    Possible workarounds:
    1) Scan only live hosts on the local network (do an ARP scan to find them)
    2) Fix the code 1: use a pool of sockets for sending; or
    3) Fix the code 2: check if target is local and skip it if there's no ARP cache entry
    """)
                                                print("[I] Attempting to auto-throttle scan (this is going to make it slow)")
                                                self.send_buffer_warning_displayed = True

                                            # Sleep to letter the buffer empty a bit
                                            # We can't sleep too long or we might miss replies
                                            time.sleep(0.1)

                                            if self.next_timer_adjust is None or time.time() > self.next_timer_adjust:
                                                # Intervals of 0.002 - 0.003 worked will during testing.  So increments of
                                                # 0.0003 should work to help us locate a suitable interval.
                                                old_interval = self.inter_packet_interval
                                                self.inter_packet_interval += 0.0003

                                                # As we just slept, the scanner timers will be disrupted, so we need to reset
                                                new_bandwidth_bits_per_second = int(8 * (self.payload_len_estimate + self.packet_overhead) / self.inter_packet_interval)
                                                print("[I] Auto-adjusting bandwidth to %s bits per second" % new_bandwidth_bits_per_second)
                                                self.set_bandwidth(new_bandwidth_bits_per_second)
                                                self.scan_start_time_internal = time.time() # TODO need to track the real start time AND the start time used for timing.

                                                # 0.9 seconds should be enough to let the buffer empty a bit
                                                # after that we'll wait another 0.1 seconds to let the buffer empty a bit more
                                                # This seems a slow way to adjust the timer, but if we go faster, we risk
                                                # overshooting and the scan will run more slowly than necessary
                                                self.next_timer_adjust = time.time() + 0.9

                                            # We didn't send a packet, but we need to set this to avoid a retry
                                            # Retrying is bad because we know the send buffer is full.
                                            sent = True
                                            send_buffer_full = True

                                if remove_and_blacklist:
                                    print("[W] Target IP %s will be removed from scan queue and added to blocklist" % ps.target_ip)
                                    self.add_to_blocklist(ps.target_ip)
                                    try:
                                        self.probe_states_queue.remove(ps)
                                    except ValueError:
                                        print("[W] Couldn't remove from queue")
                                        print(self.probe_states_queue)
                                        exit(1)

                            if send_buffer_full:
                                # Break out of the for-loop so we don't send any more packets right away
                                break

                            # Update stats
                            self.probes_sent_count += 1
                            ps.probes_sent += 1
                            ps.probe_sent_time = time.time()
                            self.bytes_sent += len(payload_bin) + self.packet_overhead

            else:
                # sleep for self.inter_packet_interval seconds
                time.sleep(self.inter_packet_interval) # python might sleep for too long - e.g. minimum of 1-10ms.  That's OK, we'll be less likely to sleep next time round the loop.

            # recv some packets
            # for efficiency we only receive after every 10 packets sent, or if we're past the next recv time
            # whichever is sooner
            now = time.time()
            if self.probes_sent_count % 10 == 0 or self.next_recv_time < now:
                self.next_recv_time = now + self.recv_interval
                scan_running = self.receive_packets(self.get_socket_list()) or more_hosts

        # recv any remaining packets
        self.receive_packets(self.get_socket_list())

        # self.scan_duration = time.time() - self.scan_start_time
        self.scan_duration = last_send_time - self.scan_start_time

        # scan_duration can be 0 for quick scans on windows
        if self.scan_duration == 0:
            self.scan_duration = 0.001
        self.scan_rate_bits_per_second = int(8 * self.bytes_sent / self.scan_duration)

        if self.debug:
            self.debug_write_log()

    def reset_scan_timers(self):
        pass

# returns True if we have more targets to probe; False if not
    def receive_packets(self, socket_list):
        if socket_list:
            # check if there are any packets to receive
            readable, _, _ = select.select(socket_list, [], [], 0)

            # recv if there are
            for s in readable:
                data, addr = (None, None)
                try:
                    data, addr = s.recvfrom(1024) #
                except socket.error as e:
                    continue
                srcip = addr[0]
                srcport = addr[1]
                socket_probe_index = self.get_probe_index_from_socket(s)
                if socket_probe_index is None:
                    print("[W] Received reply from %s:%s but don't know which probe it's for: %s" % (srcip, srcport, str_or_bytes_to_hex(data)))
                    continue
                port = self.get_probe_port(socket_probe_index)
                probe_name = self.get_probe_name(socket_probe_index)

                found = False
                # search for probe state
                for probe_state in self.probe_states_queue:
                    if socket_probe_index == probe_state.probe_index and probe_state.target_ip == srcip and port == srcport:
                        if self.reply_callback_function:
                            self.reply_callback_function(probe_name, srcip, port, str_or_bytes_to_hex(data))
                        else:
                            print("Received reply to probe %s (target port %s) from %s:%s: %s" % (probe_name, port, srcip, srcport, str_or_bytes_to_hex(data)))
                        self.probe_states_queue.remove(probe_state)
                        self.decrease_count_in_queue(probe_state.probe_index)
                        found = True
                        self.replies += 1
                        if self.debug:
                            self.debug_log_reply(probe_name, srcip, port, data)
                        break
                if not found:
                    print("[W] Received unexpected reply to probe %s (target port %s) reply from %s:%s: %s" % (probe_name, port, srcip, srcport, str_or_bytes_to_hex(data)))
                    self.unexpected_replies += 1

        if len(self.probe_states_queue) == 0:
            return False
        return True

    def inform_starting_probe_type(self, probe_index):
        print("[i] Sending probe %s to targets on port %s..." % (self.get_probe_name(probe_index), self.get_probe_port(probe_index)))

    def decrease_count_in_queue(self, probe_index):
        self.count_in_queue[probe_index] -= 1
        if self.count_in_queue[probe_index] == 0:
            self.close_socket_for_probe_index(probe_index)

    def get_queue_length(self):
        return len(self.probe_states_queue)

    def queue_peek_first(self):
        return self.probe_states_queue[0]

    def get_socket_list(self):
        return list(self.probe_index_to_socket_dict.values())

    #
    # UDP Specific Methods
    #

    def set_custom_probes(self, probes): # tuple of (ip, port, probe_name, payload_bin)
        self.custom_probes = probes
        self.target_source = "custom"

    def close_socket_for_probe_index(self, probe_index):
        socket = self.probe_index_to_socket_dict[probe_index]
        if self.debug:
            print("[D] Closing socket for probe index %s (%s on port %s)" % (probe_index, self.get_probe_name(probe_index), self.get_probe_port(probe_index)))
        socket.close()
        del self.probe_index_to_socket_dict[probe_index]

#
# Helper functions
#

# recvfrom returns bytes in python3 and str in python3.  This function converts either to hex string
def str_or_bytes_to_hex(str_or_bytes):
    return "".join("{:02x}".format(c if type(c) is int else ord(c)) for c in str_or_bytes)

def get_time():
    offset = time.timezone
    if time.localtime().tm_isdst:
        offset = time.altzone
    offset = int(offset / 60 / 60 * -1)
    if offset > 0:
        offset = "+" + str(offset)
    else:
        offset = str(offset)
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + " UTC" + offset

def round_pretty(x):
    # avoid math errors
    if x < 0.01:
        x = 0.01
    if x <= 100:
        # round to 3 significant figures
        return round(x, 2-int(math.floor(math.log10(abs(x)))))
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

# return list of ports from a string like "1,2,3-5,6"
def expand_port_list(ports):
    ports_list = []
    for port in ports.split(','):
        if '-' in port:
            port_range = port.split('-')
            if len(port_range) != 2:
                print("[E] Port range %s is not in the right format" % port)
                sys.exit(0)
            for p in range(int(port_range[0]), int(port_range[1]) + 1):
                if 0 < p < 65536:
                    ports_list.append(p)
                else:
                    print("[E] Port %s is not in in range 1-65535" % p)
                    sys.exit(0)
        else:
            port = int(port)
            if 0 < port < 65536:
                ports_list.append(port)
            else:
                print("[E] Port %s is not in in range 1-65535" % port)
                sys.exit(0)
    return ports_list

# hex to bytes
def hex_decode(hex_string):
    return bytes(bytearray.fromhex(hex_string))

def hex_encode(hex_bytes):
    return hex_bytes.hex()

# Define probes
probe_list = []

# from ike-scan
probe_list.append({'source': 'ups', 'name': 'ike', 'payload': '5b5e64c03e99b51100000000000000000110020000000000000001500000013400000001000000010000012801010008030000240101', 'rarity': '1', 'ports': '500'})

# small services
probe_list.append({'source': 'ups', 'name': 'echo', 'payload': '313233', 'rarity': '3', 'ports': '7'})
probe_list.append({'source': 'ups', 'name': 'systat', 'payload': '313233', 'rarity': '3', 'ports': '11'})
probe_list.append({'source': 'ups', 'name': 'daytime', 'payload': '313233', 'rarity': '3', 'ports': '13'})
probe_list.append({'source': 'ups', 'name': 'chargen', 'payload': '313233', 'rarity': '3', 'ports': '19'})
probe_list.append({'source': 'ups', 'name': 'time', 'payload': '313233', 'rarity': '3', 'ports': '37'})

# misc
probe_list.append({'source': 'ups', 'name': 'net-support', 'payload': '01000000000000000000000000000000000080000000000000000000000000000000000000', 'rarity': '6', 'ports': '5405'})
probe_list.append({'source': 'ups', 'name': 'gtpv1', 'payload': '320100040000000050000000', 'rarity': '6', 'ports': '2123'})

# https://community.cisco.com/t5/vpn/problems-getting-l2tp-over-ipsec-on-ios/td-p/1438134
probe_list.append({'source': 'ups', 'name': 'l2tp', 'payload': 'c8020060000000000000000080080000000000018008000000020100800a0000000300000001800a00000004000000000008000000060500800900000007776655000f000000084d6963726f736f6674800800000009000180080000000a0008', 'rarity': '2', 'ports': '1701'})

# These are some probes from amap 5.2
probe_list.append({'source': 'amap', 'name': 'rpc', 'payload': '039b65420000000000000002000f4243000000000000000000000000000000000000000000000000', 'rarity': '1', 'ports': '111'})
probe_list.append({'source': 'amap', 'name': 'ntp', 'payload': 'cb0004fa000100000001000000000000000000000000000000000000000000000000000000000000bfbe7099cdb34000', 'rarity': '1', 'ports': '123'})
probe_list.append({'source': 'amap', 'name': 'snmp-public', 'payload': '3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500', 'rarity': '1', 'ports': '161'})
probe_list.append({'source': 'amap', 'name': 'ms-sql', 'payload': '02', 'rarity': '2', 'ports': '1434'})
probe_list.append({'source': 'amap', 'name': 'ms-sql-slam', 'payload': '0a', 'rarity': '6', 'ports': '1434'})
probe_list.append({'source': 'amap', 'name': 'netop', 'payload': 'd6818152000000f3874e01023200a8c000000113c1d904dd037d00000d005448435448435448435448435448432020202020202020202020202020202020023200a8c00000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'rarity': '6', 'ports': '6502'})
probe_list.append({'source': 'amap', 'name': 'tftp', 'payload': '00012f6574632f706173737764006e6574617363696900', 'rarity': '1', 'ports': '69'})
probe_list.append({'source': 'amap', 'name': 'db2', 'payload': '444232474554414444520053514c3038303230', 'rarity': '6', 'ports': '523'})
probe_list.append({'source': 'amap', 'name': 'citrix', 'payload': '1e00013002fda8e300000000000000000000000000000000000000000000', 'rarity': '3', 'ports': '1604'})

# Nmap lists a lot of ports for some probe types.  Reduce those by listing a smaller portlist instead.
nmap_preferences = []
nmap_preferences.append({'name': 'RPCCheck', 'ports': '111'})
nmap_preferences.append({'name': 'DNSVersionBindReq', 'ports': '53'})
nmap_preferences.append({'name': 'Help', 'ports': '42'}) # TODO what is port 42?
nmap_preferences.append({'name': 'DNSStatusRequest', 'ports': '53'})
nmap_preferences.append({'name': 'NTPRequest', 'ports': '123'})
nmap_preferences.append({'name': 'AFSVersionRequest', 'ports': '7001'})
nmap_preferences.append({'name': 'DTLSSessionReq', 'ports': '443'})
nmap_preferences.append({'name': 'Sqlping', 'ports': '1434'})

# These are from nmap
nmap_probe_list = []
# The lines below can be updated with newer nmap probes.
# This list was taken from nmap 7.80, which has a GPLv2 compatible license.
# To extract probes from a different version of nmap:
#  python3 parse-nmap.py nmap-service-probes
# ===
nmap_probe_list.append({'source': 'nmap', 'name': 'RPCCheck', 'payload': '72fe1d130000000000000002000186a00001977c0000000000000000000000000000000000000000', 'rarity': '1', 'ports': '17,88,111,407,500,517,518,1419,2427,4045,10000,10080,12203,27960,32750-32810,38978'})
nmap_probe_list.append({'source': 'nmap', 'name': 'DNSVersionBindReq', 'payload': '0006010000010000000000000776657273696f6e0462696e640000100003', 'rarity': '1', 'ports': '53,1967,2967'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Help', 'payload': '68656c700d0a0d0a', 'rarity': '3', 'ports': '7,13,37,42'})
nmap_probe_list.append({'source': 'nmap', 'name': 'NBTStat', 'payload': '80f00010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001', 'rarity': '4', 'ports': '137'})
nmap_probe_list.append({'source': 'nmap', 'name': 'SNMPv1public', 'payload': '3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500', 'rarity': '4', 'ports': '161'})
nmap_probe_list.append({'source': 'nmap', 'name': 'SNMPv3GetRequest', 'payload': '303a020103300f02024a69020300ffe30401040201030410300e0400020100020100040004000400301204000400a00c020237f00201000201003000', 'rarity': '4', 'ports': '161'})
nmap_probe_list.append({'source': 'nmap', 'name': 'DNS-SD', 'payload': '000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001', 'rarity': '4', 'ports': '5353'})
nmap_probe_list.append({'source': 'nmap', 'name': 'DNSStatusRequest', 'payload': '000010000000000000000000', 'rarity': '5', 'ports': '53,69,135,1761'})
nmap_probe_list.append({'source': 'nmap', 'name': 'SIPOptions', 'payload': '4f5054494f4e53207369703a6e6d205349502f322e300d0a5669613a205349502f322e302f554450206e6d3b6272616e63683d666f6f3b72706f72740d0a46726f6d3a203c7369703a6e6d406e6d3e3b7461673d726f6f740d0a546f3a203c7369703a6e6d32406e6d323e0d0a43616c6c2d49443a2035303030300d0a435365713a203432204f5054494f4e530d0a4d61782d466f7277617264733a2037300d0a436f6e74656e742d4c656e6774683a20300d0a436f6e746163743a203c7369703a6e6d406e6d3e0d0a4163636570743a206170706c69636174696f6e2f7364700d0a0d0a', 'rarity': '5', 'ports': '5060'})
nmap_probe_list.append({'source': 'nmap', 'name': 'NTPRequest', 'payload': 'e30004fa000100000001000000000000000000000000000000000000000000000000000000000000c54f234b71b152f3', 'rarity': '5', 'ports': '123,5353,9100'})
nmap_probe_list.append({'source': 'nmap', 'name': 'AFSVersionRequest', 'payload': '000003e7000000000000006500000000000000000d0500000000000000000000', 'rarity': '5', 'ports': '7001,1719'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Citrix', 'payload': '1e00013002fda8e300000000000000000000000000000000000000000000', 'rarity': '5', 'ports': '1604'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Kerberos', 'payload': '6a816e30816ba103020105a20302010aa4815e305ca00703050050800010a2041b024e4da3173015a003020100a10e300c1b066b72627467741b024e4da511180f31393730303130313030303030305aa70602041f1eb9d9a8173015020112020111020110020117020101020103020102', 'rarity': '5', 'ports': '88'})
nmap_probe_list.append({'source': 'nmap', 'name': 'DTLSSessionReq', 'payload': '16feff000000000000000000360100002a000000000000002afefd000000007c77401e8ac822a0a018ff9308caac0a642fc92264bc08a81689193000000002002f0100', 'rarity': '5', 'ports': '443,853,4433,4740,5349,5684,5868,6514,6636,8232,10161,10162,12346,12446,12546,12646,12746,12846,12946,13046'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Sqlping', 'payload': '02', 'rarity': '6', 'ports': '1434,19131-19133'})
nmap_probe_list.append({'source': 'nmap', 'name': 'xdmcp', 'payload': '00010002000100', 'rarity': '6', 'ports': '177'})
nmap_probe_list.append({'source': 'nmap', 'name': 'QUIC', 'payload': '0d89c19c1c2afffcf15139393900', 'rarity': '6', 'ports': '3310'})
nmap_probe_list.append({'source': 'nmap', 'name': 'sybaseanywhere', 'payload': '1b00003d0000000012434f4e4e454354494f4e4c4553535f544453000000010000040005000500000102000003010104080000000000000000070204b1', 'rarity': '7', 'ports': '2638'})
nmap_probe_list.append({'source': 'nmap', 'name': 'NetMotionMobility', 'payload': '00405000000000855db491280000000000017c9140000000aa39da423765cf010000000000000000000000000000000000000000000000000000000000000000', 'rarity': '7', 'ports': '5008'})
nmap_probe_list.append({'source': 'nmap', 'name': 'LDAPSearchReqUDP', 'payload': '30840000002d02010763840000002404000a01000a0100020100020164010100870b6f626a656374436c617373308400000000', 'rarity': '8', 'ports': '389'})
nmap_probe_list.append({'source': 'nmap', 'name': 'ibm-db2-das-udp', 'payload': '444232474554414444520053514c303830313000', 'rarity': '8', 'ports': '523'})
nmap_probe_list.append({'source': 'nmap', 'name': 'SqueezeCenter', 'payload': '6549504144004e414d45004a534f4e00564552530055554944004a56494406123456781234', 'rarity': '8', 'ports': '3483'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Quake2_status', 'payload': 'ffffffff737461747573', 'rarity': '8', 'ports': '27910-27914'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Quake3_getstatus', 'payload': 'ffffffff676574737461747573', 'rarity': '8', 'ports': '26000-26004,27960-27964,30720-30724,44400'})
nmap_probe_list.append({'source': 'nmap', 'name': 'serialnumberd', 'payload': '534e51554552593a203132372e302e302e313a4141414141413a78737672', 'rarity': '8', 'ports': '626'})
nmap_probe_list.append({'source': 'nmap', 'name': 'vuze-dht', 'payload': 'fff0970d2e60d16f000004000055abec32000000000032040a00c875f816005cb965000000004ed1f528', 'rarity': '8', 'ports': '17555,49152-49156'})
nmap_probe_list.append({'source': 'nmap', 'name': 'pc-anywhere', 'payload': '4e51', 'rarity': '8', 'ports': '5632'})
nmap_probe_list.append({'source': 'nmap', 'name': 'pc-duo', 'payload': '00808008ff00', 'rarity': '8', 'ports': '1505'})
nmap_probe_list.append({'source': 'nmap', 'name': 'pc-duo-gw', 'payload': '20908008ff00', 'rarity': '8', 'ports': '2303'})
nmap_probe_list.append({'source': 'nmap', 'name': 'memcached', 'payload': '000100000001000073746174730d0a', 'rarity': '8', 'ports': '11211'})
nmap_probe_list.append({'source': 'nmap', 'name': 'svrloc', 'payload': '0201000036200000000000010002656e00000015736572766963653a736572766963652d6167656e74000764656661756c7400000000', 'rarity': '8', 'ports': '427'})
nmap_probe_list.append({'source': 'nmap', 'name': 'ARD', 'payload': '0014000103', 'rarity': '8', 'ports': '3283'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Quake1_server_info', 'payload': '8000000c025155414b450003', 'rarity': '9', 'ports': '26000-26004'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Quake3_master_getservers', 'payload': 'ffffffff6765747365727665727320363820656d7074792066756c6c', 'rarity': '9', 'ports': '27950,30710'})
nmap_probe_list.append({'source': 'nmap', 'name': 'BackOrifice', 'payload': 'ce63d1d216e713cf38a5a586b2754b99aa3258', 'rarity': '9', 'ports': '19150'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Murmur', 'payload': '000000006162636465666768', 'rarity': '9', 'ports': '64738'})
nmap_probe_list.append({'source': 'nmap', 'name': 'Ventrilo', 'payload': '01e7e57531a3170b21cfbf2b994edd19acde085f8b240a1119b6736fad2813d20ab91275', 'rarity': '9', 'ports': '3784'})
nmap_probe_list.append({'source': 'nmap', 'name': 'TeamSpeak2', 'payload': 'f4be03000000000000000000010000003278ba85095465616d537065616b00000000000000000000000000000000000000000a57696e646f7773205850000000000000000000000000000000000000000200000020003c000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086e69636b6e616d65000000000000000000000000000000000000000000', 'rarity': '9', 'ports': '8767'})
nmap_probe_list.append({'source': 'nmap', 'name': 'TeamSpeak3', 'payload': '05ca7f169c11f98900000000029d748b45aa7befb99efead0819bacf41e016a2326cf3cff48e3c4483c88d51456f9095233e00972b1c71b24ec061f1d76fc57ef64852bf826aa23b65aa187a1738c38127c347fca735bafc0f9d9d72249dfc02176d6bb12d72c6e3171c95d9699957cedddf05dc039456043a14e5ad9a2b14303a23a325ade8e6398a852ac6dfe55d2da02f5d9cd72b24fbb09cc2ba89b41b17a2b6', 'rarity': '9', 'ports': '9987'})
nmap_probe_list.append({'source': 'nmap', 'name': 'FreelancerStatus', 'payload': '0002f1260126f090a6f026574eaca0ecf868e48d21', 'rarity': '9', 'ports': '2302'})
nmap_probe_list.append({'source': 'nmap', 'name': 'ASE', 'payload': '73', 'rarity': '9', 'ports': '1258,2126,3123,12444,13200,23196,26000,27138,27244,27777,28138'})
nmap_probe_list.append({'source': 'nmap', 'name': 'AndroMouse', 'payload': '414d534e494646', 'rarity': '9', 'ports': '8888'})
nmap_probe_list.append({'source': 'nmap', 'name': 'AirHID', 'payload': '66726f6d3a616972686964', 'rarity': '9', 'ports': '13246'})
nmap_probe_list.append({'source': 'nmap', 'name': 'OpenVPN', 'payload': '3864c17801b89bcb8f0000000000', 'rarity': '9', 'ports': '1962'})
nmap_probe_list.append({'source': 'nmap', 'name': 'ipmi-rmcp', 'payload': '0600ff07000000000000000000092018c88100388e04b5', 'rarity': '9', 'ports': '623'})
nmap_probe_list.append({'source': 'nmap', 'name': 'coap-request', 'payload': '400101cebb2e77656c6c2d6b6e6f776e04636f7265', 'rarity': '9', 'ports': '5683'})
nmap_probe_list.append({'source': 'nmap', 'name': 'UbiquitiDiscoveryv1', 'payload': '01000000', 'rarity': '9', 'ports': '10001'})
nmap_probe_list.append({'source': 'nmap', 'name': 'UbiquitiDiscoveryv2', 'payload': '02080000', 'rarity': '9', 'ports': '10001'})
# ===

if __name__ == "__main__":
    VERSION = "0.9.1"

    # Defaults
    DEFAULT_MAX_PROBES = 2
    DEFAULT_BANDWIDTH = "250k"
    DEFAULT_PACKET_RATE = 0
    DEFAULT_PACKET_HOST_RATE = 2
    DEFAULT_RTT = 1
    DEFAULT_RARITY = 6
    DEFAULT_PROBES = "all"

    # These get overriden later
    max_probes = DEFAULT_MAX_PROBES
    bandwidth = DEFAULT_BANDWIDTH
    packet_rate = DEFAULT_PACKET_RATE
    packet_rate_per_host = DEFAULT_PACKET_HOST_RATE
    rtt = DEFAULT_RTT
    rarity = DEFAULT_RARITY

    probe_dict = {}                  # populated later with all possible probes from config above
    probe_names_selected = []        # from command line
    blocklist_ips = []               # populated later with all ips in blocklist

    script_name = sys.argv[0]

    # parse command line options
    parser = argparse.ArgumentParser(usage='%s [options] [ -p probe_name ] -f ipsfile\n       %s [options] [ -p probe_name ] 10.0.0.0/16 10.1.0.0-10.1.1.9 192.168.0.1' % (script_name, script_name))

    parser.add_argument('-f', '--file', dest='file', help='File of ips')
    parser.add_argument('-p', '--probe_name', dest='probe_name_str_list', default=DEFAULT_PROBES, type=str, help='Name of probe or "all".  Default: %s' % (DEFAULT_PROBES))
    parser.add_argument('-l', '--list_probes', dest='list_probes', action="store_true", help='List all available probe name then exit')
    parser.add_argument('-b', '--bandwidth', dest='bandwidth', default=DEFAULT_BANDWIDTH, type=str, help='Bandwidth to use in bits/sec.  Default %s' % (DEFAULT_BANDWIDTH))
    parser.add_argument('-c', '--commonness', dest='commonness', default=argparse.SUPPRESS, type=int, help='Commonness of probes to send 1-9.  9 is common, 1 is rare.  Implies -p all.  Default %s' % (10-DEFAULT_RARITY))
    parser.add_argument('-P', '--packetrate', dest='packetrate', default=DEFAULT_PACKET_RATE, type=str, help='Max packets/sec to send.  Default unlimited')
    parser.add_argument('-H', '--retryrate', dest='packehosttrate', default=DEFAULT_PACKET_HOST_RATE, type=int, help='Max rate (packets/sec) for retrying the same probe.  Default %s' % (DEFAULT_PACKET_HOST_RATE))
    parser.add_argument('-R', '--rtt', dest='rtt', default=DEFAULT_RTT, type=str, help='Max round trip time for probe.  Default %ss' % (DEFAULT_RTT))
    parser.add_argument('-r', '--retries', dest='retries', default=DEFAULT_MAX_PROBES, type=int, help='No of packets to sent to each host.  Default %s' % (DEFAULT_MAX_PROBES))
    parser.add_argument('-d', '--debug', dest='debug', action="store_true", help='Debug mode')
    parser.add_argument('-B', '--blocklist', dest='blocklist', default=None, type=str, help='List of blacklisted ips.  Useful on windows to blocklist network addresses.  Separate with commas: 127.0.0.0,192.168.0.0.  Default None')
    args, targets = parser.parse_known_args()

    #
    # Change defaults based on command line options
    #

    # set max_probes from retries
    if args.retries is not None:
        max_probes = args.retries + 1

    # set bandwidth
    if args.bandwidth is not None:
        bandwidth = args.bandwidth

    # set packet rate
    if args.packetrate is not None:
        packet_rate = args.packetrate

    # set packet rate per host
    if args.packehosttrate is not None:
        packet_rate_per_host = args.packehosttrate

    # set rtt
    if args.rtt is not None:
        rtt = args.rtt

    # set probe names
    if args.probe_name_str_list is not None:
        probe_names_selected = args.probe_name_str_list.split(',')

    # set rarity
    if 'commonness' in args:
        rarity = 10 - args.commonness
        if "all" not in probe_names_selected:
            probe_names_selected.append("all")
    else:
        rarity = DEFAULT_RARITY

    # set blocklist
    if args.blocklist is not None:
        blocklist_ips = args.blocklist.split(',')

    #
    # Parse probe data, probe options
    #

    # Populate probe_dict from probe_list
    for probe in probe_list + nmap_probe_list:
        source = probe['source']
        name = probe['name']
        payload = probe['payload']
        probe_rarity = probe['rarity']
        ports_string = probe['ports']

        # Check types to keep things neat
        if not type(probe_rarity) == str:
            print("[E] Rarity should be a string, not %s" % type(probe_rarity))
            sys.exit(0)
        if not type(ports_string) == str:
            print("[E] Ports should be a string, not %s" % type(ports_string))
            sys.exit(0)

        probe_rarity = int(probe_rarity)

        # Use a different port list than nmap if specified in nmap_preferences
        if source == 'nmap':
            for pref_dict in nmap_preferences:
                if name == pref_dict['name']:
                    ports_string = pref_dict['ports']

        if name not in probe_dict.keys():
            probe_dict[name] = {}

        for port in expand_port_list(ports_string):
            if port not in probe_dict[name].keys():
                probe_dict[name][port] = {}
            probe_dict[name][port]["config_tuple"] = (port, name, payload)
            probe_dict[name][port]["rarity"] = probe_rarity

    # check probe_names are valid
    for probe_name in probe_names_selected:
        if probe_name not in list(probe_dict.keys()) + ["all"]:
            print("[E] Probe name %s (from -p) unknown.  Use -l to list valid names" % (probe_name))
            sys.exit(0)

    # check probe_names are valid
    probes_to_use_tuple_list = []
    all_probe_names = list(probe_dict.keys())

    # Iterate over probe_dict and select required probes, adding them to probe_names and probe_tuples_list
    for probe_name in probe_dict.keys():
        if probe_name in probe_names_selected:
            # Add regardless of rarity
            for port in probe_dict[probe_name].keys():
                probes_to_use_tuple_list.append(probe_dict[probe_name][port]["config_tuple"])

        if "all" in probe_names_selected:
            for port in probe_dict[probe_name].keys():
                # Add if rarity matches
                if probe_dict[probe_name][port]["rarity"] <= rarity:
                    probes_to_use_tuple_list.append(probe_dict[probe_name][port]["config_tuple"])

    # print a unique list of ports used by the probes - used by test-server to prove the scanner is working
    if args.debug:
        ports_used = []
        for probe_name in probe_dict.keys():
            for port in probe_dict[probe_name].keys():
                if port not in ports_used:
                    ports_used.append(port)
        ports_used.sort()
        print("[D] Using ports %s" % (ports_used))

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
        for probe_name in ["all"] + all_probe_names:
            print("* %s" % probe_name)
        sys.exit(0)

    # error if rarity is not 1-9
    if rarity < 1 or rarity > 9:
        print("[E] Rarity must be between 1 and 9")
        sys.exit(0)

    # error if no targets were specified
    if not args.file and not targets:
        parser.print_help()
        sys.exit(0)

    # error if --file and targets were specified
    if args.file and targets:
        print("[E] You cannot specify both a file of targets and a list of targets")
        sys.exit(0)

    print("Starting udpy_proto_scanner v%s ( https://github.com/CiscoCXSecurity/udpy_proto_scanner ) at %s" % (VERSION, get_time()))

    # Send each type of probe separately
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
    scanner.set_probes(probes_to_use_tuple_list)
    scanner.set_debug(args.debug)
    scanner.set_blocklist(blocklist_ips)

    # Start scan
    scanner.start_scan()

    # Print stats
    print("")
    print("Total replies: %s (+%s unexpected replies)" % (scanner.replies, scanner.unexpected_replies))
    print("Scan for complete at %s" % get_time())
    print("Sent %s bytes (%s bits) in %s probes in %ss to %s hosts: %s bits/s, %s bytes/s, %s packets/s" % (scanner.bytes_sent, scanner.bytes_sent * 8, scanner.probes_sent_count, round_pretty(scanner.scan_duration), scanner.host_count, scanner.scan_rate_bits_per_second, round_pretty(scanner.bytes_sent / scanner.scan_duration), round_pretty(scanner.probes_sent_count / scanner.scan_duration)))
