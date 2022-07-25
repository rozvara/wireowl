# -*- coding: utf8 -*-

# This file is part of wireowl and pcap2pdf which are released under GNU GPLv2 license.
#
# Copyright 2021, 2022 Jiri Rozvaril <rozvara at vync dot org>

import time
import threading
import ipaddress
import subprocess
from collections import deque

# expected columns exported by tshark (see fields.conf)
P_TIME, P_ETHSRC, P_ETHDST, \
P_IPSRC, P_IPDST, P_IPV6SRC, P_IPV6DST, \
P_TCPSRCPORT, P_TCPDSTPORT, P_TCPSTREAM, \
P_UDPSRCPORT, P_UDPDSTPORT, P_UDPSTREAM, \
P_PROTOCOL, P_DHCPHOSTNAME, \
P_DNSQRYNAME, P_DNSCNAME, P_DNSA, P_DNSAAAA, \
P_DNSNSECNEXTDOMAINNAME, P_DNSPTRDOMAINNAME, P_DNSQRYNAME, \
P_DNSRESPNAME, P_DNSSRVNAME, P_DNSSRVPROTO, \
P_DNSSRVSERVICE, P_DNSSRVTARGET, P_DNSTXT, \
P_FRAMELEN, P_TCPLEN, P_INFO, COLUMNS_EXPECTED = range(32)

# information to dig from mDNS (multicast) packets
MDNS_KEYS = [('dns.qry.name',              P_DNSQRYNAME),
             ('dns.nsec.next_domain_name', P_DNSNSECNEXTDOMAINNAME),
             ('dns.resp.name',             P_DNSRESPNAME),
             ('dns.ptr.domain_name',       P_DNSPTRDOMAINNAME),
             ('dns.srv.name',              P_DNSSRVNAME),
             ('dns.srv.proto',             P_DNSSRVPROTO),
             ('dns.srv.service',           P_DNSSRVSERVICE),
             ('dns.srv.target',            P_DNSSRVTARGET),
             ('dns.txt',                   P_DNSTXT)]


#    #          ######
 #    #         #     #   ##    ####  #    # ###### #    # #####
  #    #        #     #  #  #  #    # #   #  #      ##   # #    #
   #    #       ######  #    # #      ####   #####  # #  # #    #
  #    #        #     # ###### #      #  #   #      #  # # #    #
 #    #         #     # #    # #    # #   #  #      #   ## #    #
#    #          ######  #    #  ####  #    # ###### #    # #####


class TrafficInspector():
    """
    Inspects packets and updates data of devices and their communication
    """
    def __init__(self):
        self.devices = {}               # all devices (dict: 'macaddr':MacAddrDevice)
        self.clients = set()            # client's devices, set of keys/mac addresses
        self.last_pkt_time = 0          # time of last processed packet
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        with self._lock:
            self.last_pkt_time = float(pkt[P_TIME])
            self.mac_addresses_update(pkt)
            # always update src
            self.devices[pkt[P_ETHSRC]].inspect_packet_and_update(pkt)
            # update dst when recognized
            if pkt[P_ETHDST] in self.devices:
                self.devices[pkt[P_ETHDST]].inspect_packet_and_update(pkt)

    def mac_addresses_update(self, pkt):
        # Checks and adds new devices and/or new clients
        if not pkt[P_ETHSRC] in self.devices:
            self.devices[pkt[P_ETHSRC]] = MacAddrDevice(pkt[P_ETHSRC])
        # uncoment if interested in all ethdst (eg. broadcasts)
        ##### if not pkt[P_ETHDST] in self.devices:
        #####     self.devices[pkt[P_ETHDST]] = MacAddrDevice(pkt[P_ETHDST])

        # check/add clients (based on dhcp or dns requests)
        if pkt[P_PROTOCOL] == 'DNS' and pkt[P_INFO].startswith('Standard query 0x'):
            self.clients.add(pkt[P_ETHSRC])
        elif pkt[P_PROTOCOL] == 'DHCP' and pkt[P_INFO].startswith('DHCP ACK') and \
            pkt[P_IPDST] != '255.255.255.255':
            self.clients.add(pkt[P_ETHDST])

    def get_devices(self):
        with self._lock:
            ret = list(self.devices.keys())
        ret.sort()
        return ret

    def get_clients(self):
        with self._lock:
            ret = list(self.clients)
        ret.sort()
        return ret

    def get_device_statistics(self, macaddr, ui_time):
        with self._lock:
            ret = self.devices[macaddr].device_statistics(ui_time)
        return ret

    def get_device_connections(self, macaddr, ui_time):
        with self._lock:
            ret = self.devices[macaddr].connections_list(ui_time)
        return ret

    def get_device_dnsreplies(self, macaddr):
        with self._lock:
            ret = self.devices[macaddr].dns_reply_list()
        return ret

    def get_device_domain_ips_list(self, macaddr):
        with self._lock:
            ret = self.devices[macaddr].domain_ips_list()
        return ret

    def get_device_dnscnames(self, macaddr):
        with self._lock:
            ret = self.devices[macaddr].dns_cnames_list()
        return ret

    def get_device_mdns(self, macaddr):
        with self._lock:
            ret = self.devices[macaddr].mdns_list()
        return ret

    def get_device_ip_name(self, macaddr, ip):
        ret = self.devices[macaddr].ip_name(ip)
        return ret

    def get_device_ip_tx_min_graph(self, macaddr, ip, ui_time):
        with self._lock:
            ret = self.devices[macaddr].connections[ip].tx_min_graph_data(ui_time)
        return ret

    def get_device_ip_tx_sec_graph(self, macaddr, ip, ui_time):
        with self._lock:
            ret = self.devices[macaddr].connections[ip].tx_sec_graph_data(ui_time)
        return ret

    def get_device_ip_rx_min_graph(self, macaddr, ip, ui_time):
        with self._lock:
            ret = self.devices[macaddr].connections[ip].rx_min_graph_data(ui_time)
        return ret

    def get_device_ip_rx_sec_graph(self, macaddr, ip, ui_time):
        with self._lock:
            ret = self.devices[macaddr].connections[ip].rx_sec_graph_data(ui_time)
        return ret

    def clear_device_stats(self, macaddr):
        with self._lock:
            self.devices[macaddr].clear_statistics()

    def clear_device_all(self, macaddr):
        with self._lock:
            self.devices[macaddr] = MacAddrDevice(macaddr)

    def export_device(self, macaddr, ui_time):
        with self._lock:
            try:
                wf = open(f"/tmp/wireowl-export-{macaddr.replace(':','')}-{int(ui_time)}.txt", 'w')
                wf.write(f"DEVICE {macaddr} @ {ui_time}\n")
                wf.write(f"{self.devices[macaddr].device_statistics(ui_time)}\n\n")
                wf.write("CONNECTIONS LIST\n")
                wf.write(f"{self.devices[macaddr].connections_list(ui_time)}\n\n")
                wf.write("IP->DOMAINS\n")
                wf.write(f"{self.devices[macaddr].dns_reply_list()}\n\n")
                wf.write("DOMAIN->IPs\n")
                wf.write(f"{self.devices[macaddr].domain_ips_list()}\n\n")
                wf.write("CNAMES\n")
                wf.write(f"{self.devices[macaddr].dns_cnames_list()}\n\n")
                wf.write("SRV TARGETS\n")
                wf.write(f"{self.devices[macaddr].srvtargets}\n\n")
                wf.write("MDNS\n")
                wf.write(f"{self.devices[macaddr].mdns_list()}\n\n")
                wf.close()
            except:
                return False
            return True


#    #          ######
 #    #         #     # ###### #    # #  ####  ######
  #    #        #     # #      #    # # #    # #
   #    #       #     # #####  #    # # #      #####
  #    #        #     # #      #    # # #      #
 #    #         #     # #       #  #  # #    # #
#    #          ######  ######   ##   #  ####  ######


class MacAddrDevice():
    """
    Statistics for one device, which is every seen MAC addresses in network capture
    """
    def __init__(self, macaddr):
        self.my_macaddress = macaddr    # device's mac address
        self.first_pkt_time = 0         # time of first received packet
        self.last_pkt_time = 0          # time of last sent packet
        self.packets_count = 0          # total packets processed
        self.my_ips = set()             # all device's seen IP addresses
        self.my_hostname = set()        # hostname advertised to dhcp service
        self.tx_protocols = set()       # outgoing protocols
        self.connections = {}           # IP connections from/to device dict: 'ip':IPConnection
        self.longest_conn = 10          # length of longest IP address in connection for formatting
        self.ip2domains = {}            # DNS queries dict: 'ip':set(domain,domain,domain...)
        self.domain2ips = {}            # DNS queries dict: 'domain':set(ip,ip,ip...)
        self.blockeddomains = set()     # DNS queries blocked by DNS server
        self.cnames = {}                # CNAMES of requested domains
        self.srvtargets = {}            # SRV records  # TODO: do I understand SRV records PROPERLY?
        self.mdns = {}                  # mDSN info transmitting from device
        self.tx_bytes = 0               # transmitted bytes
        self.rx_bytes = 0               # received bytes
        self.tx_pkts = 0                # transmitted packets
        self.rx_pkts = 0                # received packets
        self.dns_queries = 0            # no. of DNS queries
        self.dns_replies = 0            # no. of DNS replies

    # inspect packet from device's point of view (both sender and receiver)
    def inspect_packet_and_update(self, pkt):

        # process DNS replies to know who is who (IP->domains)
        if pkt[P_PROTOCOL] == 'DNS':
            if self.my_macaddress == pkt[P_ETHDST]:
                self.dns_replies += 1
                self.update_dns_ips(pkt)
            else:
                self.dns_queries += 1

        # what is device telling to network (Bonjour, Avahi etc)
        elif pkt[P_PROTOCOL] == 'MDNS':
            if self.my_macaddress == pkt[P_ETHSRC]:
                self.update_mdns(pkt)

        elif pkt[P_PROTOCOL] == 'DHCP':
            if self.my_macaddress == pkt[P_ETHSRC] and pkt[P_DHCPHOSTNAME]:
                self.my_hostname.update([pkt[P_DHCPHOSTNAME]])

        def ip_address(direction, pkt):
            if direction == 'src':
                ipaddr = pkt[P_IPSRC] if pkt[P_IPSRC] else pkt[P_IPV6SRC]
            else:
                ipaddr = pkt[P_IPDST] if pkt[P_IPDST] else pkt[P_IPV6DST]
            # work around: tshark sometimes exports both ipdst and ipsrc in one field
            if '|' in ipaddr:
                ipaddr = ipaddr.split('|')[0]
            return ipaddr

        # update device stats AND IP connection stats
        ipaddr = None
        if self.my_macaddress == pkt[P_ETHSRC]:  # when the device is source...
            self.tx_protocols.add(packet_protocol(pkt))
            self.tx_bytes += int(pkt[P_FRAMELEN])
            self.tx_pkts += 1
            ipaddr = ip_address('src', pkt)  # device's own IP address
            if ipaddr:
                # local network addresses should be address of the device
                # (if many, than it's a router)
                if ipaddr not in ['0.0.0.0', '::']:
                    if ipaddress.ip_address(ipaddr).is_private:
                        self.my_ips.add(ipaddr)

            # update last activity time, if device transmits
            self.update_activity_time(float(pkt[P_TIME]))
            ipaddr = ip_address('dst', pkt)           # ...update destination connection

        elif self.my_macaddress == pkt[P_ETHDST]:  # when the device is destination...
            self.rx_bytes += int(pkt[P_FRAMELEN])
            self.rx_pkts += 1
            ipaddr = ip_address('src', pkt)           # ...update source connection

        if ipaddr:
            self.update_ip_connection(ipaddr, pkt)

        self.packets_count += 1

    def update_activity_time(self, epochtime):
        self.last_pkt_time = epochtime
        if not self.first_pkt_time:
            self.first_pkt_time = epochtime

    def update_ip_connection(self, ipaddr, pkt):
        # check/add connection
        if not ipaddr in self.connections:
            self.connections[ipaddr] = IPConnection(ipaddr)
            self.longest_conn = max(self.longest_conn, len(ipaddr))
        # update
        self.connections[ipaddr].inspect_packet_and_update(self.my_macaddress, pkt)

    def update_dns_ips(self, pkt):
        # SRV response
        if pkt[P_DNSSRVNAME] and pkt[P_DNSSRVTARGET]:
            if pkt[P_DNSSRVTARGET] != '<Root>':
                self.srvtargets[pkt[P_DNSSRVTARGET]] = pkt[P_DNSSRVNAME]
                if pkt[P_DNSSRVNAME] not in self.cnames:
                    self.cnames[pkt[P_DNSSRVNAME]] = set()
                self.cnames[pkt[P_DNSSRVNAME]].update([pkt[P_DNSSRVTARGET]])

        # A/AAAA response (linked to previous SRV target, if any; otherwise normal)
        if pkt[P_DNSA] or pkt[P_DNSAAAA]:
            ips = set(pkt[P_DNSA].split('|') + pkt[P_DNSAAAA].split('|'))
            ips.remove('')

            if pkt[P_DNSQRYNAME] in self.srvtargets:
                qryname = self.srvtargets[pkt[P_DNSQRYNAME]]
            else:
                qryname = pkt[P_DNSQRYNAME]

            for ip in ips:
                if ip not in self.ip2domains:
                    self.ip2domains[ip] = set()
                self.ip2domains[ip].update([qryname])

            if qryname not in self.domain2ips:
                self.domain2ips[qryname] = set()
            self.domain2ips[qryname].update(ips)

            # CNAMES
            domains = set(pkt[P_DNSRESPNAME].split('|') + pkt[P_DNSCNAME].split('|'))
            if '' in domains: domains.remove('')
            if '<Root>' in domains: domains.remove('<Root>')
            if pkt[P_DNSQRYNAME] in domains: domains.remove(pkt[P_DNSQRYNAME])
            if domains:
                if pkt[P_DNSQRYNAME] not in self.cnames:
                    self.cnames[pkt[P_DNSQRYNAME]] = set()
                self.cnames[pkt[P_DNSQRYNAME]].update(domains)

    def update_mdns(self, pkt):
        for key, idx in MDNS_KEYS:
            if pkt[idx]:
                values = pkt[idx].split('|')
                if key not in self.mdns:
                    self.mdns[key] = set()
                self.mdns[key].update(values)

    def dns_reply_list(self):
        return self.ip2domains

    def domain_ips_list(self):
        return self.domain2ips

    def unique_domains_requested(self):
        return len(self.domain2ips)

    def dns_cnames_list(self):
        return self.cnames

    def mdns_list(self):
        return self.mdns

    def ip_name(self, ip):
        if ip in self.ip2domains:
            txt = ', '.join(self.ip2domains[ip])
            if self.connections[ip].private_ip:
                txt += " (local)"
        else:
            if self.connections[ip].multicast_ip:
                txt = "Multicast"
            elif self.connections[ip].private_ip:
                txt = "Reserved" if self.connections[ip].reserved_ip else "Local network"
            elif self.connections[ip].global_ip:
                txt = "Global IP"
            else:
                txt = "Unknown type of"
            txt +=  " address"
        return txt

    def device_statistics(self, now):
        dct = {}
        dct['rx'] = self.rx_bytes
        dct['tx'] = self.tx_bytes
        dct['rp'] = self.rx_pkts
        dct['tp'] = self.tx_pkts
        dct['dnsq'] = self.dns_queries
        dct['dnsr'] = self.dns_replies
        dct['dnsd'] = self.unique_domains_requested()
        dct['conn'] = len(self.connections.keys())
        dct['colw'] = self.longest_conn
        dct['pkts'] = self.packets_count
        dct['fa'] = self.first_pkt_time
        dct['la'] = self.last_pkt_time - now    # 0 first, older minus (time unseen)
        dct['prot'] = self.tx_protocols
        ips = list(self.my_ips)
        ips.sort()
        dct['ip'] = ', '.join(ips) if ips else ''
        dct['hn'] = ', '.join(list(self.my_hostname)) if self.my_hostname else ''
        return dct

    def clear_statistics(self):
        self.first_pkt_time = 0
        self.last_pkt_time = 0
        self.packets_count = 0
        self.tx_protocols = set()
        self.connections = {}
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.tx_pkts = 0
        self.rx_pkts = 0
        self.dns_queries = 0

    def connections_list(self, now):
        dct = {}
        for ip in self.connections.keys():
            dct[ip] = self.connections[ip].ip_statistics(now)
        return dct

# protocol/port for TCP, protocol\port for UDP
#
def packet_protocol(pkt):
    ret = pkt[P_PROTOCOL]
    if pkt[P_UDPDSTPORT]:
        ret += '\\' + pkt[P_UDPDSTPORT]
    elif pkt[P_TCPDSTPORT]:
        ret += '/' + pkt[P_TCPDSTPORT]
    return ret



#    #          ### ######
 #    #          #  #     #     ####   ####  #    # #    #
  #    #         #  #     #    #    # #    # ##   # ##   #
   #    #        #  ######     #      #    # # #  # # #  #
  #    #         #  #          #      #    # #  # # #  # #
 #    #          #  #          #    # #    # #   ## #   ##
#    #          ### #           ####   ####  #    # #    #


class IPConnection():
    """
    Statistics for an IP address/server, from device's point of view (sender or receiver)
    """
    def __init__(self, ipaddr):
        self.my_ipaddress = ipaddr   # IP address of the object
        self.tx_protocols = set()

        self.first_touch = 0
        self.last_touch = 0

        self.tx_bytes = 0
        self.tx_sec_graph = None
        self.tx_min_graph = None

        self.rx_bytes = 0
        self.rx_sec_graph = None
        self.rx_min_graph = None

        ip = ipaddress.ip_address(ipaddr)
        self.global_ip = ip.is_global
        self.private_ip = ip.is_private
        self.multicast_ip = ip.is_multicast
        self.reserved_ip = ip.is_reserved
        self.ip_ver = 4 if isinstance(ip, ipaddress.IPv4Address) else 6
        del ip

        self.country = ''
        try:
            if self.ip_ver == 4:
                cmd = "which geoiplookup > /dev/null && geoiplookup "+ipaddr+" | awk '{print$4}'"
            else:
                cmd = "which geoiplookup6 > /dev/null && geoiplookup6 "+ipaddr+" | awk '{print$5}'"
            output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
            if output[2:4] == ',\n':   # if found, there is 'CC,\n'
                self.country = output[0:2]
        except:
            pass

    def inspect_packet_and_update(self, macaddr, pkt):
        tm = float(pkt[P_TIME])
        self.last_touch = tm

        # init when never seen before
        if not self.first_touch:
            self.first_touch = tm
            self.tx_sec_graph = GraphTimeLine(tm, 1)  # sec
            self.tx_min_graph = GraphTimeLine(tm, 60) # min
            self.rx_sec_graph = GraphTimeLine(tm, 1)
            self.rx_min_graph = GraphTimeLine(tm, 60)

        vol = int(pkt[P_FRAMELEN])
        if macaddr == pkt[P_ETHSRC]:
            self.tx_bytes += vol
            self.tx_sec_graph.update(tm, vol)
            self.tx_min_graph.update(tm, vol)
            self.tx_protocols.add(packet_protocol(pkt))
        else:
            self.rx_bytes += vol
            self.rx_sec_graph.update(tm, vol)
            self.rx_min_graph.update(tm, vol)

    def ip_statistics(self, now):
        return {'rx': self.rx_bytes,
                'tx': self.tx_bytes,
                'glob': self.global_ip,
                'priv': self.private_ip,
                'mult': self.multicast_ip,
                'rsrv': self.reserved_ip,
                'cntr': self.country,
                'fa': self.first_touch,
                'la': self.last_touch - now,
                'prot': self.tx_protocols
               }

    def tx_sec_graph_data(self, now):
        return self.tx_sec_graph.get_graph()

    def tx_min_graph_data(self, now):
        return self.tx_min_graph.get_graph()

    def rx_sec_graph_data(self, now):
        return self.rx_sec_graph.get_graph()

    def rx_min_graph_data(self, now):
        return self.rx_min_graph.get_graph()


# graph data
#
class GraphTimeLine():
    # zero values are not stored, only intervals (keys) with some traffic
    # (when new packet arrives, values are updated)
    def __init__(self, start, bar_len):
        self.gr = {}  # graph values {time:value}
        self.bar_len = bar_len  # seconds in one graph bar (1=sec, 60=min)
        self.first = self.interval(start)

    def interval(self, tm):
        return int(tm/self.bar_len)*self.bar_len

    def update(self, tm, value):
        # timeframe where the packet belongs to
        place = self.interval(tm)
        # update or create
        if place in self.gr.keys():
            self.gr[place] += value
        else:
            self.gr[place] = value

    def get_graph(self):
        dct = {'f': self.first, 'l': self.bar_len}
        dct.update(self.gr)
        return dct



#    #          ######
 #    #         #     # ######   ##   #####  ###### #####
  #    #        #     # #       #  #  #    # #      #    #
   #    #       ######  #####  #    # #    # #####  #    #
  #    #        #   #   #      ###### #    # #      #####
 #    #         #    #  #      #    # #    # #      #   #
#    #          #     # ###### #    # #####  ###### #    #


class PacketReader():
    """
    Reads from file or named pipe tab delimited plain text (output of tshark -T fields ....)
    There is queue between reader and packet processor (not to block pipe)
    Can simulate speed when reads from file: 0=immediately, 1=simulate realtime, 60=60x faster etc.
    """
    def __init__(self, read_from, inspector, replay=0, limit=float('inf'), write_to=None):

        self.worker = inspector         # packet processor object
        self.capture_limit = limit      # max number of packets to process
        self.wf = None                  # write file descriptor
        self.queue = deque()            # "thread-safe memory efficient queue"
        self.pkts_processed = 0
        self.first_pkt_time = 0
        self.last_pkt_time = 0
        self.last_cpu_time = 0
        self.performance = 0            # pkts per second (computing, not network traffic)
        self.is_running = False
        self.is_reading = False
        self.status = 0                 # 0-no errors, otherwise 1,2,3...
        self.speed = replay             # if from file, speed of replay

        self.reader_thread = threading.Thread(
                                target=self.stream_reader_daemon,
                                args=(read_from,),
                                daemon=True,
                                name='pipe_reader')
        self.queue_thread = threading.Thread(
                                target=self.queue_processor,
                                name='packet_processor')
        self.perfmon_thread = threading.Thread(
                                target=self.performance_monitor,
                                name='perf_monitor')

        if write_to:
            try:
                self.wf = open(write_to, 'w')
            except:
                self.status = 11

    def stream_reader_daemon(self, read_from):
        self.is_reading = True
        with open(read_from, 'r') as inputstream:
            # basic format check
            row = inputstream.readline() # header
            if self.wf:
                self.wf.write(row)
            pkt = row.split('\t')
            if len(pkt) != COLUMNS_EXPECTED:
                self.status = 1
                self.capture_limit = -1
            elif pkt[P_TIME] == 'frame.time_epoch':
                # read first packet and check format
                row = inputstream.readline()
                pkt = row.split('\t')
                try:
                    _ = int(pkt[P_FRAMELEN])
                    self.last_pkt_time = float(pkt[P_TIME])
                    self.first_pkt_time = float(pkt[P_TIME])
                except:
                    self.status = 2
                    self.capture_limit = -1
            else:
                self.status = 3
                self.capture_limit = -1
            # loop won't start if errors
            while row and self.pkts_processed < self.capture_limit:
                self.queue.append(row)
                row = inputstream.readline()
        self.is_reading = False

    def queue_processor(self):
        while self.is_running:
            while len(self.queue) > 0 and self.pkts_processed < self.capture_limit:
                row = self.queue.popleft()
                if self.wf:
                    self.wf.write(row)
                pkt = row.split('\t')
                # packet delay when simulating speed
                if self.speed > 0:
                    delay = (float(pkt[P_TIME]) - self.last_pkt_time)/self.speed
                    # interruptable sleep for long waits between packets
                    while delay > 3:
                        time.sleep(3)
                        delay -= 3
                        if not self.is_running:  # stop event
                            delay = 0
                    if delay > 0: time.sleep(delay)
                self.last_cpu_time = time.time()
                self.last_pkt_time = float(pkt[P_TIME])
                self.worker.process_packet(pkt)
                self.pkts_processed += 1
            time.sleep(0.2)
            # quit when limit is reached or nothing else will arrive into queue
            if (not self.is_reading and len(self.queue) == 0) \
                or (self.pkts_processed >= self.capture_limit):
                self.is_running = False

    def performance_monitor(self):
        while self.is_running:
            previous = self.pkts_processed
            time.sleep(1)
            self.performance = self.pkts_processed - previous
        self.performance = -1

    def start(self):
        if not self.status:
            self.is_running = True
            self.reader_thread.start()
            self.queue_thread.start()
            self.perfmon_thread.start()

    def stop(self):
        self.is_running = False
        self.capture_limit = -1
        if self.wf:
            time.sleep(0.1)
            self.wf.close()

    def get_statuses(self):
        tm = self.last_pkt_time
        if self.is_running:
            elapsed = time.time() - self.last_cpu_time
            tm += elapsed*self.speed if self.speed else elapsed
        return {'time': tm,
                'snc': self.first_pkt_time,
                'pkts': self.pkts_processed,
                'live': self.is_running,
                'ql': len(self.queue) if isinstance(self.queue, deque) else -1,
                'perf': self.performance,
                'err': self.status}
