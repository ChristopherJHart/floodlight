from ciscoconfparse import CiscoConfParse as CCP
import logging
import os
import sys
import time
import subprocess
import re
import hashlib
from scapy.all import sniff, rdpcap, wrpcap
from operator import itemgetter
from pprint import pprint, pformat

__author__ = "Christopher Hart"
__email__ = "chart2@cisco.com"
__copyright__ = "Copyright (c) 2018 Cisco Systems. All rights reserved."
__credits__ = ["Christopher Hart",]
__license__ = """
################################################################################
# Copyright (c) 2018 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.0 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.
################################################################################
"""

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log_format = logging.Formatter("%(asctime)-15s %(levelname)-8s %(message)s")
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(log_format)
log.addHandler(stream_handler)
file_handler = logging.FileHandler("/var/log/floodlight.log", mode="a+")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_format)
log.addHandler(file_handler)

NXOS_CFG_PATH = "/startup-config"

def main():
    if os.environ.get("DEBUG") is not None:
        log.setLevel(logging.DEBUG)
        log.info("[LOG] Debug logging level set!")
    else:
        log.setLevel(logging.INFO)
        log.info("[LOG] Info logging level set!")
    
    if os.path.isfile(NXOS_CFG_PATH):
        log.info("[SETUP] NX-OS startup-config file detected")
        with open(NXOS_CFG_PATH) as cfgfile:
            cfg_list = cfgfile.readlines()
        filters = create_filters(CCP(cfg_list))
        log.info("==== FILTERS ====")
        log.info("\n%s", pformat(filters))
    else:
        log.error("[SETUP] NX-OS startup-config file not detected! Using empty filters...")
        filters = {}
    
    if os.environ.get("CAPTURE_TIME") is not None:
        capture_time = int(os.environ.get("CAPTURE_TIME"))
    else:
        capture_time = 1
    
    cap_timeout = 60 * capture_time
    log.info("[CAPTURE] Beginning packet capture, be back in %s seconds...", cap_timeout)
    tshark_cmd = "tshark -n -i eth1 -a duration:{} -w /tmp/floodlight.pcapng > /dev/null 2>&1".format(cap_timeout)
    subprocess.Popen(tshark_cmd, shell=True).wait()
    packets = rdpcap("/tmp/floodlight.pcapng")
    log.info("[CAPTURE] Packet capture finished! %s packets in capture", len(packets))
    if filters:
        unexpected_packets = [packet for idx, packet in enumerate(packets, 1) if not expected_packet(filters, packet, idx)]
    else:
        unexpected_packets = packets
    log.info("[UNEXPECTED] Number of unexpected packets: %s", len(unexpected_packets))
    unique_packets = {}
    for pkt in unexpected_packets:
        pkt_hash = get_packet_hash(pkt)
        log.debug("[PKT-HASH] Packet summary (%s) -> %s hash", summarize_packet(pkt), get_packet_hash(pkt))
        if pkt_hash in unique_packets.keys():
            unique_packets[pkt_hash]["flow_size"] += get_packet_length(pkt)
            unique_packets[pkt_hash]["pkts"].append(pkt)
        else:
            unique_packets[pkt_hash] = {"flow_size": get_packet_length(pkt), "pkts": [pkt]}
    unique_packet_list = unique_packets.values()
    sorted_list = sorted(unique_packet_list, key=itemgetter("flow_size"), reverse=True)
    log.info("{0!s: >15} RESULTS {0!s: <15}".format("="*5))
    for packet in sorted_list:
        log.info("%s bytes (%s packets) | %s", "{:,}".format(int(packet["flow_size"])), "{:,}".format(len(packet["pkts"])), summarize_packet(packet["pkts"][0]))
    if os.environ.get("EXPORT") is not None:
        wrpcap(os.environ.get("EXPORT"), unexpected_packets)
        log.info("[WRITE-PCAP] Successfully wrote unexpected packets to PCAP at %s", os.environ.get("EXPORT"))

def get_packet_length(pkt):
    try:
        return int(pkt["IP"].len)
    except IndexError:
        return 0

def get_packet_hash(pkt):
    """
    Returns a SHA256 hash of a summarized packet for the purpose of uniquely identifying a flow.

    Args:
        pkt: A pyshark.packet object that will be hashed
    
    Returns:
        String representing a SHA256 hash of the provided packet
    """
    return hashlib.sha256((bytes(summarize_packet(pkt).encode()))).hexdigest()

def summarize_packet(pkt):
    """
    Summarizes a packet into a human-legible string. Five key fields are represented
    in the summary - source/destination IP, source/destination MAC address, source/
    destination TCP/UDP port, and the transport protocol in use (such as TCP/UDP).
    If any of the five key fields are missing, they are replaced with the text
    "None".

    Args:
        pkt: A pyshark.packet object that will be summarized
    
    Returns:
        String representing the summary of a packet
    """
    try:
        l4_protocol = pkt[2].name
    except (AttributeError, IndexError):
        l4_protocol = "None"
    try:
        src_mac = pkt["Ethernet"].src
    except (AttributeError, IndexError):
        src_mac = "None"
    try:
        dst_mac = pkt["Ethernet"].dst
    except (AttributeError, IndexError):
        dst_mac = "None"
    try:
        src_ip = pkt["IP"].src
    except (AttributeError, IndexError):
        src_ip = "None"
    try:
        dst_ip = pkt["IP"].dst
    except (AttributeError, IndexError):
        dst_ip = "None"
    try:
        src_port = pkt[2].sport
    except (AttributeError, IndexError):
        src_port = "None"
    try:
        dst_port = pkt[2].dport
    except (AttributeError, IndexError):
        dst_port = "None"
    try:
        app_protocol = pkt.lastlayer().name
    except (AttributeError, IndexError):
        app_protocol = "Unknown"
    return "{!s: <5} ({!s: <7}) {!s: <17} {!s: >15}:{!s: <6} -> {!s: >15}:{!s: <6} {!s: <17}".format(l4_protocol, app_protocol, src_mac, src_ip, src_port, dst_ip, dst_port, dst_mac)

def create_filters(parse):
    """
    Creates filters representing control-plane traffic that the device
    should expect to receive based upon the startup configuration. These
    filters are dictionary of lists as follows:

    IP - A list of strings representing whitelisted IP addresses. If any
        of these IP addresses appear in the source or destination IP fields
        of a packet, the packet is expected.
    MAC - A list of strings representing whitelisted MAC addresses. If any
        of these MAC addresses appear in the source or destination MAC fields
        of a packet, the packet is expected.
    IP Protocol Type - A list of strings representing whitelisted IP protocol
        types. If any of these IP protocol types appear in the IP field of a 
        packet, the packet is expected. 
    Ports - A list of dictionaries representing whitelisted transport protocol
        ports. If any of these transport protocol and port combinations appear
        in the transport protocol field of a packet, the packet is expected.
        The defined port may be either the source or destination port.
    Complex - A list of dictionaries representing a complex filter. These
        filters are typically evaluated on a case-by-case basis by specific
        functions. Each dictionary SHOULD contain the "protocol" key, the
        value of which is a string representing a human-readable name of
        the expected protocol.
    Protocols - A list of strings representing protocol names. These are human-
        readable names of expected protocols, and are used to summarize the
        expected protocols that will be filtered.
    
    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
    
    Returns:
        A dictionary of lists with filters that will whitelist expected control-
        plane traffic.
    """
    filters = {}
    filters["ip"] = []
    filters["mac"] = []
    filters["ip_protocol_type"] = []
    filters["ports"] = []
    filters["complex"] = []
    filters["protocols"] = []
    filter_ospf(parse, filters)
    filter_eigrp(parse, filters)
    filter_bgp(parse, filters)
    filter_stp(parse, filters)
    filter_hsrp(parse, filters)
    filter_vrrp(parse, filters)
    filter_ssh(parse, filters)
    filter_vpc(parse, filters)
    filter_cdp(parse, filters)
    filter_lldp(parse, filters)
    return filters

def filter_ospf(parse, filters):
    """
    Detects the presence of the OSPF feature and configuration. If both are found,
    adds filter information to the filters argument that will whitelist OSPF
    control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If OSPF feature is not enabled, or if feature is enabled but no
        configuration is found, returns None.
    """
    if parse.find_objects("^feature ospf"):
        log.debug("[FILTER] OSPF feature is enabled")
        if parse.find_objects("^router ospf"):
            log.info("[FILTER] OSPF feature and configuration found!")
            filters["ip"] += ["224.0.0.5", "224.0.0.6"]
            filters["ip_protocol_type"].append("89")
            filters["protocols"].append("OSPF")
        else:
            log.warning("[FILTER] OSPF feature is enabled, but no configuration found!")
            return None
    else:
        log.info("[FILTER] OSPF feature is not enabled, skipping...")
        return None

def filter_eigrp(parse, filters):
    """
    Detects the presence of the EIGRP feature and configuration. If both are found,
    adds filter information to the filters argument that will whitelist EIGRP
    control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If EIGRP feature is not enabled, or if feature is enabled but no
        configuration is found, returns None.
    """
    if parse.find_objects("^feature eigrp"):
        log.debug("[FILTER] EIGRP feature is enabled")
        if parse.find_objects("^router eigrp"):
            log.info("[FILTER] EIGRP feature and configuration found!")
            filters["ip"].append("224.0.0.10")
            filters["ip_protocol_type"].append("88")
            filters["protocols"].append("EIGRP")
        else:
            log.warning("[FILTER] EIGRP feature is enabled, but no configuration found!")
            return None
    else:
        log.debug("[FILTER] EIGRP feature is not enabled, skipping...")
        return None

def filter_bgp(parse, filters):
    """
    Detects the presence of the BGP feature and configuration. If both are found,
    adds filter information to the filters argument that will whitelist BGP
    control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If BGP feature is not enabled, or if feature is enabled but no
        configuration is found, returns None.
    """
    if parse.find_objects("^feature bgp"):
        log.debug("[FILTER] BGP feature is enabled")
        if parse.find_objects("^router bgp"):
            log.info("[FILTER] BGP feature and configuration found!")
            filters["ports"].append({"transport": "TCP", "port": "179"})
            filters["protocols"].append("BGP")
        else:
            log.warning("[FILTER] BGP feature is enabled, but no configuration found!")
            return None
    else:
        log.info("[FILTER] BGP feature is not enabkled, skipping...")
        return None

def filter_stp(parse, filters):
    """
    Detects the presence of STP configuration. If found, adds filter information
    to the filters argument that will whitelist STP control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If STP configuration is not found, returns None.
    """
    if parse.find_objects("^spanning-tree"):
        log.info("[FILTER] STP configuration found!")
        filters["mac"].append("01:80:c2:00:00:00")
        filters["protocols"].append("Spanning Tree Protocol")
    else:
        log.info("[FILTER] STP configuration not found, skipping...")
        return None

def filter_hsrp(parse, filters):
    """
    Detects the presence of the HSRP feature and configuration. If both are found,
    adds filter information to the filters argument that will whitelist HSRP
    control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If HSRP feature is not enabled, or if feature is enabled but no
        configuration is found, returns None.
    """
    if parse.find_objects("^feature hsrp"):
        log.debug("[FILTER] HSRP feature is enabled")
        hsrp_groups = parse.find_objects(r"hsrp \d+")
        if hsrp_groups:
            log.info("[FILTER] HSRP feature and configuration found!")
            for group_cfg in hsrp_groups:
                filters["mac"].append("00:00:0c:07:ac:{:02x}".format(group_cfg.text.split()[-1]))
            filters["ip"].append("224.0.0.102")
            filters["protocols"].append("HSRP")
        else:
            log.warning("[FILTER] HSRP feature is enabled, but no configuration found!")
            return None
    else:
        log.info("[FILTER] HSRP configuration not found, skipping...")
        return None

def filter_vrrp(parse, filters):
    """
    Detects the presence of the VRRP feature and configuration. If both are found,
    adds filter information to the filters argument that will whitelist VRRP
    control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If VRRP feature is not enabled, or if feature is enabled but no
        configuration is found, returns None.
    """
    if parse.find_objects("^feature vrrp"):
        log.debug("[FILTER] HSRP feature is enabled")
        vrrp_groups = parse.find_objects("vrrp \d+")
        if vrrp_groups:
            log.info("[FILTER] VRRP feature and configuration found!")
            for group_cfg in vrrp_groups:
                filters["mac"].append("00:00:5e:00:01:{:02x}".format(group_cfg.text.split()[-1]))
            filters["ip"].append("224.0.0.18")
            filters["ip_protocol_type"].append("112")
            filters["protocols"].append("VRRP")
        else:
            log.warning("[FILTER] VRRP feature is enabled, but no configuration found!")
            return None
    else:
        log.info("[FILTER] VRRP configuration not found, skipping...")
        return None

def filter_ssh(parse, filters):
    """
    Adds filter information to the filters argument that will whitelist SSH
    control-plane traffic. Note that because the SSH feature is on by default
    and is very, *very* rarely disabled, we do not attempt to detect SSH
    server configuration.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    """
    filters["ports"].append({"transport": "TCP", "port": "22"})
    filters["protocols"].append("SSH")

def filter_vpc(parse, filters):
    """
    Detects the presence of the vPC feature and configuration. If both are found,
    adds filter information to the filters argument that will whitelist vPC
    control-plane traffic. A complex filter is utilized to whitelist vPC
    control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If vPC feature is not enabled, or if feature is enabled but no
        configuration is found, returns None.
    """
    if parse.find_objects("^feature vpc"):
        log.debug("[FILTER] vPC feature is enabled")
        vpc_pka = parse.find_objects("peer-keepalive destination")
        if vpc_pka:
            log.info("[FILTER] vPC feature and peer-keepalive configuration found!")
            for cfg in vpc_pka:
                new_filter = {}
                new_filter["protocol"] = "vPC"
                new_filter["dst_ip"] = re.search(r"destination (\S+)", cfg.text).group(1)
                res = re.search(r"source (\S+)", cfg.text)
                if res:
                    new_filter["src_ip"] = res.group(1)
                new_filter["src_port"] = "3200"
                new_filter["dst_port"] = "3200"
                new_filter["transport"] = "UDP"
                filters["complex"].append(new_filter)
        else:
            log.warning("[FILTER] vPC feature is enabled, but no vPC peer-keepalive configuration found!")
            return None
    else:
        log.info("[FILTER] vPC configuration not found, skipping...")
        return None

def filter_cdp(parse, filters):
    """
    Detects the presence of CDP configuration. If configuration is not found,
    adds filter information to the filters argument that will whitelist CDP
    control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If CDP configuration is found, returns None.
    """
    if not parse.find_objects("^no cdp enable"):
        log.info("[FILTER] CDP feature is enabled!")
        filters["mac"].append("01:00:0c:cc:cc:cc")
        filters["protocols"].append("CDP")
    else:
        log.info("[FILTER] CDP is disabled, skipping...")
        return None

def filter_lldp(parse, filters):
    """
    Detects the presence of the LLDP feature. If found, adds filter information
    to the filters argument that will whitelist LLDP control-plane traffic.

    Args:
        parse: a ciscoconfparse.CiscoConfParse object representing the device's
               startup configuration.
        filters: A dictionary of lists with filters that will whitelist expected
                 control-plane traffic.
    
    Returns:
        If LLDP feature is not enabled, returns None.
    """
    if parse.find_objects("^feature lldp"):
        log.info("[FILTER] LLDP feature is enabled")
        filters["mac"].append("01:80:c2:00:00:0e")
        filters["protocols"].append("LLDP")
    else:
        log.info("[FILTER] LLDP is disabled, skipping...")
        return None

def expected_packet(filters, packet, idx):
    log.debug("[PKT-CHECK][%s] Checking packet...", idx)
    if (filtered_ip(filters["ip"], packet, idx) or 
            filtered_mac(filters["mac"], packet, idx) or 
            filtered_protocol_types(filters["ip_protocol_type"], packet, idx) or 
            filtered_ports(filters["ports"], packet, idx)):
        log.debug("[PKT-CHECK][%s] Packet is expected!", idx)
        return True
    if "complex" in filters.keys():
        for complex_filter in filters["complex"]:
            if "vPC" in complex_filter["protocol"]:
                if filtered_vpc(complex_filter, packet, idx):
                    return True
    else:
        log.debug("[PKT-CHECK][%s] Packet is ~NOT~ expected!", idx)
        return False

def filtered_ip(ips, packet, idx):
    log.debug("[PKT-CHECK-IP][%s] Checking for match against IP filters", idx)
    try:
        if (str(packet["IP"].src) in ips) or (str(packet["IP"].dst) in ips):
            log.debug("[PKT-CHECK-IP][%s] Match! Source IP: %s Destination IP: %s", idx, packet["IP"].src, packet["IP"].dst)
            return True
        else:
            log.debug("[PKT-CHECK-IP][%s] No match", idx)
            return False
    except (AttributeError, IndexError):
        log.debug("[PKT-CHECK-IP][%s] No IP header in packet", idx)
        return False

def filtered_mac(macs, packet, idx):
    log.debug("[PKT-CHECK-MAC][%s] Checking for match against MAC filters", idx)
    try:
        if (packet["Ethernet"].src in macs) or (packet["Ethernet"].dst in macs):
            log.debug("[PKT-CHECK-MAC][%s] Match! Source MAC: %s Destination MAC: %s", idx, packet["Ethernet"].src, packet["Ethernet"].dst)
            return True
        else:
            log.debug("[PKT-CHECK-MAC][%s] No match", idx)
            return False
    except (AttributeError, IndexError):
        log.debug("[PKT-CHECK-MAC][%s] No Ethernet header in packet", idx)
        return False

def filtered_protocol_types(types, packet, idx):
    log.debug("[PKT-CHECK-IP-PROTO][%s] Checking for match against IP protocol filters", idx)
    try:
        if str(packet["IP"].proto) in types:
            log.debug("[PKT-CHECK-IP-PROTO][%s] Match! Packet IP Protocol: %s", idx, packet["IP"].proto)
            return True
        else:
            log.debug("[PKT-CHECK-IP-PROTO][%s] No match", idx)
            return False
    except (AttributeError, IndexError):
        log.debug("[PKT-CHECK-IP-PROTO][%s] No IP header in packet", idx)
        return False

def filtered_ports(ports, packet, idx):
    log.debug("[PKT-CHECK-L4-PORT][%s] Checking for match against L4 port filters", idx)
    try:
        packet_dict_src = {"transport": packet[2].name, "port": packet[2].sport}
        packet_dict_dst = {"transport": packet[2].name, "port": packet[2].dport}
        log.debug("[PKT-CHECK-L4-PORT][%s] TCP packet detected, source: %s dst: %s", idx, packet_dict_src, packet_dict_dst)
    except (AttributeError, IndexError):
        log.debug("[PKT-CHECK-L4-PORT][%s] No L4 headers in packet", idx)
        return False
    if packet_dict_src in ports:
        log.debug("[PKT-CHECK-L4-PORT][%s] Match! Transport: %s Source Port: %s", idx, packet_dict_src["transport"], packet_dict_src["port"])
        return True
    elif packet_dict_dst in ports:
        log.debug("[PKT-CHECK-L4-PORT][%s] Match! Transport: %s Destination Port: %s", idx, packet_dict_dst["transport"], packet_dict_dst["port"])
        return True
    else:
        log.debug("[PKT-CHECK-L4-PORT][%s] No match", idx)
        return False

def filtered_vpc(vpc_filter, packet, idx):
    log.debug("[PKT-CHECK-VPC][%s] Checking for match against vPC filter", idx)
    try:
        if (((vpc_filter["src_ip"] in packet["IP"].src) or (vpc_filter["src_ip"] in packet["IP"].dst)) and
            ((vpc_filter["dst_ip"] in packet["IP"].src) or (vpc_filter["dst_ip"] in packet["IP"].dst)) and
            (vpc_filter["transport"] in packet[2].name) and
            (vpc_filter["src_port"] in str(packet[2].sport)) and
            (vpc_filter["dst_port"] in str(packet[2].dport))):
            log.debug("[PKT-CHECK-VPC][%s] Match! vPC Source: %s vPC Destination: %s", idx, vpc_filter["src_ip"], vpc_filter["dst_ip"])
            return True
        else:
            log.debug("[PKT-CHECK-VPC][%s] No match", idx)
            return False
    except (AttributeError, TypeError, IndexError) as exc:
        log.debug("[PKT-CHECK-VPC][%s] Necessary headers are missing: %s", idx, exc)
        return False


if __name__ == "__main__":
    main()