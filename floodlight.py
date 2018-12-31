from ciscoconfparse import CiscoConfParse as CCP
import pyshark
import logging
import os
import sys
import time
import subprocess
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
log_format = logging.Formatter("%(asctime)-15s %(levelname)-8s [%(funcName)20s] %(message)s")
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
        parse = CCP(cfg_list)
    else:
        log.error("[SETUP] NX-OS startup-config file not detected!")
        sys.exit()
    
    if os.environ.get("CAPTURE_TIME") is not None:
        capture_time = int(os.environ.get("CAPTURE_TIME"))
    else:
        capture_time = 1
    
    filters = create_filters(parse)
    log.info("==== FILTERS ====")
    log.info("\n%s", pformat(filters))
    
    cap_timeout = 60 * capture_time
    log.info("[CAPTURE] Beginning packet capture, be back in %s seconds...", cap_timeout)
    tshark_cmd = "tshark -n -i eth1 -a duration:{} -w /tmp/floodlight.pcapng > /dev/null 2>&1".format(cap_timeout)
    subprocess.Popen(tshark_cmd, shell=True).wait()
    log.info("[CAPTURE] Packet capture finished!")
    capture = pyshark.FileCapture("/tmp/floodlight.pcapng")
    log.info("[CAPTURE] Number of packets in capture: %s", len(capture))
    unexpected_packets = [packet for idx, packet in enumerate(capture, 1) if not expected_packet(filters, packet, idx)]
    log.info("[UNEXPECTED] Number of unexpected packets: %s", len(unexpected_packets))
    for pkt in unexpected_packets:
        log.info("[UNEXPECTED] %s", summarize_packet(pkt))

def summarize_packet(pkt):
    try:
        l4_protocol = pkt.transport_layer
    except AttributeError:
        l4_protocol = "None"
    try:
        src_mac = pkt.eth.src
    except AttributeError:
        src_mac = "None"
    try:
        dst_mac = pkt.eth.dst
    except AttributeError:
        dst_mac = "None"
    try:
        src_ip = pkt.ip.src
    except AttributeError:
        src_ip = "None"
    try:
        dst_ip = pkt.ip.dst
    except AttributeError:
        dst_ip = "None"
    try:
        src_port = pkt.tcp.srcport
    except AttributeError:
        try:
            src_port = pkt.udp.srcport
        except AttributeError:
            src_port = "None"
    try:
        dst_port = pkt.tcp.dstport
    except AttributeError:
        try:
            dst_port = pkt.udp.dstport
        except AttributeError:
            dst_port = "None"
    try:
        app_protocol = pkt.highest_layer
    except AttributeError:
        app_protocol = "Unknown"
    return "{:5} ({:7}) {:17} {:15}:{:6} -> {:15}:{:6} {:17}".format(l4_protocol, app_protocol, src_mac, src_ip, src_port, dst_ip, dst_port, dst_mac)

def create_filters(parse):
    filters = {}
    filters["ip"] = []
    filters["mac"] = []
    filters["ip_protocol_type"] = []
    filters["protocols"] = []
    filters["ports"] = []
    #filter_ospf(parse, filters)
    #filter_eigrp(parse, filters)
    #filter_bgp(parse, filters)
    #filter_stp(parse, filters)
    #filter_hsrp(parse, filters)
    #filter_vrrp(parse, filters)
    #filter_ssh(parse, filters)
    return filters

def filter_ospf(parse, filters):
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
        log.info("[FILTER] EIGRP feature is not enabled, skipping...")
        return None

def filter_bgp(parse, filters):
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

def filter_stp(parse, filters):
    if parse.find_objects("^spanning-tree"):
        log.info("[FILTER] STP configuration found!")
        filters["mac"].append("0180.c200.0000")
        filters["protocols"].append("Spanning Tree Protocol")
    else:
        log.info("[FILTER] STP configuration not found, skipping...")
        return None

def filter_hsrp(parse, filters):
    if parse.find_objects("^feature hsrp"):
        log.debug("[FILTER] HSRP feature is enabled")
        hsrp_groups = parse.find_objects("hsrp \d+")
        if hsrp_groups:
            log.info("[FILTER] HSRP feature and configuration found!")
            for group_cfg in hsrp_groups:
                filters["mac"].append("0000.0c07.ac{:02x}".format(group_cfg.text.split()[-1]))
            filters["ip"].append("224.0.0.102")
            filters["protocols"].append("HSRP")
        else:
            log.warning("[FILTER] HSRP feature is enabled, but no configuration found!")
            return None
    else:
        log.info("[FILTER] HSRP configuration not found, skipping...")
        return None

def filter_vrrp(parse, filters):
    if parse.find_objects("^feature vrrp"):
        log.debug("[FILTER] HSRP feature is enabled")
        vrrp_groups = parse.find_objects("vrrp \d+")
        if vrrp_groups:
            log.info("[FILTER] VRRP feature and configuration found!")
            for group_cfg in vrrp_groups:
                filters["mac"].append("0000.5e00.01{:02x}".format(group_cfg.text.split()[-1]))
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
    # No need to detect configuration of SSH server, since 
    # it's on by default in NX-OS and is rarely disabled
    filters["ports"].append({"transport": "TCP", "port": "22"})
    filters["protocols"].append("SSH")

def expected_packet(filters, packet, idx):
    log.debug("[PKT-CHECK][%s] Checking packet...", idx)
    if (filtered_ip(filters["ip"], packet, idx) or 
            filtered_mac(filters["mac"], packet, idx) or 
            filtered_protocol_types(filters["ip_protocol_type"], packet, idx) or 
            filtered_ports(filters["ports"], packet, idx)):
        log.debug("[PKT-CHECK][%s] Packet is expected!", idx)
        return True
    else:
        log.debug("[PKT-CHECK][%s] Packet is ~NOT~ expected!", idx)
        return False

def filtered_ip(ips, packet, idx):
    log.debug("[PKT-CHECK-IP][%s] Checking for match against IP filters", idx)
    try:
        if (str(packet.ip.src) in ips) or (str(packet.ip.dst) in ips):
            log.debug("[PKT-CHECK-IP][%s] Match! Source IP: %s Destination IP: %s", idx, packet.ip.src, packet.ip.dst)
            return True
        else:
            log.debug("[PKT-CHECK-IP][%s] No match", idx)
            return False
    except AttributeError:
        log.debug("[PKT-CHECK-IP][%s] No IP header in packet", idx)
        return False

def filtered_mac(macs, packet, idx):
    log.debug("[PKT-CHECK-MAC][%s] Checking for match against MAC filters", idx)
    try:
        if (str(packet.eth.src) in macs) or (str(packet.eth.dst) in macs):
            log.debug("[PKT-CHECK-MAC][%s] Match! Source MAC: %s Destination MAC: %s", idx, packet.eth.src, packet.eth.dst)
            return True
        else:
            log.debug("[PKT-CHECK-MAC][%s] No match", idx)
            return False
    except AttributeError:
        log.debug("[PKT-CHECK-MAC][%s] No Ethernet header in packet", idx)
        return False

def filtered_protocol_types(types, packet, idx):
    log.debug("[PKT-CHECK-IP-PROTO][%s] Checking for match against IP protocol filters", idx)
    try:
        if packet.ip.proto in types:
            log.debug("[PKT-CHECK-IP-PROTO][%s] Match! Packet IP Protocol: %s", idx, packet.ip.proto)
            return True
        else:
            log.debug("[PKT-CHECK-IP-PROTO][%s] No match", idx)
            return False
    except AttributeError:
        log.debug("[PKT-CHECK-IP-PROTO][%s] No IP header in packet", idx)
        return False

def filtered_ports(ports, packet, idx):
    log.debug("[PKT-CHECK-L4-PORT][%s] Checking for match against L4 port filters", idx)
    packet_dict = {}
    try:
        if packet.tcp:
            packet_dict["transport"] = "TCP"
            packet_dict["port"] = packet.tcp.dstport
            log.debug("[PKT-CHECK-L4-PORT][%s] TCP packet detected, dict: %s", idx, packet_dict)
    except AttributeError:
        try:
            if packet.udp:
                packet_dict["transport"] = "UDP"
                packet_dict["port"] = packet.udp.dstport
                log.debug("[PKT-CHECK-L4-PORT][%s] UDP packet detected, dict: %s", idx, packet_dict)
        except AttributeError:
            log.debug("[PKT-CHECK-L4-PORT][%s] No L4 headers in packet", idx)
            return False
    if not packet_dict:
        return False
    if packet_dict in ports:
        log.debug("[PKT-CHECK-L4-PORT][%s] Match! Transport: %s Destination Port: %s", idx, packet_dict["protocol"], packet_dict["port"])
        return True
    else:
        log.debug("[PKT-CHECK-L4-PORT][%s] No match", idx)
        return False

if __name__ == "__main__":
    main()