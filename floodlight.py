from ciscoconfparse import CiscoConfParse as CCP
import pyshark
import logging
import os
import sys
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
    log.info("\n{}".format(pformat(filters)))
    
    capture = pyshark.LiveCapture("eth1")
    cap_timeout = 60 * capture_time
    log.info("[CAPTURE] Beginning packet capture, be back in {} seconds...".format(cap_timeout))
    capture.sniff(timeout=cap_timeout)
    log.info("[CAPTURE] Packet capture finished! Number of packets: {}".format(len(capture)))
    for index, packet in enumerate(capture):
        print("Checking packet {}".format(index))
        try:
            #print("Contents: {} Type: {}".format(packet.ip.src, type(packet.ip.src)))
            #print("Contents: {} Type: {}".format(packet.eth.src, type(packet.eth.src)))
            print("Contents: {} Type: {}".format(packet.tcp, type(packet.tcp)))
            print("Dir: {}".format(dir(packet.tcp)))
            #print("Contents: {} Type: {}".format(packet.ip.proto, type(packet.ip.proto)))
            sys.exit()
        except AttributeError:
            continue

    unexpected_packets = [packet for packet in capture if not expected_packet(filters, packet)]
    print("[UNEXPECTED] Number of unexpected packets: {}".format(len(unexpected_packets)))

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

def expected_packet(filters, packet):
    if (filtered_ip(filters["ip"], packet) or filtered_mac(filters["mac"], packet) or filtered_protocol_types(filters["ip_protocol_types"], packet) or filtered_ports(filters["ports"], packet)):
        return True
    else:
        return False

def filtered_ip(ips, packet):
    if (str(packet.ip.src) in ips) or (str(packet.ip.dst) in ips):
        log.debug("[PACKET-IP] Source IP: {} Destination IP: {}".format(packet.ip.src, packet.ip.dst))
        return True
    else:
        return False

def filtered_mac(macs, packet):
    if (str(packet.eth.src) in macs) or (str(packet.eth.dst) in macs):
        log.debug("[PACKET-MAC] Source MAC: {} Destination MAC: {}".format(packet.eth.src, packet.eth.dst))
        return True
    else:
        return False

def filtered_protocol_types(types, packet):
    if packet.ip.proto in types:
        log.debug("[PACKET-PROTO] Packet IP Protocol: {}".format(packet.ip.proto))
        return True
    else:
        return False

def filtered_ports(ports, packet):
    packet_dict = {}
    try:
        if packet.tcp:
            packet_dict["transport"] = "TCP"
            packet_dict["port"] = packet.tcp.dst
    except AttributeError:
        try:
            if packet.udp:
                packet_dict["transport"] = "UDP"
                packet_dict["port"] = packet.udp.dst
        except AttributeError:
            return False
    if packet_dict in ports:
        log.debug("[PACKET-PORTS] Transport: {} Destination Port: {}".format(packet_dict["protocol"], packet_dict["port"]))
        return True
    else:
        return False

if __name__ == "__main__":
    main()