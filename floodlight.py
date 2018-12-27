from ciscoconfparse import CiscoConfParse as CCP
import pyshark
import logging
import argparse
import os
import sys

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
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(log_format)
log.addHandler(handler)
logging.basicConfig(filename="floodlight.log", filemode="a+")

NXOS_CFG_PATH = "/startup-config"

def main():
    args = parse_arguments()
    if args.debug:
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
    
    capture = pyshark.LiveCapture()
    capture.sniff(timeout=args.capture_time)
    for packet in capture.sniff_continuously():
        log.info("Packet: {}".format(packet))

def parse_arguments():
    parser = argparse.ArgumentParser(description="Identifies unexpected control-plane traffic")

    # Optional arguments
    parser.add_argument("--debug", "-d", action="store_true", default=False, help="Enable debug logging levels")
    parser.add_argument("--capture-time", "-c", action="store", default="1", help="Amount of time (in minutes) to capture control-plane traffic for")

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    main()