# Floodlight

[![](https://images.microbadger.com/badges/version/chrisjhart/floodlight.svg)](https://microbadger.com/images/chrisjhart/floodlight "Get your own version badge on microbadger.com")
[![](https://images.microbadger.com/badges/image/chrisjhart/floodlight.svg)](https://microbadger.com/images/chrisjhart/floodlight "Get your own image badge on microbadger.com")
![Docker Pulls](https://img.shields.io/docker/pulls/chrisjhart/floodlight.svg)
![Docker Stars](https://img.shields.io/docker/stars/chrisjhart/floodlight.svg)

Floodlight is a Dockerized Python application that identifies unexpected control plane traffic on Docker-capable Cisco Nexus data center switches and displays the top talkers of unexpected traffic. The startup configuration of the switch is analyzed to determine what traffic should be expected, and what traffic should not be expected.

## Usage

```
docker create \
--name=floodlight \
--net=host \
-e CAPTURE_TIME=<time-in-seconds>
-e EXPORT=/bootflash/pcap_filename.pcap \
-e DEBUG=<1/0>
-v /var/sysmgr/startup-cfg/ascii/system.cfg:/startup-config
-v /var/log/:/var/log/
-v /bootflash:/bootflash
chrisjhart/floodlight
```

If desired, the user may also utilize Docker Compose to use this application. The docker-compose.yml file in this repository may be used as a baseline. For more information about Docker Compose on Cisco NX-OS, refer to the Cisco documentation for [Installing Docker Compose in the NX-OS Bash Shell](https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/213961-install-docker-compose-in-nx-os-bash-she.html).

## Parameters

* `--net=host` - Shares Docker host networking with container, which is **required** in order for Floodlight to properly capture control plane traffic for analysis
* `-e CAPTURE_TIME=` - An integer representing the number of seconds that Floodlight should capture control plane traffic for analysis. If not defined, default is 60 seconds.
* `-e EXPORT=` - An absolute filepath that defines where a PCAP containing all unexpected traffic is to be stored. **In addition to setting this environmental variable, the directory must be mounted as a volume into the container in order for unexpected traffic to be exported.**
* `-e DEBUG=` - When set to `1`, enables debug logging in the `/var/log/floodlight.log` file. This should be used for troubleshooting - it is not recommended to enable this in a production environment.
* `-v /var/sysmgr/startup-cfg/ascii/system.cfg:/startup-config` - Mounts the Nexus device's startup configuration into the container to determine what control plane traffic is to be expected. If this file is not mounted, or Floodlight does not recognize the file as valid NX-OS configuration, then all control plane traffic will be considered unexpected.
* `-v /var/log:/var/log` - Allows logging to `/var/log/floodlight.log` on the Docker host. This is useful for debugging purposes and determining when the application was last executed.
* `-v /bootflash:/bootflash` - Mounts the bootflash directory of the Nexus device inside of the container to allow for a PCAP of unexpected traffic to be stored. **In addition to mounting this directory, the `EXPORT=` environmental variable must be set to an absolute filepath inside of the `bootflash` directory in order for unexpected traffic to be exported.**

## Identifying Expected Control Plane Traffic

Existing filters have been built for a small set of commonly-used protocols that can be used on Cisco Nexus data center switches; however, this list is not exhaustive by any means. If a protocol is in use in *your* environment that is not caught by an existing filter, refer to the Contributing section of this document to find out how the protocol can be added to this application.

The following list of control plane protocols are currently supported by Floodlight:

* **OSPF** - Open Shortest Path First
* **EIGRP** - Enhanced Interior Gateway Routing Protocol
* **BGP** - Border Gateway Protocol
* **Spanning Tree Protocol**
* **HSRP** - Hot Standby Router Protocol
* **VRRP** - Virtual Router Redundancy Protocol
* **SSH** - Secure SHell
* **vPC** - Virtual Port Channel peer-keepalive heartbeat
* **CDP** - Cisco Discovery Protocol
* **LLDP** - Link Layer Discovery Protocol

## Caveats

* Expected control plane traffic is determined through the device's startup configuration. If Floodlight reports a false positive (unexpected traffic that is actually expected) and the protocol is in the supported list above, ensure that the startup configuration of the device has recently been updated through the `copy running-config startup-config` command.

## Contributing

If you have identified an unsupported protocol that you would like to add a filter for, feel free to fork this project, add the necessary code, then open up a Pull Request. The maintainer(s) of this project will review the code, provide feedback if necessary, and merge the code accordingly.

If you have identified an unsupported protocol and would like support for it, but do not have experience with Python and cannot add it yourself, feel free to open up a GitHub Issue in this repository to ask for support. Alternatively, feel free to contact the maintainer(s) of this repository directly.

## License

This project is licensed under the terms of the Cisco Sample Code License. Please refer to the LICENSE.md file in this repository for more information, or view the license [here](https://developer.cisco.com/docs/licenses/#!cisco-sample-code-license/cisco-sample-code-license)