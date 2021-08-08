#!/usr/bin/env python3

'''
Based on original gist by drath (MIT license):
 https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c

When using Pihole for DNS without DHCP, the admin interface only displays
clients as IP addresses.

This utility sniffs for DHCP traffic (requests in particular), and records
IP address and corresponding hostnames in /etc/hosts.

For any unnamed devices, we attempt to profile the device using
fingerbank.org to generate some kind of meaningful simulated hostname.

Pihole will pick up the /etc/hosts names and display them in the UI.

- Requires fingerbank API key (https://api.fingerbank.org/users/register) in
  a secrets.py file.

- Requires libpcap to be installed (via tcpdump, for instance)

- Attempts to modify /etc/hosts, so needs to run as root

License: MIT.

Copyright (c) 2021 Dan Fielding

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

'''

import os
from scapy.all import *
from python_hosts import Hosts, HostsEntry
from shutil import copyfile
import sys
import urllib3
import requests
import json
import secrets
import datetime


'''
Global stuff
'''
 
interface = "eth0"
fingerbank_enabled = True
fingerbank_url = 'https://api.fingerbank.org/api/v2/combinations/interrogate'
confidence_threshold = 25
verbose = False
headers = {
    'Content-Type': 'application/json',
}

if fingerbank_enabled:
    params = (
        ('key', secrets.API_KEY),
    )


'''
Logging
'''

def log_fingerbank_error(e, response):
    print(f' HTTP error: {e}')
    responses = {
        404: "No device was found the the specified combination",
        502: "No API backend was able to process the request.",
        429: "The amount of requests per minute has been exceeded.",
        403: "This request is forbidden. Your account may have been blocked.",
        401: "This request is unauthorized. Either your key is invalid or wasn't specified."
    }
    print(responses.get(response.status_code, "Fingerbank API returned some unknown error"), flush=True)

def log_packet_info(packet):
    packet_type = ''
    types = {
        1: "DHCP Discover",
        2: "DHCP Offer",
        3: "DHCP Request",
        5: "DHCP Ack",
        8: "DHCP Inform"
    }
    if DHCP in packet:
        packet_type = types.get(packet[DHCP].options[0][1], "Some Other DHCP Packet")
    else:
        packet_type = "Unhandled"
    print('\n[{:%Y-%m-%d %H:%M:%S}]: {} - {}'.format(datetime.datetime.now(), packet.summary(), packet_type), flush=True)

def log_fingerbank_response(json_response):
    #print(json.dumps(json_response, indent=4))
    print(f"Device Profile: {json_response['device']['name']}, Confidence score: {json_response['score']}", flush=True)


# https://jcutrer.com/howto/dev/python/python-scapy-dhcp-packets
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass

def handle_dhcp_packet(packet):
    log_packet_info(packet)
    if DHCP in packet:
        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        if requested_addr is not None:
            hostname = get_option(packet[DHCP].options, 'hostname')
            param_req_list = get_option(packet[DHCP].options, 'param_req_list')
            vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')
            print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}", flush=True)
            # Only bother profiling the device if it doesn't have a name
            device_profile = None
            if hostname is None:
                device_profile = profile_device(param_req_list, packet[Ether].src, vendor_class_id)
            update_hosts_file(requested_addr, hostname, device_profile)

def profile_device(dhcp_fingerprint, macaddr, vendor_class_id):
    # Do nothing if fingerbank is disabled
    if fingerbank_enabled is False:
        return None
    if dhcp_fingerprint is None:
        return None
    data = {}
    data['dhcp_fingerprint'] = ','.join(map(str, dhcp_fingerprint))
    data['debug'] = 'on'
    data['mac'] = macaddr
    data['vendor_class_id'] = vendor_class_id
    if verbose:
        print(f"Will attempt to profile using {dhcp_fingerprint}, {macaddr}, and {vendor_class_id}", flush=True)

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(fingerbank_url, 
        headers=headers, 
        params=params, 
        data=json.dumps(data))
        log_fingerbank_response(response.json())
        # Filter out profiles that we have little confidence in
        if response.json()['score'] < confidence_threshold:
            return None
        return response.json()['device']['name']
    except requests.exceptions.HTTPError as err:
        log_fingerbank_error(err, response)
    except Exception as err:
        print(f"Error occurred: {err}", flush=True)

    return None

'''
Update the hosts file based on address, hostname, profile if required
'''

def update_hosts_file(address, hostname, profile):
    copyfile("/etc/hosts", "hosts")
    chosen_name = None
    if hostname is not None:
        chosen_name = hostname
    elif profile is not None:
        chosen_name = address + "-" + re.sub("[^A-Za-z0-9]", "_", profile)

    # TODO should we remove hosts entries, to avoid stale data?
    # Do we need to differentiate between low confidence data, no data and error?
    if chosen_name is not None:
        hosts = Hosts(path='hosts')
        hosts.remove_all_matching(address=address)
        new_entry = HostsEntry(entry_type='ipv4', address=address, names=[chosen_name])
        hosts.add([new_entry])
        hosts.write()
        copyfile("hosts", "/etc/hosts")

        if verbose:
            print(f"Updated hostsfile: {address} = {chosen_name}", flush=True)

print("Starting\n", flush=True)
# Require libpcap to use filtering
# Will sniff (and log) eeeeeeeverything otherwise, which is obviously not ideal
sniff(iface = interface, filter='udp and (port 67 or 68)', prn = handle_dhcp_packet, store = 0)
print("\n Shutting down...", flush=True)

'''
End of file
'''
