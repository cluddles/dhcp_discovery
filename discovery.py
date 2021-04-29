#!/usr/bin/env python3

'''
Taken from code snippet by drath, modified slightly:
 https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c

Pihole is great, but the admin interface only displays device details 
by IP address which can be confusing. This script changes the display
from IP address to a more recognizable hostname. And as a bonus, attaches
the profile (from fingerbank.org) of the device to the hostname as well - 
so instead of something like 192.168.1.101, you see galaxys6-samsung. 
Shweet. 
Usage notes
- sudo python3.6 discovery.py
- Tested with python 3.6 only
- Requires fingerbank API key (https://api.fingerbank.org/users/register) in a secrets.py file.
- Displays log messages at appropriate times

License: MIT.
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
fingerbank_url = 'https://api.fingerbank.org/api/v2/combinations/interrogate'
confidence_threshold = 25
headers = {
    'Content-Type': 'application/json',
}

params = (
    ('key', secrets.API_KEY),
)

'''
Log message for troubleshooting
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
    print(responses.get(response.status_code, "Fingerbank API returned some unknown error"))
    return

def log_packet_info(packet):
    #print(packet.summary())
    #print(ls(packet))
    #print('---')
    #print('Packet:', packet.summary())
    print('\n--- {:%Y-%m-%d %H:%M:%S} ---'.format(datetime.datetime.now()))
    print('Packet:', packet.summary())
    types = {
        1: "DHCP Discover",
        2: "DHCP Offer",
        3: "DHCP Request",
        5: "DHCP Ack",
        8: "DHCP Inform"
    }
    if DHCP in packet:
        print(types.get(packet[DHCP].options[0][1], "Some Other DHCP Packet"))
    return

def log_fingerbank_response(json_response):
    #print(json.dumps(json_response, indent=4))
    print(f"Device Profile: {json_response['device']['name']}, Confidence score: {json_response['score']}")

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
        hostname = get_option(packet[DHCP].options, 'hostname')
        param_req_list = get_option(packet[DHCP].options, 'param_req_list')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')
        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}.")
        device_profile = profile_device(param_req_list, packet[Ether].src, vendor_class_id)
        if ((device_profile != -1) and requested_addr):
            update_hosts_file(requested_addr, hostname, device_profile)
    # Python why you hate flushing?
    sys.stdout.flush()
    return

def profile_device(dhcp_fingerprint, macaddr, vendor_class_id):
    if dhcp_fingerprint is None:
        return -1
    data = {}
    data['dhcp_fingerprint'] = ','.join(map(str, dhcp_fingerprint))
    data['debug'] = 'on'
    data['mac'] = macaddr
    data['vendor_class_id'] = vendor_class_id
    print(f"Will attempt to profile using {dhcp_fingerprint}, {macaddr}, and {vendor_class_id}")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(fingerbank_url, 
        headers=headers, 
        params=params, 
        data=json.dumps(data))
        log_fingerbank_response(response.json())
        # If score is less than 30, there is very little confidence on the returned profile. Ignore it.
        if (response.json()['score'] < confidence_threshold):
            print("Low confidence")
            return "unrecognised"
        return response.json()['device']['name']
    except requests.exceptions.HTTPError as err:
        log_fingerbank_error(err, response)
    except Exception as err:
        print(f"Error occurred: {err}")

    return -1

'''
Update the hosts file with <hostname>-<profile> for hostname
'''

def update_hosts_file(address, hostname, profile):
    if profile is not None:
        copyfile("/etc/hosts", "hosts")
        etchostname = profile.replace(" ", "_")
        if hostname:
            etchostname = etchostname + "-" + hostname
        elif address:
            etchostname = etchostname + "-" + address.replace(".", "_")
        print(f"Updating hostname as: {etchostname} with {address}")

        hosts = Hosts(path='hosts')
        hosts.remove_all_matching(name=etchostname)
        new_entry = HostsEntry(entry_type='ipv4', address=address, names=[etchostname])
        hosts.add([new_entry])
        hosts.write()
        copyfile("hosts", "/etc/hosts")

        print(f"Updated Host name for hostsfile is {etchostname}")

            
print("Starting\n", flush=True)
sniff(iface = interface, filter='udp and (port 67 or 68)', prn = handle_dhcp_packet, store = 0)
print("\n Shutting down...", flush=True)

'''
End of file
'''
