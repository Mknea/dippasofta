#!/usr/bin/env python

"""
Source: https://github.com/atimorin/scada-tools/blob/master/profinet_scanner.scapy.py
File: profinet_scanner.py
Desc: Scan subnet and find profinet-enabled devices (PLC, HMI), PC workstations.
      Extract network info, names, roles.
"""

__author__ = "Aleksandr Timorin"
__copyright__ = "Copyright 2013, Positive Technologies"
__license__ = "GNU GPL v3"
__version__ = "1.1"
__maintainer__ = "Aleksandr Timorin"
__email__ = "atimorin@gmail.com"
__status__ = "Development"

import sys
import time
import threading
import string
import socket
import struct
import uuid
from binascii import hexlify, unhexlify
from scapy.all import conf, sniff, srp, Ether
import csv
import netifaces
import argparse

cfg_dst_mac = '01:0e:cf:00:00:00' # Siemens family
cfg_sniff_time = 2 # seconds

sniffed_packets = None
args = None

def get_src_iface():
    return conf.iface

def get_src_mac(interface):
    # Returns first MAC address found for given ETHERNET interface
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    except ValueError:
        print("Error: You must specify a valid interface name.")
        sys.exit(1)

def sniff_packets(src_iface):
    global sniffed_packets
    sniffed_packets = sniff(iface=src_iface, filter='ether proto 0x8892', timeout=cfg_sniff_time)

def is_printable(data):
    printset = set(string.printable)
    return set(data).issubset(printset)

def parse_load(data, src):
    type_of_station = None
    name_of_station = None
    vendor_id = None
    device_id = None
    device_role = None
    ip_address = None
    subnet_mask = None
    standard_gateway = None
    try:
        data = hexlify(data)
        print(data)
        print(data[0:8])
        # First 8 bytes are followed by the length of the rest of the message:
        PROFINET_DCPDataLength = int(data[20:24], 16) # Number of bytes after this value

        # Each block starts with 1 byte for device options and 1 byte for suboptions
        # afterwards follows 2 bytes for the length of the rest of the block
        block_bounds = [[0] * 2 for i in range(7)]
        block_bounds[0][0] = 24
        print(block_bounds)
        print(data[28:32])
        print(int(data[28 : 32], 16))
        print(int(data[(block_bounds[0][0] + 4) : (block_bounds[0][0] + 8)], 16))
        print("block bounds: {0}".format(block_bounds[0][0] + 8 + int(data[(block_bounds[0][0] + 4) : (block_bounds[0][0] + 8)], 16)))
        for i in range (7):
            print("Block start: ", data[block_bounds[i][0]-4: block_bounds[i][0]])
            print("Length: ", data[(block_bounds[i][0] + 4) : (block_bounds[i][0] + 8)])
            block_bounds[i][1] = block_bounds[i][0] + 8 + int(data[(block_bounds[i][0] + 4) : (block_bounds[i][0] + 8)], 16)*2
            print("Block End:", data[block_bounds[i][1]-4: block_bounds[i][1]])
            if (i < 6):
                if block_bounds[i][1] % 2 != 0:
                    block_bounds[i+1][0] = block_bounds[i][1] + 5
                else:
                    block_bounds[i+1][0] = block_bounds[i][1] + 4
        print(block_bounds)

        Device_options_block_length = int(data[28:32])
        profinet_packet = {
            "Device_options_block": data[24:(24 + 6 + Device_options_block_length)],
            "Device_specific_block": None,
            "Device_nameofstation_block": None,
            "Device_ID_block": None,
            "Device_role_block": None,
            "Device_instance_block": None,
            "IP_block": None
        }
        #print(profinet_packet)
        #print(Device_options_block_length)
        #print(profinet_packet["Device_options_block"])


        PROFINET_DCPDataLength = int(data[20:24], 16)
        start_of_Block_Device_Options = 24
        Block_Device_Options_DCPBlockLength = int(data[start_of_Block_Device_Options + 2*2:start_of_Block_Device_Options + 4*2], 16)
        
        start_of_Block_Device_Specific = start_of_Block_Device_Options + Block_Device_Options_DCPBlockLength*2 + 4*2
        Block_Device_Specific_DCPBlockLength = int(data[start_of_Block_Device_Specific+2*2:start_of_Block_Device_Specific+4*2], 16)
        
        padding = Block_Device_Specific_DCPBlockLength%2
        
        start_of_Block_NameOfStation = start_of_Block_Device_Specific + Block_Device_Specific_DCPBlockLength*2 + (4+padding)*2
        Block_NameOfStation_DCPBlockLength = int(data[start_of_Block_NameOfStation+2*2:start_of_Block_NameOfStation+4*2], 16)
        
        padding = Block_NameOfStation_DCPBlockLength%2

        start_of_Block_Device_ID = start_of_Block_NameOfStation + Block_NameOfStation_DCPBlockLength*2 + (4+padding)*2
        Block_DeviceID_DCPBlockLength = int(data[start_of_Block_Device_ID+2*2:start_of_Block_Device_ID+4*2], 16)
        __tmp = data[start_of_Block_Device_ID+4*2:start_of_Block_Device_ID+4*2+Block_DeviceID_DCPBlockLength*2][4:]
        vendor_id, device_id = __tmp[:4], __tmp[4:]
        
        padding = Block_DeviceID_DCPBlockLength%2

        start_of_Block_DeviceRole = start_of_Block_Device_ID + Block_DeviceID_DCPBlockLength*2 + (4+padding)*2
        print("Start of devicerole block: ", data[start_of_Block_DeviceRole])
        Block_DeviceRole_DCPBlockLength = int(data[start_of_Block_DeviceRole+2*2:start_of_Block_DeviceRole+4*2], 16)
        device_role = data[start_of_Block_DeviceRole+4*2:start_of_Block_DeviceRole+4*2+Block_DeviceRole_DCPBlockLength*2][4:6]
        
        padding = Block_DeviceRole_DCPBlockLength%2

        start_of_Block_IPset = start_of_Block_DeviceRole + Block_DeviceRole_DCPBlockLength*2 + (4+padding)*2
        print("Start of IPset block: ", data[start_of_Block_IPset])
        Block_IPset_DCPBlockLength = int(data[start_of_Block_IPset+2*2:start_of_Block_IPset+4*2], 16)
        __tmp = data[start_of_Block_IPset+4*2:start_of_Block_IPset+4*2+Block_IPset_DCPBlockLength*2][4:]
        print("__tmp: " + __tmp)
        ip_address_hex, subnet_mask_hex, standard_gateway_hex = __tmp[:8], __tmp[8:16], __tmp[16:]
        ip_address = socket.inet_ntoa(struct.pack(">L", int(ip_address_hex, 16)))
        
        print("ip_address_hex: " + ip_address_hex + " subnet_mask_hex: " + subnet_mask_hex + " standard_gateway_hex: " + standard_gateway_hex)
        #subnet_mask = socket.inet_ntoa(struct.pack(">L", int(subnet_mask_hex, 16)))
        subnet_mask = None
        #standard_gateway = socket.inet_ntoa(struct.pack(">L", int(standard_gateway_hex, 16)))
        standard_gateway = None
        tos = data[start_of_Block_Device_Specific+4*2 : start_of_Block_Device_Specific+4*2+Block_Device_Specific_DCPBlockLength*2][4:]
        nos = data[start_of_Block_NameOfStation+4*2 : start_of_Block_NameOfStation+4*2+Block_NameOfStation_DCPBlockLength*2][4:]
        type_of_station = unhexlify(tos)
        name_of_station = unhexlify(nos)
        if not is_printable(type_of_station):
            type_of_station = 'not printable'
        if not is_printable(name_of_station):
            name_of_station = 'not printable'
    except:
        if args.verbose == True:
            print("%s:\n %s At line: %s" %(src, str(sys.exc_info()), str(sys.exc_info()[2].tb_lineno)))
    return type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway

#def create_packet_payload():
#    pass

def check_vendor_id(id):
    try:
        with open('vendor_ID_table.csv', mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                    if id < int(row["Vendor ID"]):
                        return ""
                    elif id == int(row["Vendor ID"]):
                        return row[" Vendor name"].strip()
    except EnvironmentError:
        print("VendorID table not provided.")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest="src_iface", default="", help="source network interface")
    parser.add_argument('-v', dest="verbose", default=False, help="verbose mode")
    args = parser.parse_args()
    if args.verbose.lower() == "true":
        args.verbose = True
    # Get the interface from user or use the first found interface
    src_iface = args.src_iface or get_src_iface()
    # Get MAC address for given interface
    src_mac = get_src_mac(src_iface)

    if (args.verbose == True):
        print("{0:20}: {1}\n{2:20}: {3}".format("Source interface", src_iface, "Source MAC", src_mac))

    # run sniffer
    t = threading.Thread(target=sniff_packets, args=(src_iface,))
    t.setDaemon(True)
    t.start()

    # create and send broadcast profinet packet
    payload =  'fefe 05 00 04010002 0080 0004 ffff '
    payload = payload.replace(' ', '')
    pp = Ether(type=0x8892, src=src_mac, dst=cfg_dst_mac)/payload.decode('hex')
    #pp.show2()
    ans, unans = srp(pp, iface=src_iface)

    # wait sniffer...
    t.join()
    # parse and print result
    result = {}
    for p in sniffed_packets:
        if hex(p.type) == '0x8892' and p.src != src_mac:
            result[p.src] = {'load': p.load}
            type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway = parse_load(p.load, p.src)
            result[p.src]['type_of_station'] = type_of_station
            result[p.src]['name_of_station'] = name_of_station
            result[p.src]['vendor_id'] = vendor_id
            result[p.src]['device_id'] = device_id
            result[p.src]['device_role'] = device_role
            result[p.src]['ip_address'] = ip_address
            result[p.src]['subnet_mask'] = subnet_mask
            result[p.src]['standard_gateway'] = standard_gateway

    print "found %d devices" % len(result)
    print "{0:17} : {1:15} : {2:15} : {3:20} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}".format('mac address', 'type of station', 
                                                                                              'name of station', 'vendor id', 
                                                                                              'device id', 'device role', 'ip address',
                                                                                              'subnet mask', 'standard gateway')
    for (mac, profinet_info) in result.items():
        p = result[mac]
        vendor = check_vendor_id(int(p['vendor_id'], 16))
        if vendor != "":
            p['vendor_id'] = p['vendor_id'] + " (" + vendor + ")"
        print "{0:17} : {1:15} : {2:15} : {3:20} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}".format(mac, 
                                                                                                p['type_of_station'], 
                                                                                                p['name_of_station'], 
                                                                                                p['vendor_id'],
                                                                                                p['device_id'],
                                                                                                p['device_role'],
                                                                                                p['ip_address'],
                                                                                                p['subnet_mask'],
                                                                                                p['standard_gateway'],
                                                                                                )

      
