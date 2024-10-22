#!/usr/bin/env python

"""
File:   profinetscanner.py
Desc:   Scan subnet and find profinet-enabled devices (PLC, HMI), PC workstations.
        Extract network info, names, roles.
Source: https://github.com/atimorin/scada-tools/blob/master/profinet_scanner.scapy.py
"""

__authors__ = "Aleksi Makinen and Aleksandr Timorin"
__copyright__ = "orig. Copyright 2013 Positive Technologies, Copyright 2019, Aleksi Makinen"
__license__ = "GNU GPL v3"
__version__ = "2.0"
__status__ = "Development"
'''
Credit goes also to Tijl Deneut's script:
https://github.com/tijldeneut/ICSSecurityScripts/blob/master/FullSiemensScan.py
Which implemented further parsing that was taken as reference when developing this script.
'''
import sys
import time
import threading
import string
import socket
import struct
import uuid
from binascii import hexlify, unhexlify
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import conf, sniff, srp, Ether, Dot1Q
import csv
import netifaces
import argparse
from texttable import Texttable             # Result printing
import binascii        
from robot.api import logger                # For Robot Framework prints
from robot.api.deco import keyword          # Modifying Robot Framework keyword call

cfg_dst_mac = '01:0e:cf:00:00:00' # Siemens family
cfg_sniff_time = 2 # seconds

sniffed_packets = None
args = None

def get_src_iface():
    ''' Returns the default network interface '''
    return conf.iface

def get_src_mac(interface):
    ''' Returns first MAC address found for given interface '''
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    except ValueError:
        print("Error: You must specify a valid interface name.")
        sys.exit(1)

def sniff_packets(src_iface):
    ''' Starts sniffing packets on given interface and saves them to global variable '''
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

    profinet_packet = None
    try:
        data = hexlify(data)
        # First 8 bytes are followed by the length of the rest of the message:
        PROFINET_DCPDataLength = int(data[20:24], 16) # Number of bytes after this value

        # Each block starts with 1 byte for device options and 1 byte for suboptions
        # afterwards follows 2 bytes for the length of the rest of the block

        # Collect the bounds to 2-dimensional list
        block_bounds = [[0] * 2 for i in range(7)]
        block_bounds[0][0] = 24
        for i in range (7):
            #print "Block start: ", block_bounds[i][0], "-", block_bounds[i][0]+4, " : ", data[block_bounds[i][0]: (block_bounds[i][0]+4)]
            #print "Length: ", data[(block_bounds[i][0] + 4) : (block_bounds[i][0] + 8)]
            block_bounds[i][1] = block_bounds[i][0] + 8 + int(data[(block_bounds[i][0] + 4) : (block_bounds[i][0] + 8)], 16)*2
            #print "Block End:", block_bounds[i][1]-4, "-", block_bounds[i][1], " : ", data[block_bounds[i][1]-4: block_bounds[i][1]]
            if (i < 6):
                # No odd bytes allowed, padding added for them
                if (block_bounds[i][1]/2) % 2 != 0:
                    block_bounds[i+1][0] = block_bounds[i][1] + 2
                else:
                    block_bounds[i+1][0] = block_bounds[i][1]
            # In some messages 'Device Instance' field was missing, the parsing must end if IP field (0x0102) is already reached
            if (i == 5):
                if (data[block_bounds[5][0]:(block_bounds[5][0] + 4)] == '0102'):
                    break
        #Device_options_block_length = int(data[28:32])
        # Get each block of message to their own dict entry based on bounds
        profinet_packet = {
            "Device_options":         data[block_bounds[0][0]:block_bounds[0][1]],
            "Device_specific":        data[block_bounds[1][0]:block_bounds[1][1]],
            "Device_nameofstation":   data[block_bounds[2][0]:block_bounds[2][1]],
            "Device_ID":              data[block_bounds[3][0]:block_bounds[3][1]],
            "Device_role":            data[block_bounds[4][0]:block_bounds[4][1]]
        }
        if (i == 5): # Device instance field was missing
            profinet_packet.update({"IP": data[block_bounds[5][0]:block_bounds[5][1]]})
        else:
            profinet_packet.update([("Device_instance", data[block_bounds[5][0]:block_bounds[5][1]]),
                                    ("IP",              data[block_bounds[6][0]:block_bounds[6][1]])])
        #print(profinet_packet)
        def get_block_length(key):
            return (int(profinet_packet[key][4:8], 16))*2
        
        type_of_station = unhexlify(profinet_packet["Device_specific"][8:8+get_block_length("Device_specific")]).strip("\0")
        #print(type_of_station)
        name_of_station = unhexlify(profinet_packet["Device_nameofstation"][8:8+get_block_length("Device_nameofstation")]).strip("\0")
        vendor_id = profinet_packet["Device_ID"][(8+4):(8+4+(get_block_length("Device_ID")-4)/2)]
        device_id = profinet_packet["Device_ID"][8+4+(get_block_length("Device_ID")-4)/2:8+(get_block_length("Device_ID"))]
        device_role = profinet_packet["Device_role"][12:12+get_block_length("Device_role")-6]
        
        # Get the normal representation for IP addresses
        def transform_to_address(address):
            return socket.inet_ntoa(struct.pack(">L", int(address, 16)))
        ip_address  = transform_to_address(profinet_packet["IP"][12:20])
        subnet_mask = transform_to_address(profinet_packet["IP"][20:28])
        standard_gateway = transform_to_address(profinet_packet["IP"][28:36])

    except:
        if (args != None):
            if args.verbose == True:
                print("Error occurred during the parsing of the received message:")
                print("%s:\n %s At line: %s" %(src, str(sys.exc_info()), str(sys.exc_info()[2].tb_lineno)))
                if (profinet_packet != None): print(profinet_packet)
    return type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway

def check_vendor_id(id):
    '''
    Compares the given vendor id against CSV-table with vendor names tied to id's.
    Returns the name as string on success, and otherwise an empty string.
    :param id: The vendor id as dec integer
    '''
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
        return ""
    except:
        print("Something went wrong when accessing vendorID table.")
        return ""

def check_device_type(device_id):
    '''
    Compares given device id to a dict of known id aliases.
    :param device_id: The hex-code as a string
    '''
    deviceType = {
        '0a01':     'Switch',
        '0202':     'PCSIM',
        '0203':     'S7-300 CP',
        '0101':     'S7-300',
        '010d':     'S7-1200',
        '0301':     'HMI',
        '010b':     'ET200S'
    }
    for key in deviceType:
        if key == device_id:
            return deviceType[key]
    return ""

def parse_device_role(device_role_code):
    '''
    Parses device role according to given binary representation
    :param device_role_code: The role code in hex
    '''
    devrole = 'Unknown role'
    try:
        binaryID = bin(int(device_role_code, 10))[2:]
        if int(binaryID) & 1 == 1: devrole = 'IO-Device '
        elif int(binaryID) & 10 == 10: devrole = 'IO-Controller '
        elif int(binaryID) & 100 == 100: devrole = 'IO-Multidevice '
        elif int(binaryID) & 1000 == 1000: devrole = 'PN-Supervisor '
        return devrole
    except:
        print("Encountered an error while trying to parse device role.")
        return devrole

def send_message(src_mac, cfg_dst_mac, src_iface):
    '''
    Creates and broadcasts PROFINET-DCP packet wrapped in Ethernet frame
    :param src_mac:         Sending interface MAC address
    :param cfg_dst_mac:     Target devices' MAC address
    :param src_iface:       Interface from which frame is sent
    '''
    
    payload =  'fefe 05 00 04010002 0080 0004 ffff 0000'
    payload = payload.replace(' ', '')
    payload = binascii.a2b_hex(payload)
    pp = Ether(type=0x8892, src=src_mac, dst=cfg_dst_mac)/payload
    if (args != None):
        if args.verbose == True:
            pp.show2()
    ans, unans = srp(pp, iface=src_iface)


def parse_results(src_mac):
    '''
    Checks that messagetype and sender match, and calls parser.
    Returns the results as dictionary with each separate response as its own key-dict pair.
    :param src_mac: Sending interface MAC address
    '''
    result = {}
    for p in sniffed_packets:
        if sys.version_info[0] >= 3:
            frametype = hex(p[Dot1Q].type).strip()
        else:
            frametype = hex(p.type)
        if frametype == '0x8892' and p.src != src_mac:
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
    return result

@keyword(name='Log PROFINET scan results')
def log_results(resultDict, calledByRobot = False):
    '''
    Logs the results to console
    :param resultDict: Dictionary containing dictionarys for each received correct message
    :param calledFromCommandPrompt: Bool, Used to signal the need to print with warning status (for robot). Default false.
    '''
    print("found {:d} devices".format(len(resultDict)))
    if len(resultDict) == 0: return
    t = Texttable()
    t.add_row(['mac address', 'type of station', 'name of station', 'vendor id', 'device id', 'device role', 'ip address', 'subnet mask', 'standard gateway'])
    for mac in resultDict.keys():
        p = resultDict[mac]
        if p['vendor_id']!= None:
            vendor = check_vendor_id(int(p['vendor_id'], 16))
            p['vendor_id'] = p['vendor_id'] + " (" + vendor + ")"
        if p['device_id'] != None:
            deviceID = check_device_type(p['device_id'])
            p['device_id'] = p['device_id'] + " (" + deviceID + ")"
        if p['device_role'] != None:
            p['device_role'] = p['device_role'] + " (" + parse_device_role(p['device_role']) + ")"
        t.add_row([mac, 
                p['type_of_station'], 
                p['name_of_station'], 
                p['vendor_id'],
                p['device_id'],
                p['device_role'],
                p['ip_address'],
                p['subnet_mask'],
                p['standard_gateway']])
        t.set_max_width(0)
        t.set_cols_dtype(["t", "t", "t", "t", "t", "t", "t", "t", "t"])
    if (calledByRobot):
        logger.warn("\n" + t.draw())
    else:
        print(t.draw())

@keyword(name='Run PROFINET scanner')
def run_profinet_scanner(src_iface):
    '''
    Used when called as python module (by Robot framework), runs the scanner, and returns results in dictionary
    :param src_iface: The source network interface, for example eth0
    '''
    src_mac = get_src_mac(src_iface)
     # run sniffer
    t = threading.Thread(target=sniff_packets, args=(src_iface,))
    t.setDaemon(True)
    t.start()
    
    # send the identity request message
    send_message(src_mac, cfg_dst_mac, src_iface)

    # wait sniffer...
    t.join()

    # parse results...
    result = parse_results(src_mac)

    return result

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest="src_iface", default="", help="source network interface")
    parser.add_argument('-v', dest="verbose", default="False", help="verbose mode")
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
    
    # send the identity request message
    send_message(src_mac, cfg_dst_mac, src_iface)

    # wait sniffer...
    t.join()

    # parse results...
    result = parse_results(src_mac)

    # ...and print them
    log_results(result)
      
