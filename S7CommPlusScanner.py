'''
File:   S7CommPlusScanner.py
Desc:   Sends S7CommPlus connection request. Siemens devices utilising said protocol (such as S7-1200 and S7-1500)
        will answer with connection response. The response contains hardware ID and firmware version, which are obtained and printed.
        Note that the connection is not finalised, as it would require authenticating to the PLC with additional packets with encryption.
        See 'The spear to break the security wall of S7CommPlus' by Lei et al. (2017) and 'Rogue7: Rogue Engineering-Station attacks on S7 Simatic PLCs' by Biham et al. (2019) for more information.
        Mofidied to be callable through Robot Framework.
Source: https://github.com/tijldeneut/ICSSecurityScripts/blob/master/FullSiemensScan.py
'''

__authors__ = "Aleksi Makinen and Tilj Deneut"
__copyright__ = "Copyright 2019, Aleksi Makinen"
__license__ = "GNU GPL v3"
__version__ = "2.0"
__status__ = "Development"

import sys, socket, re, string
import argparse
from binascii import hexlify, unhexlify
from robot.api.deco import keyword          # Modifying Robot Framework keyword call
from texttable import Texttable             # Printing result to table
from robot.api import logger 

@keyword(name='Run S7CommPlus scanner')
def run_scanner(targetIP, calledbyrobot = False):
    '''
    Handles sending and reception of the packets, and calls parsing and also logging when called through command-prompt.
    When called through Robot Framework, returns a dictionary containing the results of the scan.
    '''
    if not isIpv4(targetIP):
        logger.error('One or more addresses were wrong. \nPlease go read RFC 791 and then use a legitimate IPv4 address.')
        raise ValueError

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # 1 second timeout
    sock.connect((targetIP, 102)) ## Will setup TCP/SYN with port 102
    cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000000500c1020600c2020600c0010a'))
    if not cotpconnectresponse[10:12] == 'd0':
        if (calledbyrobot):
            logger.error("Did not get response to initial COTP connection request. No route to IP" + targetIP + "?")
        else:
            print('COTP Connection Request failed, no route to IP '+ targetIP +'?')
        return []

    data = '720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f3742363743433341a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a304a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000'
    tpktlength = str(hex((len(data)+14)/2))[2:] ## Dynamically find out the data length
    cotpdata = send_and_recv(sock, '030000'+tpktlength+'02f080'+data)
    ## It is sure that the CPU state is NOT in this response
    result = parse_results(targetIP, cotpdata)
    sock.close()
    if (calledbyrobot):
        return result
    else:
        log_results(result)

def send_and_recv(sock, strdata, sendOnly = False):
    '''
    Converts given packet from string to hex values, and sends them to through given socket.
    Optionally can also listen to response and return it.
    :param sock: Socket object through which packets are sent
    :param strdata: data to be sent as a string
    :param sendOnly: Optional boolean parameter, if true will also return response
    :returns: If enabled, returns the response as bytes
    '''
    data = unhexlify(strdata.replace(' ','').lower()) ## Convert to real HEX (\x00\x00 ...)
    sock.send(data)
    if sendOnly: return
    ret = sock.recv(65000)
    return ret

def parse_results(IP, data):
    '''
    Parses received message hexstring relevant fields into dictionary
    '''
    hardware = data.split(';')[-3]
    firmware = filter(lambda x: x in string.printable, data.split(';')[-2].replace('@','.'))
    return {"IP": IP, "hardware": hardware, "firmware": firmware}

@keyword(name='Log S7CommPlus scanner results')
def log_results(dataDict, calledbyrobot = False):
    ''' Prints a table with the given dictionary. '''
    t = Texttable()
    t.add_row(['Target IP', 'Hardware ID', 'Firmware version'])
    t.add_row([dataDict["IP"], dataDict["hardware"], dataDict["firmware"]])
    t.set_max_width(0)
    t.set_cols_dtype(["t", "t", "t"])
    if (calledbyrobot):
        logger.warn("\n" + t.draw())
    else:
        print(t.draw())

def isIpv4(ip):
    ''' Checks that given IP address complies to specification '''
    match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
    if not match:
        return False
    quad = []
    for number in match.groups():
        quad.append(int(number))
    if quad[0] < 1:
        return False
    for number in quad:
        if number > 255 or number < 0:
            return False
    return True

def main():
    ''' Handles arguments when called from command-prompt. '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', dest="targetIP", default=None, help="target device IP address")
    args = parser.parse_args()
    if args.targetIP == None:
        print("Missing target IP address.\nPlease use handle -i <IP> when calling this function.")
        sys.exit()
    else:
        IP = args.targetIP
    if not isIpv4(IP):
        print('One or more addresses were wrong. \nPlease go read RFC 791 and then use a legitimate IPv4 address.')
        sys.exit()
    run_scanner(IP)

if __name__ == "__main__":
    main()