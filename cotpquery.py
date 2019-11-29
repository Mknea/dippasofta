'''
File:   COTPRequest.py
Desc:   
Source: https://github.com/tijldeneut/ICSSecurityScripts/blob/master/FullSiemensScan.py
'''
import sys, socket, re, string
import argparse
from binascii import hexlify, unhexlify
from robot.api.deco import keyword          # Modifying Robot Framework keyword call
from texttable import Texttable             # Printing result to table

def getInfoViaCOTP(targetIP):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # 1 second timeout
    sock.connect((targetIP, 102)) ## Will setup TCP/SYN with port 102
    cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000000500c1020600c2020600c0010a'))
    if not cotpconnectresponse[10:12] == 'd0':
        print('COTP Connection Request failed, no route to IP '+ targetIP +'?')
        return []

    data = '720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f3742363743433341a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a304a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000'
    tpktlength = str(hex((len(data)+14)/2))[2:] ## Dynamically find out the data length
    cotpdata = send_and_recv(sock, '030000'+tpktlength+'02f080'+data)
    #print(cotpdata)
    ## It is sure that the CPU state is NOT in this response
    parse_and_log_results(cotpdata)
    sock.close()

def send_and_recv(sock, strdata, sendOnly = False):
    data = unhexlify(strdata.replace(' ','').lower()) ## Convert to real HEX (\x00\x00 ...)
    sock.send(data)
    if sendOnly: return
    ret = sock.recv(65000)
    return ret

def parse_and_log_results(data):
    t = Texttable()
    t.add_row(['Hardware ID', 'Firmware version'])
    hardware = data.split(';')[2]
    firmware = filter(lambda x: x in string.printable, data.split(';')[3].replace('@','.'))
    t.add_row([hardware, firmware])
    t.set_max_width(0)
    t.set_cols_dtype(["t", "t"])
    print(t.draw())

def isIpv4(ip):
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

@keyword(name='Send COTP query')
def main(IP = ""):
    if IP == "":
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
    
    getInfoViaCOTP(IP)

if __name__ == "__main__":
    main()