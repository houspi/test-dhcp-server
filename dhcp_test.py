#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# test of DHCP server 
# by houspi@gmail.com
# TODO
#   get broadcast address from network environment
#   calc time working
#   ? validate cli parameters


import os
import sys
import argparse
import re
import socket
import struct
from uuid import getnode
from random import randint

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DEFAULT_DHCP_SERVER_ADDRESS = '255.255.255.255'
WAIT_TIMEOUT = 10

class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def buildPacket(self, mac_address):
        mac_bytes = b''
        for i in range(0, 12, 2) :
            mac_bytes += struct.pack('!B', int(mac_address[i:i + 2], 16))

        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID    #Transaction ID
        packet += b'\x00\x00'   #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #My (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        packet += mac_bytes             #Client MAC address
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'    #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67      #Server host name (empty)
        packet += b'\x00' * 125     #Boot file name (empty)
        packet += b'\x63\x82\x53\x63'       #Magic cookie: DHCP
        packet += b'\x35\x01\x01'           #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x3d\x06' + mac_bytes   #Option: (t=61,l=6) Client identifier
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet

class DHCPOffer:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        self.unpack()
    
    def unpack(self):
        if self.data[4:8] == self.transID :
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24])) 
            self.DHCPServerIdentifier = '.'.join(map(lambda x:str(x), data[245:249]))
            self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x:str(x), data[257:261]))
            self.subnetMask = '.'.join(map(lambda x:str(x), data[263:267]))
            dnsNB = int(data[268]/4)
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x:str(x), data[269 + i :269 + i + 4])))
                
    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address', 'subnet mask', 'lease time' , 'default gateway']
        val = [self.DHCPServerIdentifier, self.offerIP, self.subnetMask, self.leaseTime, self.router]
        for i in range(4):
            print('{0:18s} : {1:15s}'.format(key[i], val[i]))
        
        if self.DNS:
            print('{0:18s}'.format('DNS Servers') + ' : ', end='')
            print('{0:15s}'.format(self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)): 
                print('{0:18s} {1:15s}'.format(' ', self.DNS[i])) 

if __name__ == '__main__':
    if(os.geteuid() != 0) :
        exit('You must be root to run this program.')
    parser = argparse.ArgumentParser(description='Command line parameters')
    parser.add_argument('-m', action='store', dest='mac_address', help='MAC address. Default the MAC of this host')
    parser.add_argument('-s', action='store', dest='dhcp_server_address', help='DHCP Server address. Default %s'%DEFAULT_DHCP_SERVER_ADDRESS)
    args = parser.parse_args()
    if(args.mac_address) :
        my_mac_address = re.sub(':', '', args.mac_address)
    else :
        my_mac_address = str(hex(getnode()))[2:]
    if(args.dhcp_server_address) :
        dhcp_server_address = args.dhcp_server_address
    else :
        dhcp_server_address = DEFAULT_DHCP_SERVER_ADDRESS

    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    try:
        dhcps.bind(('', DHCP_CLIENT_PORT))
    except Exception as e:
        dhcps.close()
        exit('Can\'t bind dhcp client port %d '%DHCP_CLIENT_PORT)
 
    discoverPacket = DHCPDiscover()
    dhcps.sendto(discoverPacket.buildPacket(my_mac_address), (dhcp_server_address, DHCP_SERVER_PORT))
    print('DHCP Discover sent to %s\nwaiting for reply...'%dhcp_server_address)
    
    dhcps.settimeout(WAIT_TIMEOUT)
    try:
        while True:
            data = dhcps.recv(1024)
            offer = DHCPOffer(data, discoverPacket.transactionID)
            if offer.offerIP:
                offer.printOffer()
                break
    except socket.timeout as e:
        print(e)
    
    dhcps.close()
    exit(0)
