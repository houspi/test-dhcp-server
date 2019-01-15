#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# send a DHCP request to DHCP server to see if it's up and running
# by houspi@gmail.com
# TODO
#   get broadcast address from the network environment
#   ? validate cli parameters

import os
import sys
import argparse
from time import time
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
    def __init__(self):
        self.data = b''
        self.transID = b''
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        
    def setData(self, data, transID):
        self.data = data
        self.transID = transID
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.transID :
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24])) 
            self.DHCPServerIdentifier = '.'.join(map(lambda x:str(x), data[245:249]))
            self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
            self.subnetMask = '.'.join(map(lambda x:str(x), data[257:261]))
            self.router = '.'.join(map(lambda x:str(x), data[263:267]))
            dnsNB = int(data[268]/4)
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x:str(x), data[269 + i :269 + i + 4])))
                
    def printOffer(self):
        keys = ['DHCP Server', 'Offered IP address', 'default router', 'lease time' , 'subnet mask']
        vals = [self.DHCPServerIdentifier, self.offerIP, self.router, self.leaseTime, self.subnetMask]
        for i in range(len(keys)):
            print('{0:18s} : {1:15s}'.format(keys[i], vals[i]))
        
        if self.DNS:
            print('{0:18s} : {1:15s}'.format('DNS Servers', self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)): 
                print('{0:18s} {1:15s}'.format(' ', self.DNS[i])) 

if __name__ == '__main__':
    if(os.geteuid() != 0) :
        exit('You must be root to run this program.')
    parser = argparse.ArgumentParser(description='send a DHCP request to DHCP server to see if it\'s up and running')
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

    start_time = time()
    dhcp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcp_client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    dhcp_client.settimeout(WAIT_TIMEOUT)
    
    try:
        dhcp_client.bind(('', DHCP_CLIENT_PORT))
    except Exception as e:
        dhcp_client.close()
        exit('Can\'t bind dhcp client port %d '%DHCP_CLIENT_PORT)
 
    discoverPacket = DHCPDiscover()
    dhcp_client.sendto(discoverPacket.buildPacket(my_mac_address), (dhcp_server_address, DHCP_SERVER_PORT))
    print('DHCP Discover sent to %s\nwaiting for reply...'%dhcp_server_address)
    
    offer = DHCPOffer()    
    try:
        while True:
            data = dhcp_client.recv(2048)
            offer.setData(data, discoverPacket.transactionID)
            if offer.offerIP:
                break
    except socket.timeout as e:
        print(e)
    
    dhcp_client.close()
    end_time = time()
    offer.printOffer()
    print('{0:18s} : {1:8f}'.format( 'Requets time', end_time-start_time ))
    exit(0)
