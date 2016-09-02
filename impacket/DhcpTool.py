# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#


import pcapy
import socket
import time
from random import randint

from impacket import structure
from impacket.ImpactDecoder import EthDecoder
from impacket.dhcp import DhcpPacket


class DHCPTool:
    def initialize(self):
        self.pcap = pcapy.open_live(pcapy.lookupdev(), -1, 1, 1)
        self.pcap.setfilter("port 67", 1, 0xffffff00)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect(('192.168.1.1',67))
        self.decoder = EthDecoder()

    def targetRun(self):
        for i in range(1,254):
            self.sendDISCOVER('12345%c' % i, ip = '192.168.1.%d' % i)
            self.processPacketsForOneSecond()

    def finalize(self):
        self.pcap.close()
        Module.finalize(self)

    def processPacketsForOneSecond(self):
        t = time.time()
        while time.time()-t < 1:
            p = self.pcap.next()
            if p[1][2]:
                pp = self.decoder.decode(p[0])
                print pp

    def sendDHCP(self, type, chaddr, hostname = None, ip = None, xid = None,opts = []):
        p = DhcpPacket()

        opt = [('message-type',type)] + list(opts)

        if xid is None:
            xid = randint(0,0xffffffff)
        if ip:
            ip = structure.unpack('!L',socket.inet_aton(ip))[0]
            p['ciaddr'] = ip
            opt.append(('requested-ip',ip))

        if hostname is not None:
            for i in range(0,len(hostname),255):
                opt.append(('host-name',hostname[i:i+255]))

        p['op']     = p.BOOTREQUEST
        p['xid']    = xid
        p['chaddr'] = chaddr
        p['cookie'] = 0x63825363
        p['options'] = opt

        self.sock.send(str(p))

    def sendDISCOVER(self, chaddr, hostname = None, ip = None,xid = 0x12345678):
        print 'DHCPDISCOVER: %s' % ip
        self.sendDHCP(DhcpPacket.DHCPDISCOVER, chaddr, hostname, ip, xid)
