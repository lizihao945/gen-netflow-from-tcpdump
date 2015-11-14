#!/usr/bin/python
#! -*- encoding: utf-8 -*-

import socket, struct
from socket import inet_ntoa

# Byte Order: (!) network (= big-endian)
# C Type:
# (H) unsigned short, 2 bytes
# (I) unsigned int, 4 bytes

# NetFlow Format
# http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html

# NetFlow Header Record
versionINR = slice(0, 2), '!H'
countINR = slice(2, 4), '!H'
SysUptimeINR = slice(4, 8), '!I'
unix_secsINR = slice(8, 12), '!I'
unix_nsecsINR = slice(12, 16), '!I'
flow_sequenceINR = slice(16, 20), '!I'
engine_typeINR = slice(20, 21), '!B'
engine_idINR = slice(21, 22), '!B'
sampling_intervalINR = slice(22, 24), '!H'

# NetFlow Record Format
srcaddrINR = slice(0, 4), '!I'
dstaddrINR = slice(4, 8), '!I'
nexthopINR = slice(8, 12), '!I'
inputINR = slice(12, 14), '!H'
outputINR = slice(14, 16), '!H'
dPktsINR = slice(16, 20), '!I'
dOctetsINR = slice(20, 24), '!I'
FirstINR = slice(24, 28), '!I'
LastINR = slice(28, 32), '!I'
srcportINR = slice(32, 34), '!H'
dstportINR = slice(34, 36), '!H'
pad1INR = slice(36, 37), '!B'
tcp_flagsINR = slice(37, 38)
protINR = slice(38, 39), '!B'
tosINR = slice(39, 40), '!B'
src_asINR = slice(40, 42), '!H'
dst_asINR = slice(42, 44), '!H'
src_maskINR = slice(44, 45), '!B'
dst_maskINR = slice(45, 46), '!B'
pad2INR = slice(46, 48), '!H'

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

class NetFlowParser:
    def __init__(self):
        self.setup()
        self.parse()

    def setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 41300))
        self.byteSize = 1500

    def parse(self):
        while True:
            byteData, addr = self.sock.recvfrom(self.byteSize)

            # Parse Header
            nfHeader = {}
            nfHeader['version'] = struct.unpack(versionINR[1], byteData[versionINR[0]])[0]
            nfHeader['count'] = struct.unpack(countINR[1], byteData[countINR[0]])[0]
            # version, count = struct.unpack('!HH', byteData[0:4])
            if nfHeader['version'] != 5:
                print "Not NetFlow v5!"
                continue

            # It's pretty unlikely you'll ever see more then 1000 records in a 1500 byte UDP packet
            if nfHeader['count'] <= 0 or nfHeader['count'] >= 1000:
                print "Invalid count %s" % nfHeader['count']
                continue

            uptime = socket.ntohl(struct.unpack('I', byteData[SysUptimeINR[0]])[0])
            epochseconds = socket.ntohl(struct.unpack('I', byteData[unix_secsINR[0]])[0])

            for i in range(0, nfHeader['count']):
                try:
                    base = SIZE_OF_HEADER + (i * SIZE_OF_RECORD)
                    data = struct.unpack('!IIIIHH', byteData[base + 16:base + 36])
                    nfdata = {}
                    nfdata['saddr'] = inet_ntoa(byteData[base + 0:base + 4])
                    nfdata['daddr'] = inet_ntoa(byteData[base + 4:base + 8])
                    nfdata['pcount'] = data[0]
                    nfdata['bcount'] = data[1]
                    nfdata['stime'] = data[2]
                    nfdata['etime'] = data[3]
                    nfdata['sport'] = data[4]
                    nfdata['dport'] = data[5]
                    nfdata['protocol'] = ord(byteData[base + 38])
                    # Do something with the netflow record..
                    print "%s:%s -> %s:%s" % (nfdata['saddr'], nfdata['sport'], nfdata['daddr'], nfdata['dport'])
                except:
                    continue

if __name__ == '__main__':
    NetFlowParser()
