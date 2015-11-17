#!/usr/bin/python
#! -*- encoding: utf-8 -*-

import csv
import sys

def numToDocIP(num):
    w = str(int(num / 16777216) % 256)
    x = str(int(num / 65536) % 256)
    y = str(int(num / 256) % 256)
    z = str(int(num ) % 256)
    return w + '.' + x + '.' + y + '.' + z
if __name__ == '__main__':
    FIELDS = ['src_ip', 'src_port', 'dest_ip', 'dest_port', 'protocol', 'flow_packets', 'flow_octets']

    csv_file = open('test.csv', 'w')
    writer = csv.DictWriter(csv_file, fieldnames = FIELDS)

    # write header
    writer.writerow(dict(zip(FIELDS, FIELDS)))

    with open('result.csv') as f:
        while True:
            rawData = f.readline().strip().split(',')
            if (len(rawData) < len(FIELDS)):
                break
            nfData = {}
            nfData['src_ip'] = numToDocIP(int(rawData[0]))
            nfData['src_port'] = rawData[1]
            nfData['dest_ip'] = numToDocIP(int(rawData[2]))
            nfData['dest_port'] = rawData[3]
            nfData['protocol'] = rawData[4]
            nfData['flow_packets'] = rawData[5]
            nfData['flow_octets'] = rawData[6]
            print nfData
            writer.writerow(nfData)
