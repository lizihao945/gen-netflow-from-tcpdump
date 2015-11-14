#!/usr/bin/python
#! -*- encoding: utf-8 -*-

from socket import *
import sys
import select

host = "0.0.0.0"
port = 41300
s = socket(AF_INET, SOCK_DGRAM)
s.bind((host, port))

addr = (host, port)
buf = 1024

f = open("netflow.dump",'wb')

data, addr = s.recvfrom(buf)

try:
    while(data):
        f.write(data)
        s.settimeout(2)
        data, addr = s.recvfrom(buf)

except timeout:
    f.close()
    s.close()
    print "All flows received!"
