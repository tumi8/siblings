#!/usr/bin/env python3

import sys, csv

arr = []

d4, d6 = dict(), dict()

with open(sys.argv[1], "r") as csvfile:
    datareader = csv.reader(csvfile)
    count = 0
    for row in datareader:
        # assuming format like:
        # www.first-colo.net.,212.224.70.17,2a01:7e0::212:224:70:17,80,servers
        ip4 = row[1]
        ip6 = row[2]
        port = row[3]
        count += 1
        if port in d4 and port in d6:
            d4[port].append(ip4)
            d6[port].append(ip6)
        elif port not in d4 and port not in d6:
            d4[port] = [ip4]
            d6[port] = [ip6]
        else:
            print("CRITICAL ERROR: row {} not (missing) in both d4 {} and d6 {}".format(row, d4, d6))
            raise ValueError('WEIRD! exit!')

#print("read {} lines from file.".format(len(arr)))

for k,v in d4.items():
    out4name = sys.argv[1]+"-ipv4-port"+k
    out6name = sys.argv[1]+"-ipv6-port"+k
    fd4 = open(out4name, "w")
    fd6 = open(out6name, "w")
    for i in v:
        fd4.write(i+"\n")
    for i in d6[k]:
        fd6.write(i+"\n")
    fd4.close()
    fd6.close()
