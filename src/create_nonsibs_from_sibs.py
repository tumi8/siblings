#!/usr/bin/env python3

import sys, csv

arr = []

with open(sys.argv[1], "r") as csvfile:
    datareader = csv.reader(csvfile)
    count = 0
    for row in datareader:
        arr.append(row)
    #    count = count+1
    #    try:
    #        ip = row[0]
    #        tcpt = row[1]

print("read {} lines from file.".format(len(arr)))

import random

try:
    seed = sys.argv[2]
except:
    seed = 42

random.seed(seed)
#print(arr)
random.shuffle(arr)
#print("shuffled!")
#print(arr)

outfname = "{}__nonsiblings_seed{}".format(sys.argv[1], seed)
fd = open(outfname, "w")
#writer = csv.writer(fd)

for i in range(len(arr)):
    #orig_line = "{},{},{}".format(arr[i][0],arr[i][1],arr[i][2]) # offset IPv6
    line = "{}_+_{},{},{}".format(arr[i][0], arr[(i+1)%len(arr)][0], arr[i][1], arr[(i+1)%len(arr)][2]) # offset IPv6
    #print("orig_line:", orig_line)
    #print("chng_line:", line)
    fd.write(line+"\n")

print("Written non-siblings of seed {} to file {}".format(seed, outfname))
