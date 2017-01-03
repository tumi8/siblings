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
random.shuffle(arr)

try:
    n = int(sys.argv[3])
    if n > len(arr):
        n= len(arr) -1
except:
    n=1

#print("shuffled!")
#print(arr)

outfname = "{}__nonsiblings_seed{}_n{}".format(sys.argv[1], seed,n)
fd = open(outfname, "w")
#writer = csv.writer(fd)
ctr=0

for i in range(len(arr)):
    for j in range(1,n):
        if arr[i][0] != arr[(i+j)%len(arr)][0]:
            line = "{}_+_{},{},{}".format(arr[i][0], arr[(i+j)%len(arr)][0], arr[i][1], arr[(i+j)%len(arr)][2]) # offset IPv6
            fd.write(line+"\n")
            ctr += 1

print("Written {} non-siblings of seed {} to file {}".format(ctr, seed, outfname))
