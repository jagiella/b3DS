#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 18 00:03:18 2022

@author: nick
"""
from sys import argv
import struct

MEDIAUNIT = 0x200


class NCCHBlock:
    def __init__(self, f, off, size, flags):
        pass


class NCSDHeader:
    def __init__(self, f):
        f.seek(0x100)  # Seek to start of NCSD header
        magic = f.read(0x04)
        print(magic)
        size = struct.unpack('I', f.read(0x04))[0]
        print(size*MEDIAUNIT)
        titleID = f.read(0x08)
        print(titleID)
        partitionsFS = f.read(0x08)
        print(partitionsFS)
        partitionsCTL = f.read(0x08)
        print(partitionsCTL)

        # partition table
        offs = []
        lens = []
        for p in range(8):
            part_off, part_len = struct.unpack('<LL', f.read(0x08))
            # part_len = struct.unpack('<L', f.read(0x04))
            print('partition %i: %i - %i (+%i)' %
                  (p, part_off, part_off + part_len, part_len))
            offs.append(part_off)
            lens.append(part_len)

        f.seek(0x188)
        part_flags = f.read(0x08)

        for p in range(8):
            NCCHBlock(f, offs[p], lens[p], part_flags[p])


with open(argv[1], 'rb') as f:
    NCSDHeader(f)
