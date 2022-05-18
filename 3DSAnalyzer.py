#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 18 00:03:18 2022

@author: nick
"""
from sys import argv
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend

MEDIAUNIT = 0x200

FLAG4 = {1: "CTR", 2: "snake (New 3DS)"}
FLAG5 = {0x1: 'Data', 0x2: 'Executable',  0x4: 'SystemUpdate',
         0x8: 'Manual', (0x4 | 0x8): 'Child', 0x10: 'Trial'}
FLAG7 = {0x1: 'FixedCryptoKey',  0x2: 'NoMountRomFs',
         0x4: 'NoCrypto',  0x20: 'using a new keyY generator'}


class Decryptor:
    def __init__(self, ncch_flags, ncch_version):
        if (ncch_flags[7] & 0x01):
            NormalKey = 0x00
            NormalKey2C = 0x00
            # if (p == 0):
            print("Encryption Method: Zero Key")
        else:
            print('Encryption Method: unknown')


class ExtendedHeader:
    def __init__(self):
        pass


class NCCHBlock:
    def __init__(self, f, partID, off, size, ncsd_flags):
        self.f = f
        self.off = off
        self.size = size

        self.sectorsize = 0x200 * (2**ncsd_flags[6])
        print('sectorsize: %i bytes' % (self.sectorsize))

        f.seek(off*self.sectorsize+0x100)
        magic = f.read(0x04)
        print(magic)

        f.seek(off*self.sectorsize + 0x108)
        # TitleID is used as IV joined with the content type.
        # self.part_id = struct.unpack('<Q', f.read(0x8))
        self.part_id = f.read(0x8)
        print('Part ID: %s' % (self.part_id))

        f.seek(off*self.sectorsize + 0x112)
        self.version = struct.unpack('<H', f.read(0x2))
        print('version: %04X' % (self.version))

        f.seek(off*self.sectorsize+0x188)
        self.ncch_flags = f.read(0x08)
        # print(ncchflag)
        # self.analyzeFlags(ncchflag)

        f.seek(off*self.sectorsize+0x180)
        self.ExHeader_len = struct.unpack('<I', f.read(0x4))[0]
        print('- ExHeader_len: %i' % (self.ExHeader_len))
        f.seek(off*self.sectorsize+0x1A4)
        self.ExeFS_len = struct.unpack('<I', f.read(0x4))[0]
        print('- ExeFS_len: %i' % (self.ExeFS_len))
        f.seek(off*self.sectorsize+0x1B4)
        self.RomFS_len = struct.unpack('<I', f.read(0x4))[0]
        print('- RomFS_len: %i' % (self.RomFS_len))

    def analyzeFlags(self, flags):
        print('- Crypto Method: ' + str(flags[3]))

        print('- Platform: ' + FLAG4[flags[4]])

        content = []
        for t in FLAG5:
            if(t & flags[5] == t):
                content.append(FLAG5[t])
        print('- Content:  ' + ', '.join(content))

        crypto = []
        for t in FLAG7:
            if(t & flags[7] == t):
                crypto.append(FLAG7[t])
        print('- Crypto:  ' + ', '.join(crypto))

    def write_dec(self, f_out):
        self.f.seek(self.off*self.sectorsize)  # go to start of partition

        # copy blocks
        # f_out.write(self.f.read(self.size*self.sectorsize))

        # keys
        # KeyY is the first 16 bytes of partition RSA-2048 SHA-256 signature
        part_keyy = struct.unpack('>QQ', self.f.read(0x10))

        # CTRs
        if(self.version == 0 or self.version == 2):
            header_ctr = self.part_id[::-1] + \
                b'\x01\x00\x00\x00\x00\x00\x00\x00'
            exefs_ctr = self.part_id[::-1] + \
                b'\x02\x00\x00\x00\x00\x00\x00\x00'
            romfs_ctr = self.part_id[::-1] + \
                b'\x03\x00\x00\x00\x00\x00\x00\x00'

        # decode exheader
        if (self.ExHeader_len > 0):
            # decrypt exheader
            self.f.seek((self.off + 1) * self.sectorsize)
            f_out.seek((self.off + 1) * self.sectorsize)
            exhdr_filelen = 0x800
            dec = Decryptor(self.ncch_flags, self.version)
            # exefsctrmode2C = Cipher(
            #     algorithms.AES(key_to_bytes(NormalKey2C)),
            #     modes.CTR(iv_to_bytes(plainIV)),
            #     backend=default_backend()).decryptor()
            # print(
            #     "Partition %1d ExeFS: Decrypting: ExHeader" % (p))
            # f_out.write(exefsctrmode2C.update(
            #     self.f.read(exhdr_filelen)))
        else:
            print('skip empty partition')


class NCSDHeader:
    def __init__(self, f):
        self.f = f

    def write_dec(self, f_out):
        self.f.seek(0x0)
        f_out.write(self.f.read(0x200))


class NCSD:
    def __init__(self, f):
        self.f = f
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

        # f.seek(0x180)
        # AddHdrSize = struct.unpack('I', f.read(0x04))  # [0]
        # print('Additional Header Size: %i' % (AddHdrSize))

        # partition table
        self.offs = []
        self.lens = []
        for p in range(8):
            part_off, part_len = struct.unpack('<LL', f.read(0x08))
            # part_len = struct.unpack('<L', f.read(0x04))
            print('partition %i: %i - %i (+%i)' %
                  (p, part_off, part_off + part_len, part_len))
            self.offs.append(part_off)
            self.lens.append(part_len)

        f.seek(0x188)
        self.ncsd_flags = f.read(0x08)

        # partition ID table
        for p in range(8):
            part_ID = struct.unpack('<Q', f.read(0x8))[0]
            print('part %i: %016X' % (p, part_ID))

        # for p in range(8):
        #     if(self.lens[p] > 0):
        #         NCCHBlock(f, p, self.offs[p], self.lens[p], self.part_flags[p])

    def header(self):
        return NCSDHeader(self.f)

    def partition(self, p):
        if(p >= 0 and p < 8):
            return NCCHBlock(self.f, p, self.offs[p], self.lens[p], self.ncsd_flags)


with open(argv[1], 'rb') as f_in:
    ncsd = NCSD(f_in)

    with open(argv[1]+'.dec.3ds', 'wb+') as f_out:
        ncsd.header().write_dec(f_out)
        for p in range(8):
            ncsd.partition(p).write_dec(f_out)
