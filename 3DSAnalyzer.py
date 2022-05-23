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


def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))


def to_bytes(num):
    return num.to_bytes(length=16, byteorder='big', signed=False)


MEDIAUNIT = 0x200

FLAG4 = {1: "CTR", 2: "snake (New 3DS)"}
FLAG5 = {0x1: 'Data', 0x2: 'Executable',  0x4: 'SystemUpdate',
         0x8: 'Manual', (0x4 | 0x8): 'Child', 0x10: 'Trial'}
FLAG7 = {0x1: 'FixedCryptoKey',  0x2: 'NoMountRomFs',
         0x4: 'NoCrypto',  0x20: 'using a new keyY generator'}

# 3DS AES Hardware Constant
Constant = int('1FF9E9AAC5FE0408024591DC5D52768A', 16)

# Retail keys
# KeyX 0x18 (New 3DS 9.3)
KeyX0x18 = int('82E9C9BEBFB8BDB875ECC0A07D474374', 16)
# KeyX 0x1B (New 3DS 9.6)
KeyX0x1B = int('45AD04953992C7C893724A9A7BCE6182', 16)
# KeyX 0x25 (> 7.x)
KeyX0x25 = int('CEE7D8AB30C00DAE850EF5E382AC5AF3', 16)
# KeyX 0x2C (< 6.x)
KeyX0x2C = int('B98E95CECA3E4D171F76A94DE934C053', 16)


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

        self.sectorsize = MEDIAUNIT * (2**ncsd_flags[6])
        # print('sectorsize: %i bytes' % (self.sectorsize))

        f.seek(off*self.sectorsize+0x100)
        self.magic = f.read(0x04)
        print(self.magic)
        if(self.magic == b'NCCH'):
            f.seek(off*self.sectorsize + 0x108)
            # TitleID is used as IV joined with the content type.
            # self.part_id = struct.unpack('<Q', f.read(0x8))
            self.part_id = f.read(0x8)
            print('Part ID: %s' % (self.part_id))

            f.seek(off*self.sectorsize + 0x112)
            self.version = struct.unpack('<H', f.read(0x2))[0]
            print('version: %04X' % (self.version))

            f.seek(off*self.sectorsize+0x188)
            self.ncch_flags = f.read(0x08)
            # print(ncchflag)
            # self.analyzeFlags(ncchflag)

            f.seek(off*self.sectorsize+0x180)
            self.ExHeader_len = struct.unpack('<I', f.read(0x4))[0]
            print('- ExHdr_len: %i' % (self.ExHeader_len))
            f.seek(off*self.sectorsize+0x1A4)
            self.ExeFS_len = struct.unpack('<I', f.read(0x4))[0]
            print('- ExeFS_len: %i' % (self.ExeFS_len))
            f.seek(off*self.sectorsize+0x1B4)
            self.RomFS_len = struct.unpack('<I', f.read(0x4))[0]
            print('- RomFS_len: %i' % (self.RomFS_len))
        else:
            print('no valid partition')

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
        if(self.magic == b'NCCH'):
            self.f.seek(self.off*self.sectorsize)  # go to start of partition

            # copy blocks
            # f_out.write(self.f.read(self.size*self.sectorsize))

            # keys
            # KeyY is the first 16 bytes of partition RSA-2048 SHA-256 signature
            KeyY = int.from_bytes(self.f.read(0x10), byteorder='big')

            if (self.ncch_flags[3] == 0x00):  # Uses Original Key
                KeyX = KeyX0x2C
            elif (self.ncch_flags[3] == 0x01):  # Uses 7.x Key
                KeyX = KeyX0x25
            elif (self.ncch_flags[3] == 0x0A):  # Uses New3DS 9.3 Key
                KeyX = KeyX0x18
            elif (self.ncch_flags[3] == 0x0B):  # Uses New3DS 9.6 Key
                KeyX = KeyX0x1B

            NormalKey = rol(
                (rol(KeyX, 2, 128) ^ KeyY) + Constant, 87, 128)
            NormalKey2C = rol(
                (rol(KeyX0x2C, 2, 128) ^ KeyY) + Constant, 87, 128)

            # CTRs
            if((self.version == 0) or (self.version == 2)):
                print(
                    'CTR = [partition_id[7], partition_id[6], ..., partition_id[0], M, 0, ..., 0]')
                header_ctr = self.part_id[::-1] + \
                    b'\x01\x00\x00\x00\x00\x00\x00\x00'
                exefs_ctr = self.part_id[::-1] + \
                    b'\x02\x00\x00\x00\x00\x00\x00\x00'
                romfs_ctr = self.part_id[::-1] + \
                    b'\x03\x00\x00\x00\x00\x00\x00\x00'
            elif(self.version == 1):
                print(
                    'CTR = [partition_id[0], partition_id[1], ...,partition_id[7], 0, 0, 0, 0, T[0], T[1], T[2], T[3]]')
            else:
                print('CTR can not be determined: version = %i' %
                      (self.version))

            # decode exheader
            if (self.ExHeader_len > 0):
                # decrypt exheader
                self.f.seek((self.off + 1) * self.sectorsize)
                f_out.seek((self.off + 1) * self.sectorsize)
                exhdr_filelen = 0x800
                dec = Decryptor(self.ncch_flags, self.version)

                # ctr = self.part_id[::-1] + header_ctr
                print(header_ctr)
                exefsctrmode2C = Cipher(
                    algorithms.AES(to_bytes(NormalKey2C)),
                    modes.CTR(header_ctr),
                    backend=default_backend()).decryptor()
                print(
                    "Partition %1d ExeFS: Decrypting: ExHeader" % (p))
                f_out.write(exefsctrmode2C.update(
                    self.f.read(exhdr_filelen)))
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
                  (p, part_off*MEDIAUNIT, (part_off + part_len)*MEDIAUNIT, part_len*MEDIAUNIT))
            self.offs.append(part_off)
            self.lens.append(part_len)

        f.seek(0x188)
        self.ncsd_flags = f.read(0x08)
        self.sectorsize = MEDIAUNIT * (2**self.ncsd_flags[6])
        print('sectorsize: %i bytes' % (self.sectorsize))

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
