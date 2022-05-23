#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 18 00:03:18 2022

@author: nick
"""
import struct
import argparse

from sys import argv

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend


def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))


def to_bytes(num):
    return num.to_bytes(length=16, byteorder='big', signed=False)


MEDIAUNIT = 0x200

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


class NCCHBlock:
    def __init__(self, f, off, size, sectorsize):
        self.f = f
        self.off = off
        self.size = size
        self.sectorsize = sectorsize
        

        f.seek(off*self.sectorsize+0x100)
        self.magic = f.read(0x04)

        if(self.magic == b'NCCH'):   
            f.seek(off*self.sectorsize + 0x108)
            self.partition_id = f.read(0x8)
            # print('Partition ID: %s' % (self.partition_id))

            f.seek(off*self.sectorsize + 0x112)
            self.version = struct.unpack('<H', f.read(0x2))[0]
            # print('- version: %04X' % (self.version))

            f.seek(off*self.sectorsize+0x188)
            self.ncch_flags = f.read(0x08)

            f.seek(off*self.sectorsize+0x180)
            self.ExHeader_len = struct.unpack('<I', f.read(0x4))[0]
            # print('- ExHdr_len: %i' % (self.ExHeader_len))
            f.seek(off*self.sectorsize+0x1A0)
            self.ExeFS_off = struct.unpack('<I', f.read(0x4))[0]
            self.ExeFS_len = struct.unpack('<I', f.read(0x4))[0]
            # print('- ExeFS_len: %i' % (self.ExeFS_len))
            f.seek(off*self.sectorsize+0x1B0)
            self.RomFS_off = struct.unpack('<I', f.read(0x4))[0]
            self.RomFS_len = struct.unpack('<I', f.read(0x4))[0]
            # print('- RomFS_len: %i' % (self.RomFS_len))
        # else:
        #     print('no valid partition')

    def write_dec(self, f_out):
        if(self.magic == b'NCCH'):
            self.f.seek(self.off*self.sectorsize)  # go to start of partition

            # keys
            if (self.ncch_flags[7] & 0x01):
                NormalKey = 0x00
                NormalKey2C = 0x00
                print("Encryption Method: Zero Key")
            else:
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
                # print(
                #     'CTR = [partition_id[7], partition_id[6], ..., partition_id[0], M, 0, ..., 0]')
                header_ctr = int.from_bytes(self.partition_id[::-1] +
                                            b'\x01\x00\x00\x00\x00\x00\x00\x00', byteorder='big')
                exefs_ctr = int.from_bytes(self.partition_id[::-1] +
                                           b'\x02\x00\x00\x00\x00\x00\x00\x00', byteorder='big')
                romfs_ctr = int.from_bytes(self.partition_id[::-1] +
                                           b'\x03\x00\x00\x00\x00\x00\x00\x00', byteorder='big')
            elif(self.version == 1):
                raise NotImplementedError(
                    'CTR = [partition_id[0], partition_id[1], ...,partition_id[7], 0, 0, 0, 0, T[0], T[1], T[2], T[3]]')
            else:
                raise ValueError('CTR can not be determined: version = %i' %
                                 (self.version))

            # copy NCCH header
            self.f.seek((self.off) * self.sectorsize)
            f_out.seek((self.off) * self.sectorsize)
            f_out.write(self.f.read(self.sectorsize))
            print(
                "Partition %1d ExeFS: Copy: NCCH Header" % (p))

            # decode exheader
            if (self.ExHeader_len != 0):
                # decrypt exheader
                exhdrSize = 0x800  # block size in bytes (2kb)

                exefsctrmode2C = Cipher(
                    algorithms.AES(to_bytes(NormalKey2C)),
                    modes.CTR(to_bytes(header_ctr)),
                    backend=default_backend()).decryptor()

                self.f.seek((self.off + 1) * self.sectorsize)
                f_out.seek((self.off + 1) * self.sectorsize)

                print(
                    "Partition %1d ExeFS: Decrypting: ExHeader" % (p))
                f_out.write(exefsctrmode2C.update(
                    self.f.read(exhdrSize)))
            else:
                print('Partition %1d ExHeader: skip' % (p))

            if (self.RomFS_off != 0):
                romfsBlockSize = 0x1000000  # block size in bytes (16mb)

                romfsctrmode = Cipher(
                    algorithms.AES(to_bytes(NormalKey)),
                    modes.CTR(to_bytes(romfs_ctr)),
                    backend=default_backend()).decryptor()

                self.f.seek(
                    (self.off + self.RomFS_off) * self.sectorsize)
                f_out.seek(
                    (self.off + self.RomFS_off) * self.sectorsize)

                for block_off in range(0, self.RomFS_len * self.sectorsize, romfsBlockSize):
                    block_len = min(self.RomFS_len * self.sectorsize - block_off,
                                    romfsBlockSize)
                    block = romfsctrmode.update(self.f.read(block_len))
                    if(block_off == 0 and block[:4] != b'IVFC'):  # check magic
                        raise ValueError(
                            'Wrong magic word of RomFS: ' + str(block[:4]))
                    f_out.write(block)
                    print("\rPartition %1d RomFS: Decrypting: %4d / %4d byte... Done" % (
                        p, block_off+block_len, self.RomFS_len * self.sectorsize))
            else:
                print('Partition %1d RomFS: skip' % (p))

            if (self.ExeFS_off != 0):
                # decrypt exefs filename table
                self.f.seek(
                    (self.off + self.ExeFS_off) * self.sectorsize)
                f_out.seek(
                    (self.off + self.ExeFS_off) * self.sectorsize)

                exefsctrmode2C = Cipher(
                    algorithms.AES(to_bytes(NormalKey2C)),
                    modes.CTR(to_bytes(exefs_ctr)),
                    backend=default_backend()).decryptor()
                f_out.write(exefsctrmode2C.update(
                    self.f.read(0x200)))
                print(
                    "Partition %1d ExeFS: Decrypting: ExeFS Filename Table" % (p))

                for j in range(10):  # 10 exefs filename slots
                    # get filename, offset and length
                    f_out.seek(
                        (self.off + self.ExeFS_off) * self.sectorsize + j*0x10)
                    filename = struct.unpack('<8s', f_out.read(0x08))[0]
                    fileoff = struct.unpack('<L', f_out.read(0x04))[0]
                    filelen = struct.unpack('<L', f_out.read(0x04))[0]
                    if(filelen != 0):
                        # print('%s: %i + %i' % (filename, fileoff, filelen))

                        # decrypt file
                        self.f.seek((((self.off + self.ExeFS_off) + 1)
                                    * self.sectorsize) + fileoff)
                        f_out.seek((((self.off + self.ExeFS_off) + 1)
                                   * self.sectorsize) + fileoff)

                        if(filename == b'banner\x00\x00' or filename == b'icon\x00\x00\x00\x00'):
                            Key = NormalKey2C
                        else:
                            Key = NormalKey

                        ctroffset = int((fileoff + self.sectorsize) / 0x10)

                        exefsctrmode = Cipher(
                            algorithms.AES(to_bytes(Key)),
                            modes.CTR(to_bytes(exefs_ctr + ctroffset)),
                            backend=default_backend()).decryptor()

                        blockSize = 1024*1024
                        for block_off in range(0, filelen, blockSize):
                            block_len = min(filelen - block_off, blockSize)
                            block = exefsctrmode.update(self.f.read(block_len))
                            f_out.write(block)
                            print("\rPartition %1d ExeFS: Decrypting: %4d / %4d byte... Done" % (
                                p, block_off+block_len, filelen))
            else:
                print('Partition %1d ExeFS: skip' % (p))


class NCSDHeader:
    def __init__(self, f):
        self.f = f

        f.seek(0x100)  # Seek to start of NCSD header
        magic = f.read(0x04)
        if(magic != b'NCSD'):
            raise ValueError('Invalid header')

        # partition table
        self.partition_offsets = []
        self.partition_lens = []
        f.seek(0x120)
        for p in range(8):
            part_off, part_len = struct.unpack('<LL', f.read(0x08))
            self.partition_offsets.append(part_off)
            self.partition_lens.append(part_len)

        f.seek(0x188)
        self.ncsd_flags = f.read(0x08)
        self.sectorsize = MEDIAUNIT * (2**self.ncsd_flags[6])

    def write_dec(self, f_out):
        self.f.seek(0x0)
        f_out.write(self.f.read(0x200))
        print('NSCD Header: Copy... Done')


class NCSD:
    def __init__(self, f):
        # self.f = f

        self.__header = NCSDHeader(f)

        self.__partitions = [NCCHBlock(
            f, self.__header.partition_offsets[i], self.__header.partition_lens[i], self.__header.sectorsize) for i in range(8)]

    def header(self):
        return self.__header

    def partition(self, p):
        if(p >= 0 and p < 8):
            return self.__partitions[p]

parser = argparse.ArgumentParser(description='Decrypt 3ds files.')
parser.add_argument('file_in', help='encrypted 3ds file')
parser.add_argument('file_out', help='decrypted 3ds file')

args = parser.parse_args(argv[1:])

with open(args.file_in, 'rb') as f_in:
    ncsd = NCSD(f_in)

    with open(args.file_out, 'wb+') as f_out:
        ncsd.header().write_dec(f_out)
        for p in range(8):
            ncsd.partition(p).write_dec(f_out)
