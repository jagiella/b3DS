# Blank
# from Crypto.Cipher import AES
# from Crypto.Util import Counter
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend
from sys import argv
import struct


def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))


def key_to_bytes(num):
    return num.to_bytes(length=16, byteorder='big', signed=False)


def iv_to_bytes(iv):
    return iv.to_bytes(16, byteorder="big", signed=False)


# Setup Keys and IVs
plain_counter = struct.unpack('>Q', b'\x01\x00\x00\x00\x00\x00\x00\x00')
exefs_counter = struct.unpack('>Q', b'\x02\x00\x00\x00\x00\x00\x00\x00')
romfs_counter = struct.unpack('>Q', b'\x03\x00\x00\x00\x00\x00\x00\x00')
# 3DS AES Hardware Constant
Constant = struct.unpack(
    '>QQ', b'\x1F\xF9\xE9\xAA\xC5\xFE\x04\x08\x02\x45\x91\xDC\x5D\x52\x76\x8A')

# Retail keys
# KeyX 0x18 (New 3DS 9.3)
KeyX0x18 = struct.unpack(
    '>QQ', b'\x82\xE9\xC9\xBE\xBF\xB8\xBD\xB8\x75\xEC\xC0\xA0\x7D\x47\x43\x74')
# KeyX 0x1B (New 3DS 9.6)
KeyX0x1B = struct.unpack(
    '>QQ', b'\x45\xAD\x04\x95\x39\x92\xC7\xC8\x93\x72\x4A\x9A\x7B\xCE\x61\x82')
KeyX0x25 = struct.unpack(
    '>QQ', b'\xCE\xE7\xD8\xAB\x30\xC0\x0D\xAE\x85\x0E\xF5\xE3\x82\xAC\x5A\xF3')  # KeyX 0x25 (> 7.x)
KeyX0x2C = struct.unpack(
    '>QQ', b'\xB9\x8E\x95\xCE\xCA\x3E\x4D\x17\x1F\x76\xA9\x4D\xE9\x34\xC0\x53')  # KeyX 0x2C (< 6.x)


# Dev Keys: (Uncomment these lines if your 3ds rom is encrypted with Dev Keys)
# KeyX0x18 = struct.unpack('>QQ', '\x30\x4B\xF1\x46\x83\x72\xEE\x64\x11\x5E\xBD\x40\x93\xD8\x42\x76') # Dev KeyX 0x18 (New 3DS 9.3)
# KeyX0x1B = struct.unpack('>QQ', '\x6C\x8B\x29\x44\xA0\x72\x60\x35\xF9\x41\xDF\xC0\x18\x52\x4F\xB6') # Dev KeyX 0x1B (New 3DS 9.6)
# KeyX0x25 = struct.unpack('>QQ', '\x81\x90\x7A\x4B\x6F\x1B\x47\x32\x3A\x67\x79\x74\xCE\x4A\xD7\x1B') # Dev KeyX 0x25 (> 7.x)
# KeyX0x2C = struct.unpack('>QQ', '\x51\x02\x07\x51\x55\x07\xCB\xB1\x8E\x24\x3D\xCB\x85\xE2\x3A\x1D') # Dev KeyX 0x2C (< 6.x)

with open(argv[1], 'rb') as f:
    with open(argv[1], 'rb+') as g:
        print(argv[1])  # Print the filename of the file being decrypted
        f.seek(0x100)  # Seek to start of NCSD header
        magic = f.read(0x04)
        if magic == b"NCSD":

            f.seek(0x188)
            ncsd_flags = struct.unpack('<BBBBBBBB', f.read(0x8))
            sectorsize = 0x200 * (2**ncsd_flags[6])

            for p in range(8):
                # Seek to start of partition information, read offsets and lengths
                f.seek((0x120) + (p*0x08))
                part_off = struct.unpack('<L', f.read(0x04))
                part_len = struct.unpack('<L', f.read(0x04))

                # Get the partition flags to determine encryption type.
                f.seek(((part_off[0]) * sectorsize) + 0x188)
                t = f.read(0x8)
                print(t)
                print(len(t))
                partition_flags = struct.unpack('<BBBBBBBB', t)

                # check if the 'NoCrypto' bit (bit 3) is set
                if (partition_flags[7] & 0x04):
                    print("Partition %1d: Already Decrypted?..." % (p))
                else:
                    if (part_off[0] * sectorsize) > 0:  # check if partition exists

                        # Find partition start (+ 0x100 to skip NCCH header)
                        f.seek(((part_off[0]) * sectorsize) + 0x100)
                        magic = f.read(0x04)

                        if magic == b"NCCH":  # check if partition is valid
                            f.seek(((part_off[0]) * sectorsize) + 0x0)
                            # KeyY is the first 16 bytes of partition RSA-2048 SHA-256 signature
                            part_keyy = struct.unpack('>QQ', f.read(0x10))

                            f.seek(((part_off[0]) * sectorsize) + 0x108)
                            # TitleID is used as IV joined with the content type.
                            tid = struct.unpack('<Q', f.read(0x8))
                            # Get the IV for plain sector (TitleID + Plain Counter)
                            plain_iv = (tid[::] + plain_counter[::])
                            # Get the IV for ExeFS (TitleID + ExeFS Counter)
                            exefs_iv = (tid[::] + exefs_counter[::])
                            # Get the IV for RomFS (TitleID + RomFS Counter)
                            romfs_iv = (tid[::] + romfs_counter[::])

                            # get exheader hash
                            f.seek((part_off[0] * sectorsize) + 0x160)
                            exhdr_sbhash = str("%016X%016X%016X%016X") % (
                                struct.unpack('>QQQQ', f.read(0x20)))

                            f.seek((part_off[0] * sectorsize) + 0x180)
                            # get extended header length
                            exhdr_len = struct.unpack('<L', f.read(0x04))

                            f.seek((part_off[0] * sectorsize) + 0x190)
                            # get plain sector offset
                            plain_off = struct.unpack('<L', f.read(0x04))
                            # get plain sector length
                            plain_len = struct.unpack('<L', f.read(0x04))

                            f.seek((part_off[0] * sectorsize) + 0x198)
                            logo_off = struct.unpack(
                                '<L', f.read(0x04))  # get logo offset
                            logo_len = struct.unpack(
                                '<L', f.read(0x04))  # get logo length

                            f.seek((part_off[0] * sectorsize) + 0x1A0)
                            exefs_off = struct.unpack(
                                '<L', f.read(0x04))  # get exefs offset
                            exefs_len = struct.unpack(
                                '<L', f.read(0x04))  # get exefs length

                            f.seek((part_off[0] * sectorsize) + 0x1B0)
                            romfs_off = struct.unpack(
                                '<L', f.read(0x04))  # get romfs offset
                            romfs_len = struct.unpack(
                                '<L', f.read(0x04))  # get romfs length

                            # get exefs hash
                            f.seek((part_off[0] * sectorsize) + 0x1C0)
                            exefs_sbhash = str("%016X%016X%016X%016X") % (
                                struct.unpack('>QQQQ', f.read(0x20)))

                            # get romfs hash
                            f.seek((part_off[0] * sectorsize) + 0x1E0)
                            romfs_sbhash = str("%016X%016X%016X%016X") % (
                                struct.unpack('>QQQQ', f.read(0x20)))

                            plainIV = int(str("%016X%016X") %
                                          (plain_iv[::]), 16)
                            exefsIV = int(str("%016X%016X") %
                                          (exefs_iv[::]), 16)
                            romfsIV = int(str("%016X%016X") %
                                          (romfs_iv[::]), 16)
                            KeyY = int(str("%016X%016X") %
                                       (part_keyy[::]), 16)
                            Const = int(str("%016X%016X") %
                                        (Constant[::]), 16)

                            KeyX2C = int(str("%016X%016X") %
                                         (KeyX0x2C[::]), 16)
                            NormalKey2C = rol(
                                (rol(KeyX2C, 2, 128) ^ KeyY) + Const, 87, 128)

                            # fixed crypto key (aka 0-key)
                            if (partition_flags[7] & 0x01):
                                NormalKey = 0x00
                                NormalKey2C = 0x00
                                if (p == 0):
                                    print("Encryption Method: Zero Key")
                            else:
                                if (partition_flags[3] == 0x00):  # Uses Original Key
                                    KeyX = int(str("%016X%016X") %
                                               (KeyX0x2C[::]), 16)
                                    if (p == 0):
                                        print("Encryption Method: Key 0x2C")
                                elif (partition_flags[3] == 0x01):  # Uses 7.x Key
                                    KeyX = int(str("%016X%016X") %
                                               (KeyX0x25[::]), 16)
                                    if (p == 0):
                                        print("Encryption Method: Key 0x25")
                                # Uses New3DS 9.3 Key
                                elif (partition_flags[3] == 0x0A):
                                    KeyX = int(str("%016X%016X") %
                                               (KeyX0x18[::]), 16)
                                    if (p == 0):
                                        print("Encryption Method: Key 0x18")
                                # Uses New3DS 9.6 Key
                                elif (partition_flags[3] == 0x0B):
                                    KeyX = int(str("%016X%016X") %
                                               (KeyX0x1B[::]), 16)
                                    if (p == 0):
                                        print("Encryption Method: Key 0x1B")
                                NormalKey = rol(
                                    (rol(KeyX, 2, 128) ^ KeyY) + Const, 87, 128)

                            if (exhdr_len[0] > 0):
                                # decrypt exheader
                                f.seek((part_off[0] + 1) * sectorsize)
                                g.seek((part_off[0] + 1) * sectorsize)
                                exhdr_filelen = 0x800
                                exefsctrmode2C = Cipher(algorithms.AES(key_to_bytes(
                                    NormalKey2C)), modes.CTR(iv_to_bytes(plainIV)), backend=default_backend()).decryptor()
                                print(
                                    "Partition %1d ExeFS: Decrypting: ExHeader" % (p))
                                g.write(exefsctrmode2C.update(
                                    f.read(exhdr_filelen)))

                            if (exefs_len[0] > 0):
                                # decrypt exefs filename table
                                f.seek(
                                    (part_off[0] + exefs_off[0]) * sectorsize)
                                g.seek(
                                    (part_off[0] + exefs_off[0]) * sectorsize)
                                exefsctrmode2C = Cipher(algorithms.AES(key_to_bytes(NormalKey2C)),
                                                        modes.CTR(iv_to_bytes(exefsIV)), backend=default_backend()).decryptor()
                                g.write(exefsctrmode2C.update(
                                    f.read(sectorsize)))
                                print(
                                    "Partition %1d ExeFS: Decrypting: ExeFS Filename Table" % (p))

                                if (partition_flags[3] == 0x01 or partition_flags[3] == 0x0A or partition_flags[3] == 0x0B):
                                    code_filelen = 0
                                    for j in range(10):  # 10 exefs filename slots
                                        # get filename, offset and length
                                        f.seek(
                                            ((part_off[0] + exefs_off[0]) * sectorsize) + j*0x10)
                                        g.seek(
                                            ((part_off[0] + exefs_off[0]) * sectorsize) + j*0x10)
                                        exefs_filename = struct.unpack(
                                            '<8s', g.read(0x08))
                                        if str(exefs_filename[0]) == str(".code\x00\x00\x00"):
                                            code_fileoff = struct.unpack(
                                                '<L', g.read(0x04))
                                            code_filelen = struct.unpack(
                                                '<L', g.read(0x04))
                                            datalenM = (
                                                (code_filelen[0]) / (1024*1024))
                                            datalenB = (
                                                (code_filelen[0]) % (1024*1024))
                                            ctroffset = int(
                                                (code_fileoff[0] + sectorsize) / 0x10)
                                            exefsctrmode = Cipher(algorithms.AES(key_to_bytes(NormalKey)),
                                                                  modes.CTR(iv_to_bytes(
                                                                      exefsIV + ctroffset)), backend=default_backend()).decryptor()
                                            exefsctrmode2C = Cipher(algorithms.AES(key_to_bytes(NormalKey2C)),
                                                                    modes.CTR(iv_to_bytes(
                                                                        exefsIV + ctroffset)), backend=default_backend()).encryptor()
                                            f.seek(
                                                (((part_off[0] + exefs_off[0]) + 1) * sectorsize) + code_fileoff[0])
                                            g.seek(
                                                (((part_off[0] + exefs_off[0]) + 1) * sectorsize) + code_fileoff[0])
                                            if (datalenM > 0):
                                                for i in range(datalenM):
                                                    g.write(exefsctrmode2C.update(
                                                        exefsctrmode.update(
                                                            f.read(1024*1024))
                                                    ))
                                                    print("\rPartition %1d ExeFS: Decrypting: %8s... %4d / %4d mb...") % (
                                                        p, str(exefs_filename[0]), i, datalenM + 1),
                                            if (datalenB > 0):
                                                g.write(exefsctrmode2C.update(
                                                        exefsctrmode.update(
                                                            f.read(datalenB))
                                                        ))
                                            print("\rPartition %1d ExeFS: Decrypting: %8s... %4d / %4d mb... Done!") % (
                                                p, str(exefs_filename[0]), datalenM + 1, datalenM + 1)

                                # decrypt exefs
                                exefsSizeM = int(
                                    (exefs_len[0] - 1) * sectorsize / (1024*1024))
                                exefsSizeB = int(
                                    (exefs_len[0] - 1) * sectorsize) % (1024*1024)
                                ctroffset = int(sectorsize / 0x10)
                                exefsctrmode2C = Cipher(algorithms.AES(key_to_bytes(NormalKey2C)),
                                                        modes.CTR(iv_to_bytes(
                                                            exefsIV + ctroffset)), backend=default_backend()).decryptor()
                                f.seek(
                                    (part_off[0] + exefs_off[0] + 1) * sectorsize)
                                g.seek(
                                    (part_off[0] + exefs_off[0] + 1) * sectorsize)
                                if (exefsSizeM > 0):
                                    for i in range(exefsSizeM):
                                        g.write(exefsctrmode2C.update(
                                            f.read(1024*1024)))
                                        print(
                                            "\rPartition %1d ExeFS: Decrypting: %4d / %4d mb" % (p, i, exefsSizeM + 1))
                                if (exefsSizeB > 0):
                                    g.write(exefsctrmode2C.update(
                                            f.read(exefsSizeB)))
                                print("\rPartition %1d ExeFS: Decrypting: %4d / %4d mb... Done" % (
                                    p, exefsSizeM + 1, exefsSizeM + 1))

                            else:
                                print(
                                    "Partition %1d ExeFS: No Data... Skipping..." % (p))

                            if (romfs_off[0] != 0):
                                romfsBlockSize = 16  # block size in mb
                                romfsSizeM = int(
                                    romfs_len[0] * sectorsize / (romfsBlockSize*(1024*1024)))
                                romfsSizeB = int(
                                    romfs_len[0] * sectorsize) % (romfsBlockSize*(1024*1024))
                                romfsSizeTotalMb = int(
                                    (romfs_len[0] * sectorsize) / (1024*1024) + 1)

                                romfsctrmode = Cipher(algorithms.AES(key_to_bytes(NormalKey)),
                                                      modes.CTR(iv_to_bytes(romfsIV)), backend=default_backend()).decryptor()

                                f.seek(
                                    (part_off[0] + romfs_off[0]) * sectorsize)
                                g.seek(
                                    (part_off[0] + romfs_off[0]) * sectorsize)
                                if (romfsSizeM > 0):
                                    for i in range(romfsSizeM):
                                        g.write(romfsctrmode.update(
                                            f.read(romfsBlockSize*(1024*1024))))
                                        print("\rPartition %1d RomFS: Decrypting: %4d / %4d mb" % (
                                            p, i*romfsBlockSize, romfsSizeTotalMb))
                                if (romfsSizeB > 0):
                                    g.write(romfsctrmode.update(
                                            f.read(romfsSizeB)))

                                print("\rPartition %1d RomFS: Decrypting: %4d / %4d mb... Done" % (
                                    p, romfsSizeTotalMb, romfsSizeTotalMb))

                            else:
                                print(
                                    "Partition %1d RomFS: No Data... Skipping..." % (p))

                            g.seek((part_off[0] * sectorsize) + 0x18B)
                            # set crypto-method to 0x00
                            g.write(struct.pack('<B', int(0x00)))
                            g.seek((part_off[0] * sectorsize) + 0x18F)
                            # read partition flag
                            flag = int(partition_flags[7])
                            # turn off 0x01 = FixedCryptoKey and 0x20 = CryptoUsingNewKeyY
                            flag = (flag & ((0x01 | 0x20) ^ 0xFF))
                            flag = (flag | 0x04)  # turn on 0x04 = NoCrypto
                            g.write(struct.pack('<B', int(flag)))  # write flag

                        else:
                            print("Partition %1d Unable to read NCCH header" % (p))
                    else:
                        print("Partition %1d Not found... Skipping..." % (p))
            print("Done...")
        else:
            print("Error: Not a 3DS Rom?")

# raw_input('Press Enter to Exit...')
